#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""encrypt.py — 本地加密工具：明文目录 → 密文目录 + 清单（两者原子地一起重新生成）

用法：
  export OOEP_PASSPHRASE='...'     # 或 --passphrase-file，或交互式输入
  python3 encrypt.py --src <明文根目录> --out <密文目录> --manifest <manifest.tsv>

  # 一次性全量迁移（v1 路径派生名 → v2 随机名，旧 .enc 会被删除）
  python3 encrypt.py --migrate-v2 --enc encrypted --out encrypted --manifest encryption/manifest.tsv

仓库里只出现两类东西：
  encrypted/<blob_id>.enc   blob_id 为随机 16 位 hex（v2），与路径无关
  encryption/manifest.tsv   blob_id + 密文 sha256 + 明文 HMAC + v（不写路径）
真实路径与文件内容都在密文里，清单与文件名反推不出模块/站点名。

性能：一次运行只生成一个会话级 salt，scrypt 只派生一次，110 个文件复用。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys

import ooep_crypto as C


def get_passphrase(args) -> bytes:
    if args.passphrase_file:
        with open(args.passphrase_file, "rb") as f:
            return f.read().rstrip(b"\r\n")
    env = os.environ.get("OOEP_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    import getpass
    return getpass.getpass("passphrase: ").encode("utf-8")


def _write_blob(out_dir: str, bid: str, blob: bytes) -> None:
    d = os.path.dirname(os.path.join(out_dir, bid + ".enc"))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(out_dir, bid + ".enc"), "wb") as f:
        f.write(blob)


def encrypt_tree(args, passphrase) -> int:
    """明文目录 → v2 密文（随机 blob_id + 会话级 salt）。"""
    rows = []
    paths = []
    salt = secrets.token_bytes(C.SALT_LEN)
    keyring = C.Keyring(passphrase)   # 整轮只跑一次 scrypt
    count = 0
    for dirpath, dirnames, filenames in os.walk(args.src):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, args.src).replace(os.sep, "/")
            with open(full, "rb") as f:
                data = f.read()
            bid = C.new_blob_id()
            payload = C.pack(rel, data)
            blob, check_key = C.encrypt_blob(passphrase, bid, payload, salt=salt, keyring=keyring)
            _write_blob(args.out, bid, blob)
            rows.append((bid, hashlib.sha256(blob).hexdigest(),
                         C.plaintext_mac(check_key, payload), C.VERSION))
            paths.append(rel)
            count += 1
            print(f"ENC v2 {bid}.enc")
    C.write_manifest(args.manifest, rows, pathset=C.pathset_digest(paths))
    if args.pathlist:
        with open(args.pathlist, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(paths)) + "\n")
    print(f"OK: {count} 个文件 → {args.out}；清单 → {args.manifest}（KDF 次数={keyring.derivations}）")
    return 0


def migrate_v2(args, passphrase) -> int:
    """v1/v2 存量密文 → v2：重新随机命名、单一会话 salt、删除旧 .enc。"""
    src_enc = args.enc or args.out
    rows, _meta = C.read_manifest(args.manifest)
    if not rows:
        print("FAIL: 清单为空", file=sys.stderr)
        return 5
    keyring = C.Keyring(passphrase)
    items = []
    seen = set()
    for bid in sorted(rows):
        sha_want, mac_want, _ver = rows[bid]
        path = os.path.join(src_enc, bid + ".enc")
        with open(path, "rb") as f:
            blob = f.read()
        if hashlib.sha256(blob).hexdigest() != sha_want:
            print(f"FAIL: 源密文校验失败 {bid}", file=sys.stderr)
            return 8
        payload, check_key, _ver = C.decrypt_blob(blob, passphrase, bid, keyring=keyring)
        if C.plaintext_mac(check_key, payload) != mac_want:
            print(f"FAIL: 源明文承诺不匹配 {bid}", file=sys.stderr)
            return 8
        rel, data = C.unpack(payload)
        if rel in seen:
            print(f"FAIL: 路径重复 {rel}", file=sys.stderr)
            return 8
        seen.add(rel)
        items.append((rel, data))

    salt = secrets.token_bytes(C.SALT_LEN)
    new_rows = []
    written = set()
    for rel, data in items:
        bid = C.new_blob_id()
        while bid in written:
            bid = C.new_blob_id()
        payload = C.pack(rel, data)
        blob, check_key = C.encrypt_blob(passphrase, bid, payload, salt=salt, keyring=keyring)
        _write_blob(args.out, bid, blob)
        written.add(bid + ".enc")
        new_rows.append((bid, hashlib.sha256(blob).hexdigest(),
                         C.plaintext_mac(check_key, payload), C.VERSION))
    C.write_manifest(args.manifest, new_rows, pathset=C.pathset_digest(seen))

    # 旧文件清理：只删 .enc，且只删不在新集合里的
    removed = 0
    for name in os.listdir(src_enc):
        if name.endswith(".enc") and name not in written:
            os.remove(os.path.join(src_enc, name))
            removed += 1
    if args.pathlist:
        with open(args.pathlist, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(seen)) + "\n")
    print(f"OK: migrated {len(items)} 个文件 → v2；删除旧密文 {removed} 个；"
          f"KDF 次数={keyring.derivations}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="ooep 加密工具（v2：随机 blob_id + 会话级 salt）")
    ap.add_argument("--src", help="明文根目录（普通模式必填；内部相对路径=仓库内路径）")
    ap.add_argument("--out", required=True, help="密文输出目录（文件名=随机 blob_id）")
    ap.add_argument("--manifest", required=True, help="清单文件路径（整体重新生成）")
    ap.add_argument("--enc", help="迁移模式的源密文目录（默认与 --out 相同）")
    ap.add_argument("--migrate-v2", action="store_true", help="把存量密文全量迁移为 v2")
    ap.add_argument("--pathlist", help="可选：写出路径清单（仅本地用，不要入库）")
    ap.add_argument("--passphrase-file", help="从文件读取口令（否则用环境变量或交互输入）")
    args = ap.parse_args()

    passphrase = get_passphrase(args)
    if not passphrase:
        print("FAIL: 口令为空", file=sys.stderr)
        return 2
    if args.migrate_v2:
        return migrate_v2(args, passphrase)
    if not args.src:
        print("FAIL: 普通模式需要 --src", file=sys.stderr)
        return 2
    return encrypt_tree(args, passphrase)


if __name__ == "__main__":
    sys.exit(main())

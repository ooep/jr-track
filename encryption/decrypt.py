#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decrypt.py — CI 端解密 / 校验 / 清理工具（零依赖，仅 Python3 标准库）

先验后写契约（verify-then-write）
  * 一次 IO：每个密文只读一遍、只解密一遍，明文暂存在内存；
    清单里**每一个**文件都通过校验后，才允许进入落盘阶段（0.85 MB 级数据无压力）。
  * `decrypt --verify-only`：全量校验 = 清单集合一致 + 每文件 sha256(密文)
    + GCM tag（含 AAD 绑定）+ 每文件 HMAC-SHA256(明文) 对清单承诺
    + 路径集合与清单路径承诺（或 --expect-paths）一致。
    全部通过只打印 `OK n=<计数>`；任一失败立即非零退出。
    此模式**绝不创建/修改任何工作区文件**（明文只存在于进程内存）。
  * `decrypt`（落盘模式）：同样一次 IO 完整校验，但按性能契约**跳过明文 HMAC 复算**
    （GCM tag + AAD + 密文 sha256 已覆盖完整性）；全部通过后才一次性写盘，
    任何失败 → 零文件落盘。
  * v2 信封使用会话级 salt，Keyring 只跑一次 scrypt（整轮 110 文件复用）。
  * 兼容 v1（OOEP01）：AAD 用旧前缀，salt 每文件独立（按 salt 缓存，仍有加速）。

子命令：
  decrypt   见上。--force 允许覆盖已存在的同名明文（默认禁止）。
            --expect-paths 可选：额外核对期望路径清单（一行一个相对路径）。
  clean     按 --pathlist 记录的真实路径删除明文，并自底向上清理空目录
            （清单里没有路径，路径清单由落盘模式写在 RUNNER_TEMP，绝不入库）。

口令来自环境变量 OOEP_PASSPHRASE 或 --passphrase-file，绝不出现在命令行参数里。
默认输出只有一行 `OK n=<计数>`：不打印任何文件路径（路径本身就含模块/站点名）。
--verbose 仅供本地调试，CI 不用。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

import ooep_crypto as C


def _pathlist_default() -> str:
    return os.path.join(os.environ.get("RUNNER_TEMP") or "/tmp", "ooep-paths.txt")


def get_passphrase(args) -> bytes:
    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file, "rb") as f:
            return f.read().rstrip(b"\r\n")
    env = os.environ.get("OOEP_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    print("::error::E2 no key", file=sys.stderr)
    sys.exit(2)


def _fail(code: int, reason: str, args, detail: str = "") -> int:
    """固定错误码 + 通用文案；不打印路径/文件名，除非本地 --verbose。"""
    print(f"::error::E{code} {reason}", file=sys.stderr)
    if args.verbose and detail:
        print(detail, file=sys.stderr)   # 仅本地调试
    return 3


def _expected_paths(args):
    if not getattr(args, "expect_paths", None):
        return None
    with open(args.expect_paths, encoding="utf-8") as f:
        return {ln.strip() for ln in f if ln.strip()}


def _verify_all(args, manifest, passphrase, meta, check_mac: bool):
    """阶段一：全量校验（每个密文只解密一次）。返回暂存列表；任一失败返回 None。

    本函数不触碰工作区文件系统（只读密文），失败时保证零落盘。
    """
    keyring = C.Keyring(passphrase)
    staged = []
    seen = set()
    for bid in sorted(manifest):
        sha_want, mac_want, _ver = manifest[bid]
        path = os.path.join(args.enc, bid + ".enc")
        try:
            with open(path, "rb") as f:
                blob = f.read()
        except OSError as e:
            _fail(7, "read error", args, f"{bid}: {e}")
            return None
        if hashlib.sha256(blob).hexdigest() != sha_want:
            _fail(8, "ciphertext checksum mismatch", args, bid)
            return None
        try:
            payload, check_key, _ver = C.decrypt_blob(blob, passphrase, bid, keyring=keyring)
        except C.CryptoError:
            _fail(3, "integrity check failed", args, bid)
            return None
        if check_mac and C.plaintext_mac(check_key, payload) != mac_want:
            _fail(8, "plaintext mac mismatch", args, bid)
            return None
        try:
            rel, data = C.unpack(payload)
        except (C.CryptoError, ValueError):
            _fail(8, "payload malformed", args, bid)
            return None
        if rel in seen:
            _fail(8, "duplicate relative path", args, rel)
            return None
        seen.add(rel)
        staged.append((rel, data))

    # 路径集合一致性：优先用调用方给的期望清单，否则用清单里的集合承诺
    want = _expected_paths(args)
    if want is not None and want != seen:
        _fail(8, "path set mismatch", args,
              f"missing={len(want - seen)} extra={len(seen - want)}")
        return None
    if want is None and meta.get("pathset") and C.pathset_digest(seen) != meta["pathset"]:
        _fail(8, "path set commitment mismatch", args)
        return None
    return staged


def cmd_decrypt(args) -> int:
    os.umask(0o077)
    manifest, meta = C.read_manifest(args.manifest)
    if not manifest:
        return _fail(5, "manifest empty", args)
    if os.environ.get("OOEP_PASSPHRASE") == "" and not args.passphrase_file:
        return _fail(2, "no key", args)

    found = set()
    for dirpath, _dirnames, filenames in os.walk(args.enc):
        for name in filenames:
            if name.endswith(".enc"):
                found.add(name[:-4])
    if found != set(manifest):
        return _fail(6, "ciphertext set mismatch", args,
                     f"missing={len(set(manifest) - found)} extra={len(found - set(manifest))}")

    passphrase = get_passphrase(args)

    # ---- 阶段一：全量校验（GCM + 每文件 sha256；verify-only 额外复算明文 HMAC） ----
    staged = _verify_all(args, manifest, passphrase, meta, check_mac=args.verify_only)
    if staged is None:
        return 3  # 校验失败：到此为止，工作区零改动

    if args.verify_only:
        print(f"OK n={len(staged)}")
        return 0

    # ---- 阶段二：全部通过后才允许触碰工作区 ----
    if len(staged) != len(manifest):
        return _fail(5, "stage count mismatch", args)
    for rel, _data in staged:
        dest = os.path.join(args.out, rel.replace("/", os.sep))
        if os.path.exists(dest) and not args.force:
            # 解密目录残留：仓库里不该有同名明文
            return _fail(9, "target exists", args, rel)

    if args.pathlist:
        os.makedirs(os.path.dirname(args.pathlist) or ".", exist_ok=True)
        with open(args.pathlist, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(sorted(rel for rel, _ in staged)) + "\n")

    for rel, data in staged:
        dest = os.path.join(args.out, rel.replace("/", os.sep))
        d = os.path.dirname(dest)
        if d:
            os.makedirs(d, mode=0o700, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)

    if args.verbose:
        for rel, _data in staged:
            print(f"DEC {rel}")
    print(f"OK n={len(staged)}")
    return 0


def cmd_clean(args) -> int:
    removed = 0
    dirs = set()
    try:
        with open(args.pathlist, encoding="utf-8") as f:
            paths = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        print("OK n=0")
        return 0
    for rel in paths:
        dest = os.path.join(args.out, rel.replace("/", os.sep))
        if os.path.isfile(dest):
            os.remove(dest)
            removed += 1
        d = os.path.dirname(dest)
        while d and os.path.dirname(d) != d:
            dirs.add(d)
            d = os.path.dirname(d)
    for d in sorted(dirs, key=lambda p: p.count(os.sep), reverse=True):
        try:
            os.rmdir(d)
        except OSError:
            pass
    print(f"OK n={removed}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="解密/校验/清理工具")
    ap.add_argument("--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decrypt")
    d.add_argument("--enc", required=True)
    d.add_argument("--manifest", required=True)
    d.add_argument("--out", required=True)
    d.add_argument("--force", action="store_true")
    d.add_argument("--verify-only", action="store_true")
    d.add_argument("--pathlist", default=_pathlist_default())
    d.add_argument("--expect-paths")
    d.add_argument("--passphrase-file")

    c = sub.add_parser("clean")
    c.add_argument("--out", required=True)
    c.add_argument("--pathlist", default=_pathlist_default())

    args = ap.parse_args(argv)
    args.passphrase_file = getattr(args, "passphrase_file", None)
    try:
        return cmd_decrypt(args) if args.cmd == "decrypt" else cmd_clean(args)
    except C.CryptoError:
        return 3


if __name__ == "__main__":
    sys.exit(main())

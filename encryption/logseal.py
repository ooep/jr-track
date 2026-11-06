#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""logseal.py — 把业务日志封成**定长**密文块（日志模式 sealed / hybrid 用）

设计要点：
  * 密钥由 CODE_KEY 经 scrypt(固定域分离 salt) 派生，与源码密文用的是不同 key。
  * 每段日志**恒定输出 8 块 × 4096 字节**（base64 后每行 5464 字符），
    内容不足则零填充，超出则截断 —— 因此"10 行"与"10,000 行"打印出的块数与
    每块长度完全相同，长度侧信道被抹平。
  * payload 头部 4 字节记录原始长度，unseal 时可**逐字节还原**（≤32KB）。
  * 本工具是明文工具（不含任何数据源信息），因为它必须存在于解密之前。
"""
from __future__ import annotations

import argparse
import base64
import secrets
import sys

import ooep_crypto as C

LOG_SALT = b"ooep-log-v1"      # 域分离：日志 key ≠ 源码 key
AAD = b"OOEPLOG1"
BLOCK = 4096                   # 每块密文字节数
NBLOCKS = 8                    # 固定块数
TOTAL = BLOCK * NBLOCKS        # 32768 字节定长密文（含 nonce+tag）
NONCE_LEN = 12
TAG_LEN = 16
PAYLOAD = TOTAL - NONCE_LEN - TAG_LEN   # 32740
HDR = 4                        # payload 内：原始长度


def _key(passphrase: str) -> bytes:
    env_key = C.derive_keys(passphrase.encode("utf-8"), LOG_SALT)[0]
    return env_key[:32]


def cmd_seal(args) -> int:
    passphrase = (args.passphrase or "").strip()
    if not passphrase:
        print("::error::seal: no key", file=sys.stderr)
        return 3
    with open(args.file, "rb") as f:
        raw = f.read()
    # 超长时保留**尾部**（失败/异常信息通常在末尾），长度仍恒定为 8 块
    body = raw[-(PAYLOAD - HDR):]
    payload = len(body).to_bytes(HDR, "big") + body
    payload += b"\x00" * (PAYLOAD - len(payload))
    nonce = secrets.token_bytes(NONCE_LEN)
    ct, tag = C.aes_gcm_seal(_key(passphrase), nonce, payload, AAD)
    blob = nonce + ct + tag
    if len(blob) != TOTAL:
        print("::error::seal: size", file=sys.stderr)
        return 3
    for i in range(NBLOCKS):
        chunk = blob[i * BLOCK:(i + 1) * BLOCK]
        print(f"SEAL b{i + 1:02d}/{NBLOCKS:02d} {base64.b64encode(chunk).decode('ascii')}")
    return 0


def cmd_unseal(args) -> int:
    passphrase = (args.passphrase or "").strip()
    if not passphrase:
        print("::error::unseal: no key", file=sys.stderr)
        return 3
    blocks = {}
    for line in sys.stdin.buffer.read().decode("utf-8", "replace").splitlines():
        parts = line.strip().split(" ")
        if len(parts) >= 3 and parts[0] == "SEAL" and parts[1].startswith("b"):
            idx = int(parts[1][1:3])
            blocks[idx] = base64.b64decode(parts[2])
    if len(blocks) != NBLOCKS:
        print(f"::error::unseal: 块数 {len(blocks)} != {NBLOCKS}", file=sys.stderr)
        return 3
    blob = b"".join(blocks[i] for i in range(1, NBLOCKS + 1))
    nonce = blob[:NONCE_LEN]
    ct = blob[NONCE_LEN:NONCE_LEN + PAYLOAD]
    tag = blob[NONCE_LEN + PAYLOAD:]
    try:
        payload = C.aes_gcm_open(_key(passphrase), nonce, ct, tag, AAD)
    except C.CryptoError:
        print("::error::unseal: 解密失败（key 不对或块被改动）", file=sys.stderr)
        return 3
    n = int.from_bytes(payload[:HDR], "big")
    sys.stdout.write(payload[HDR:HDR + n].decode("utf-8", "replace"))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seal")
    s.add_argument("--file", required=True)
    s.add_argument("--label", default="")
    u = sub.add_parser("unseal")
    ap.add_argument("--passphrase", default="")
    args = ap.parse_args(argv)
    args.passphrase = args.passphrase or __import__("os").environ.get("OOEP_PASSPHRASE", "")
    return cmd_seal(args) if args.cmd == "seal" else cmd_unseal(args)


if __name__ == "__main__":
    sys.exit(main())

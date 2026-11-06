#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""shellredact.py — workflow 日志出口的**通用**脱敏过滤器（stdin -> stdout）

只做"形态"级替换，不含任何具体域名/接口名清单（那些在加密的 baker/redact.py 里），
因此本文件可安全地明文入库。

替换：完整 URL -> [URL]；裸域名 -> [HOST]；key/token/UUID/traceback 路径 -> 对应占位。
"""
from __future__ import annotations

import re
import sys

RULES = [
    # 完整 URL（含 query 参数）
    (re.compile(r"\b(?:https?|ftp|ws|wss)://[^\s\"'<>\)\]]+"), "[URL]"),
    # 裸域名 / 子域（含 .jp .go.jp .com .ing .dev .app .io .net .org .workers.dev 等）
    (re.compile(
        r"\b(?:[A-Za-z0-9_\-]+\.)+(?:jp|com|net|org|io|dev|app|ing|me|co|gg|tv|cc|"
        r"workers\.dev|vercel\.app|pages\.dev|github\.io|cloudflare\.com)\b"), "[HOST]"),
    # 常见 token 形态
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "[KEY]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[KEY]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9._\-]{20,}"), "[KEY]"),
    (re.compile(r"(?i)((?:api[_-]?key|token|secret|passwd|password|key)\s*[=:]\s*)"
                r"[^\s&\"',;]+"), r"\1[KEY]"),
    # UUID
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "[KEY]"),
    # 超长十六进制串（hash/sha 之外的密集随机串）
    (re.compile(r"\b[0-9a-fA-F]{40,}\b"), "[KEY]"),
    # 绝对路径中的用户名段
    (re.compile(r"(/Users/|/home/)([A-Za-z0-9._\-]+)"), r"\1[PATH]"),
    # 接口形态的固定路径段
    (re.compile(r"(?<=[A-Za-z0-9])/(?:api|v1|v2|v3|rest|graphql)(?:/[^\s\"']*)?"), "[API]"),
]


def redact_line(s: str) -> str:
    for pat, rep in RULES:
        s = pat.sub(rep, s)
    return s


def main() -> int:
    data = sys.stdin.buffer.read().decode("utf-8", "replace")
    sys.stdout.write("".join(redact_line(ln) for ln in data.splitlines(keepends=True)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

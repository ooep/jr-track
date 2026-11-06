#!/usr/bin/env bash
# logrun.sh — workflow 的唯一日志出口（默认脱敏明文，密文为可选开关）
#
#   bash encryption/logrun.sh <label> <cmd...>
#
# 模式解析（优先级从高到低）：
#   1) LOG_MODE 环境变量 = plain_redacted | sealed | hybrid
#   2) SEALED_LOG=1 -> hybrid（终端只留 STEP/FAIL 状态 + 定长密文块）
#   3) 默认 plain_redacted：业务输出经 encryption/shellredact.py 形态过滤后原样外显
#
# 业务 stdout/stderr 一律先落到 600 权限的临时文件（umask 077），退出（含信号）时必删。
set -uo pipefail
mode="${LOG_MODE:-}"
if [ -z "$mode" ]; then
  case "${SEALED_LOG:-0}" in
    1) mode=hybrid ;;
    *) mode=plain_redacted ;;
  esac
fi
case "$mode" in
  sealed|hybrid) ;;
  *) mode=plain_redacted ;;
esac

label="${1:-STEP}"; shift || true
if [ "$#" -eq 0 ]; then
  echo "::error::${label} FAIL E4"
  exit 4
fi

umask 077
tmp="$(mktemp "${TMPDIR:-/tmp}/lg.XXXXXXXX")" || { echo "::error::${label} FAIL E4"; exit 4; }
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT INT TERM HUP

code=0
"$@" >"$tmp" 2>&1 || code=$?

seal() { python3 encryption/logseal.py seal --file "$tmp"; }

if [ "$code" -eq 0 ]; then
  case "$mode" in
    sealed) seal ;;
    hybrid) echo "STEP ${label} OK"; seal ;;
    *) python3 encryption/shellredact.py <"$tmp" ;;
  esac
else
  echo "::error::${label} FAIL E${code}"
  case "$mode" in
    sealed|hybrid) seal ;;
    *) python3 encryption/shellredact.py <"$tmp" ;;
  esac
fi
exit "$code"

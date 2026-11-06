#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
incremental_check.py — 增量判断：基线 ref 与 head 之间 figures 的新增/变更/删除。

用法（Actions runner，已 checkout）:
  python scripts/incremental_check.py [--base REF] [--head REF] [--root downloads]
  --base 默认 = 最近一次 message 以 'round-corners batch' 开头的 commit（即上次 apply 落点）
输出 JSON: {base, head, added[], modified[], deleted[], should_apply, summary}
cron/push 触发时用它判断"该不该 apply"；push 增量apply 的文件清单由 batch_apply --incremental 直接取 event.before..after。
"""
import argparse, json, subprocess, sys

# 显式白名单：确认无可圆角边界的文件（不计入 should_apply，避免误报"未处理"）
# 证据（2026-11-04 核查，blob 9d2377d839）：分界点碎片图（神崎川信交界）：path=0；
# rect=85 全为高 1.0 单位默认黑填充压扁虚线条（42×(2.9,1.0)+41×(8.6,1.0)+2），无浅色填充/描边长条；
# line=4（2 平行横线+2 斜线，共享端点度≥2 者 0 个，斜线为断口非连续折线）；
# 守卫版 transform=clean 且输出 sha 恒等于输入。若未来被 crawler 重写且出现可圆角元素，删除本条目。
WHITELIST = {
    'downloads/documents/jr/west/katamachi/figures/020_10.svg':
        '分界点碎片图：0 站台（无浅色填充/描边长条，path=0）、0 度=2 拐点（4 独立 line 无共享端点）、'
        '85 个高1单位压扁虚线条；guard transform=clean（输出 sha 恒等）',
    'downloads/documents/metro/kagoshima/figures/010_04.svg':
        '92 rect/11 line/2 path 无可圆角边界，输出恒等输入（2026-11-04 核查：transform=skipped_geometry，'
        'rect 全为压扁条、line 无度=2 同样式接合点、2 path 非站台边界；守卫版输出 sha 恒等于输入）',
    # 2026-11-04 核查：transform=skipped_geometry，输出 sha 恒等于输入，bbox_delta=0（无可圆角站台/接合点）
    'downloads/documents/metro/kumamoto/figures/010_02.svg':
        '无可圆角边界（transform=skipped_geometry；守卫版输出 sha 恒等，bbox_delta=0.0，validate 通过）',
}

def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    return r.stdout.strip()

def tree_svgs(ref, root):
    out = sh('git', 'ls-tree', '-r', ref, '--', root)
    d = {}
    for line in out.splitlines():
        meta, path = line.split('\t', 1)
        if path.endswith('.svg'):
            d[path] = meta.split()[2]
    return d

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default='')
    ap.add_argument('--head', default='HEAD')
    ap.add_argument('--root', default='downloads')
    args = ap.parse_args()
    base = args.base or sh('git', 'log', '-1', '--format=%H', '--grep=^round-corners batch', args.head)
    head = sh('git', 'rev-parse', args.head)
    if not base:
        print(json.dumps({'base': None, 'head': head, 'added': [], 'modified': [], 'deleted': [],
                          'should_apply': False, 'summary': '新增 0 / 变更 0 / 删除 0 / 无基线(从未 apply)'}))
        return
    b, h = tree_svgs(base, args.root), tree_svgs(head, args.root)
    added = sorted(p for p in h if p not in b)
    modified = sorted(p for p in h if p in b and h[p] != b[p])
    deleted = sorted(p for p in b if p not in h)
    wl_note = [p for p in added + modified if p in WHITELIST]
    should_apply = bool((set(added) | set(modified)) - set(WHITELIST))
    res = {'base': base, 'head': head, 'added': added, 'modified': modified, 'deleted': deleted,
           'should_apply': should_apply, 'whitelisted_hit': wl_note,
           'summary': f"新增 {len(added)} / 变更 {len(modified)} / 删除 {len(deleted)}"
                      + (f"（白名单命中 {len(wl_note)}，不计入 should_apply）" if wl_note else "")}
    print(json.dumps(res, ensure_ascii=False, indent=1))
    sys.exit(0)

if __name__ == '__main__':
    main()

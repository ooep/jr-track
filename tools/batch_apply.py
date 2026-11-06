#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
batch_apply.py — 在 GitHub Actions runner 上执行全量/增量圆角化并分批提交推送。

纪律:
  - 每批 ≤ BATCH 个文件，一批一次 commit；commit message 含批次与参数
  - force:false；推前两次 GET 复核 head；复核被改文件旧 blob 未变
  - 只写 SVG；幂等（data-round 标记）
  - 推后随机抽 5 个文件回归校验
"""
import argparse, json, os, random, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import round_corners as rc

PARAMS_NOTE = (f"platform R={rc.PLATFORM_R_RATIO:.0%}of short side clamp[{rc.PLATFORM_R_MIN:g},{rc.PLATFORM_R_MAX:g}] "
               f"area<={{area}}; track R={rc.TRACK_FILLET_K}x stroke-width; mark={rc.MARK_ATTR}={rc.VERSION}")

def sh(*args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"cmd failed: {args}\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip()

def head_sha():
    return sh('git', 'rev-parse', 'origin/main')

def load_params(path):
    try:
        return json.load(open(path))
    except Exception:
        return {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='downloads')
    ap.add_argument('--batch', type=int, default=100)
    ap.add_argument('--area-loss-max', type=float, default=0.0)
    ap.add_argument('--params', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'params.json'))
    ap.add_argument('--incremental', nargs=2, metavar=('BEFORE', 'AFTER'), default=None)
    ap.add_argument('--seed', type=int, default=7)
    args = ap.parse_args()

    params = load_params(args.params)
    event = os.environ.get('GITHUB_EVENT_NAME', '')
    dispatched = event == 'workflow_dispatch'
    if event == 'schedule':
        print(json.dumps({'status': 'scan_only', 'note': 'schedule 永不 apply'}, ensure_ascii=False))
        return
    if event == 'push':
        if not params.get('enabled', False) or not args.incremental:
            print(json.dumps({'status': 'disabled', 'note': 'push 增量需 params.enabled=true 且 --incremental'}, ensure_ascii=False))
            return
    if not dispatched and not params.get('enabled', False):
        msg = {'status': 'disabled', 'note': 'tools/params.json enabled!=true 且非 workflow_dispatch；仅扫描不提交'}
        print(json.dumps(msg, ensure_ascii=False))
        with open(os.environ.get('GITHUB_STEP_SUMMARY', '/dev/null'), 'a') as f:
            f.write("### round-corners apply\n- disabled by params gate (no commits)\n")
        return
    if not args.area_loss_max:
        args.area_loss_max = float(params.get('area_loss_max', rc.AREA_LOSS_MAX_DEFAULT))
    if params.get('batch'):
        args.batch = min(args.batch, int(params['batch']))

    sh('git', 'config', 'user.name', 'jr-track-bot')
    sh('git', 'config', 'user.email', 'jr-track-bot@users.noreply.github.com')
    sh('git', 'fetch', 'origin', 'main')
    base = head_sha()

    changed, skipped, invalid, errors = [], [], [], []
    deleted_skipped = []
    if args.incremental:
        diff = sh('git', 'diff', '--name-only', args.incremental[0], args.incremental[1], '--', args.root)
        targets = [l for l in diff.splitlines() if l.endswith('.svg')]
        # 删除过滤：本 push 删除的文件已不在工作区，open 会报错；直接跳过并在 report 单列计数（2026-11-04 修复）
        deleted = set(sh('git', 'diff', '--name-only', '--diff-filter=D',
                         args.incremental[0], args.incremental[1], '--', args.root).splitlines())
        deleted_skipped = [p for p in targets if p in deleted]
        targets = [p for p in targets if p not in deleted]
    else:
        targets = [os.path.relpath(fp, '.') for fp in rc.iter_svg_files(args.root)]
    for rel in targets:
        fp = rel
        raw = open(fp, encoding='utf-8', newline='').read()
        if not raw.rstrip().endswith('</svg>'):
            invalid.append({'path': rel, 'reason': 'not_closed'})
            continue
        try:
            import xml.etree.ElementTree as ET
            ET.fromstring(raw)
        except Exception:
            invalid.append({'path': rel, 'reason': 'xml_parse'})
            continue
        new_raw, rep = rc.transform_file(raw, args.area_loss_max)
        rep['path'] = rel
        if rep['status'] == 'error':
            errors.append(rep)
            continue
        if rep['status'] == 'changed':
            ok, probs = rc.validate(raw, new_raw)
            if not ok:
                invalid.append({'path': rel, 'reason': ';'.join(probs)})
                continue
            again, _ = rc.transform_file(new_raw, args.area_loss_max)
            if again != new_raw:
                invalid.append({'path': rel, 'reason': 'not_idempotent'})
                continue
            open(fp, 'w', encoding='utf-8', newline='').write(new_raw)
            changed.append(rep)
        elif rep['status'] == 'skipped_geometry':
            skipped.append(rep)

    report = {'base': base, 'changed': len(changed), 'skipped': len(skipped),
              'deleted_skipped': len(deleted_skipped), 'deleted_skipped_paths': deleted_skipped,
              'invalid': invalid, 'errors': errors,
              'platforms_rounded': sum(c['platform_rounded'] for c in changed),
              'corners_rounded': sum(c['corners_rounded'] for c in changed),
              'commits': []}

    if not changed:
        print(json.dumps(report, ensure_ascii=False, indent=1))
        open('apply_report.json', 'w').write(json.dumps(report, ensure_ascii=False, indent=1))
        return

    # 分批提交推送
    random.seed(args.seed)
    batches = [changed[i:i+args.batch] for i in range(0, len(changed), args.batch)]
    for bi, batch in enumerate(batches, 1):
        # 推前两次 GET 复核 head
        h1 = head_sha()
        time.sleep(2)
        h2 = head_sha()
        if h1 != h2:
            report['commits'].append({'batch': bi, 'status': 'aborted_head_moved'})
            break
        # 复核被改文件旧 blob 未变（origin/main 上的版本 == 我们的变换基底 HEAD）
        drift = []
        for c in batch:
            rel = c['path']
            old = subprocess.run(['git', 'rev-parse', f'origin/main:{rel}'],
                                 capture_output=True, text=True).stdout.strip()
            mine = subprocess.run(['git', 'rev-parse', f'HEAD:{rel}'],
                                  capture_output=True, text=True).stdout.strip()
            if old != mine:
                drift.append(rel)
        if drift:
            report['commits'].append({'batch': bi, 'status': 'aborted_blob_drift', 'files': drift[:10]})
            break
        for c in batch:
            sh('git', 'add', c['path'])
        msg = (f"round-corners batch {bi}/{len(batches)}: {len(batch)} files | " +
               PARAMS_NOTE.format(area=f"{args.area_loss_max:.3f}"))
        sh('git', 'commit', '-m', msg)
        r = subprocess.run(['git', 'push', 'origin', 'main'], capture_output=True, text=True)
        if r.returncode != 0:
            report['commits'].append({'batch': bi, 'status': 'push_failed', 'err': r.stderr[-500:]})
            break
        sh('git', 'fetch', 'origin', 'main')
        report['commits'].append({'batch': bi, 'status': 'pushed', 'sha': head_sha(),
                                  'files': len(batch)})

    # 回归：随机抽 5 个已改文件校验
    sample = random.sample(changed, min(5, len(changed)))
    reg = []
    for c in sample:
        raw = open(c['path'], encoding='utf-8').read()
        ok, probs = rc.validate(raw, raw)
        reg.append({'path': c['path'], 'ok': ok, 'problems': probs})
    report['regression'] = reg
    print(json.dumps(report, ensure_ascii=False, indent=1))
    open('apply_report.json', 'w').write(json.dumps(report, ensure_ascii=False, indent=1))
    with open(os.environ.get('GITHUB_STEP_SUMMARY', '/dev/null'), 'a') as f:
        f.write(f"### round-corners apply\n- changed: {report['changed']}\n"
                f"- platforms_rounded: {report['platforms_rounded']}\n"
                f"- corners_rounded: {report['corners_rounded']}\n"
                f"- skipped: {report['skipped']}\n- invalid: {len(invalid)}\n"
                f"- commits: {json.dumps(report['commits'], ensure_ascii=False)}\n"
                f"- regression: {json.dumps(reg, ensure_ascii=False)}\n")

if __name__ == '__main__':
    main()

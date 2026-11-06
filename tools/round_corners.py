#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round_corners.py — 车站配线图视觉圆角化（站台圆角 + 线路转弯 fillet）v1

子命令:
  scan    只读全量扫描: 损坏定性 / 元素归类 / 试做候选 / 参数统计
  apply   应用变换（幂等；已处理元素带 data-round="1"，重跑不叠加）
  verify  回归校验（XML 合法性 / viewBox 未变 / 路径字符集）

仓库实况（勘察结论）:
  - SVG 为 Illustrator 导出（配線略図.net 存档），无生成器 → 批量变换
  - 站台 = 浅色填充细长 rect（可含同样式描边孪生 rect）
  - 线路 = <line> 描边线段；转弯只出现在同样式 <line> 共享端点处（仓库无 polyline）
  - 压扁细条（无样式 path / 细 rect）= Illustrator 压扁的线，不动
  - 度=2 接合点 → 圆角；度≥3（分叉/交叉）与单根直线 → 不动

参数（集中，便于回退）:
"""
import argparse, json, math, os, re, sys, random
import xml.etree.ElementTree as ET

# ============================ 参数 ============================
VERSION = "1"
MARK_ATTR = "data-round"            # 幂等标记
PLATFORM_R_RATIO = 0.06             # 站台半径 = 短边 × 6%
PLATFORM_R_MIN = 2.0                # 下限 2 单位
PLATFORM_R_MAX = 10.0               # 上限 10 单位
AREA_LOSS_MAX_DEFAULT = 0.005       # 站台面积损失上限（默认 0.5%，可 --area-loss-max 覆盖）
TRACK_FILLET_K = 1.2                # 线路 fillet 半径 = 1.2 × 线宽
PLATFORM_ASPECT_MIN = 2.5           # 站台长边/短边 ≥ 2.5
PLATFORM_SHORT_MIN = 3.0            # 站台短边 ≥ 3（排除碎块）
BG_AREA_FRAC_MAX = 0.25             # 面积 > viewBox 25% 视为背景板
LIGHT_FILLS = {"#ffffff", "#fff", "white", "#bfbfbf", "#f2f2f2", "#e6e6e6",
               "#d9d9d9", "#f7f7f7", "#fafafa"}
COLLISION_STEP = 0.25               # 间隙冲突时半径递减步长
JUNC_EPS = 0.06                     # 接合点端点重合容差
FMT_PREC = 3                        # 输出坐标精度
# ==============================================================

TAG_RE = re.compile(r'<(?P<close>/?)\s*(?P<name>[A-Za-z_][\w.:-]*)(?P<attrs>[^<>]*?)(?P<self>/?)\s*>')
ATTR_RE = re.compile(r'([\w:.-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\')')
NUM_RE = re.compile(r'[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?')

def fmt(x):
    s = f"{x:.{FMT_PREC}f}".rstrip('0').rstrip('.')
    if s in ('', '-0'):
        return '0'
    return s

# ------------------------------ 标签流扫描 ------------------------------
def scan_tags(s):
    i, n = 0, len(s)
    while i < n:
        j = s.find('<', i)
        if j < 0:
            break
        if s.startswith('<!--', j):
            k = s.find('-->', j + 4)
            i = (k + 3) if k >= 0 else n
            continue
        if s[j:j+2] in ('<?', '<!'):
            k = s.find('>', j)
            i = (k + 1) if k >= 0 else n
            continue
        m = TAG_RE.match(s, j)
        if not m:
            i = j + 1
            continue
        attrs = {}
        for am in ATTR_RE.finditer(m.group('attrs')):
            attrs[am.group(1)] = am.group(2) if am.group(2) is not None else am.group(3)
        yield m.span(), bool(m.group('close')), m.group('name'), attrs, bool(m.group('self'))
        i = m.end()

def parse_css(text):
    """解析 <style>：支持逗号分组选择器与 px 单位。"""
    out = {}
    for m in re.finditer(r'([^{}]+)\{([^}]*)\}', text or ''):
        decls = {}
        for d in m.group(2).split(';'):
            if ':' in d:
                k, v = d.split(':', 1)
                decls[k.strip()] = v.strip()
        for sel in m.group(1).split(','):
            sel = sel.strip()
            if sel.startswith('.'):
                name = sel[1:].split()[0].split(':')[0]
                if re.fullmatch(r'[\w-]+', name):
                    out.setdefault(name, {}).update(decls)
    return out

def css_num(v):
    """'1.5px' / '.8px' / '1.5' → float；失败返回 None。"""
    if v is None:
        return None
    m = re.match(r'^([-+]?(?:\d+\.?\d*|\.\d+))\s*(px|pt|em)?$', v.strip())
    return float(m.group(1)) if m else None

def style_of(attrs, css):
    d = {}
    for c in (attrs.get('class') or '').split():
        d.update(css.get(c, {}))
    for k in ('fill', 'stroke', 'stroke-width', 'fill-rule', 'stroke-dasharray'):
        if k in attrs:
            d[k] = attrs[k]
    st = attrs.get('style') or ''
    for part in st.split(';'):
        if ':' in part:
            k, v = part.split(':', 1)
            d[k.strip()] = v.strip()
    return d

INHERITABLE = ('stroke', 'stroke-width', 'fill')
CONTAINER_SKIP = ('defs', 'clipPath', 'symbol', 'pattern', 'mask')

def build_context(raw):
    """返回 (css, shapes)；shapes 带继承样式与 in_defs 标志。"""
    css = {}
    for span, close, name, attrs, selfc in scan_tags(raw):
        if name == 'style' and not close:
            end = raw.find('</style>', span[1])
            css.update(parse_css(raw[span[1]:end if end >= 0 else None]))
            break
    shapes = []
    stack = [{'style': {}, 'skip': False}]
    for span, close, name, attrs, selfc in scan_tags(raw):
        if close:
            if len(stack) > 1:
                stack.pop()
            continue
        own = style_of(attrs, css)
        inherited = dict(stack[-1]['style'])
        for k in INHERITABLE:
            if k in own:
                inherited[k] = own[k]
        in_skip = stack[-1]['skip'] or (name in CONTAINER_SKIP)
        if name in ('g', 'svg', 'a') or name in CONTAINER_SKIP:
            if not selfc:
                stack.append({'style': inherited, 'skip': in_skip})
            continue
        if name in ('rect', 'path', 'polyline', 'polygon', 'line', 'ellipse', 'circle'):
            anc_transform = any('transform' in (s.get('attrs') or {}) for s in stack[1:])
            shapes.append({
                'tag': name, 'span': span, 'attrs': attrs, 'own': own,
                'inherited': inherited, 'selfc': selfc, 'in_defs': in_skip,
                'has_transform': ('transform' in attrs) or anc_transform,
            })
        elif name in ('text', 'tspan'):
            shapes.append({'tag': name, 'span': span, 'attrs': attrs, 'own': own,
                           'inherited': inherited, 'selfc': selfc, 'in_defs': in_skip,
                           'has_transform': 'transform' in attrs})
    return css, shapes

def resolved_fill(s):
    f = s['own'].get('fill') or s['inherited'].get('fill') or '#000000'
    return norm_color(f)

def resolved_stroke(s):
    return norm_color(s['own'].get('stroke') or s['inherited'].get('stroke'))

def resolved_sw(s):
    v = s['own'].get('stroke-width') or s['inherited'].get('stroke-width')
    return css_num(v)

def norm_color(c):
    if not c:
        return None
    c = c.strip().lower()
    m = re.fullmatch(r'#([0-9a-f]{3})', c)
    if m:
        c = '#' + ''.join(ch * 2 for ch in m.group(1))
    return c

# ------------------------------ 几何 ------------------------------
def parse_d_pts(d):
    """仅直线命令的 path → (子路径点列, ok)；含曲线 ok=False。"""
    toks = re.findall(r'[MLHVZmlhvzCSQTAcsqta]|' + NUM_RE.pattern, d)
    subs, cur, start, cur_sub = [], (0.0, 0.0), (0.0, 0.0), []
    i, cmd = 0, None
    while i < len(toks):
        t = toks[i]
        if re.fullmatch(r'[MLHVZmlhvzCSQTAcsqta]', t):
            cmd = t
            i += 1
            if cmd in 'Zz':
                cur = start
                cur_sub.append(cur)
            elif cmd in 'Mm':
                if cur_sub:
                    subs.append(cur_sub)
                cur_sub = []
            continue
        if cmd is None:
            return None, False
        if cmd in 'MmLl':
            if i + 1 >= len(toks):
                return None, False
            x, y = float(toks[i]), float(toks[i+1])
            i += 2
            cur = (cur[0] + x, cur[1] + y) if cmd.islower() else (x, y)
            if cmd in 'Mm':
                start = cur
            cur_sub.append(cur)
        elif cmd in 'Hh':
            x = float(toks[i]); i += 1
            cur = (cur[0] + x, cur[1]) if cmd == 'h' else (x, cur[1])
            cur_sub.append(cur)
        elif cmd in 'Vv':
            y = float(toks[i]); i += 1
            cur = (cur[0], cur[1] + y) if cmd == 'v' else (cur[0], y)
            cur_sub.append(cur)
        else:
            return None, False
    if cur_sub:
        subs.append(cur_sub)
    return subs, True

def rect_geo(attrs):
    try:
        x, y = float(attrs.get('x', 0)), float(attrs.get('y', 0))
        w, h = float(attrs['width']), float(attrs['height'])
    except (KeyError, ValueError):
        return None
    if w <= 0 or h <= 0:
        return None
    return x, y, w, h

def seg_dist_pt_seg(p, a, b):
    ax, ay, bx, by = *a, *b
    dx, dy = bx - ax, by - ay
    l2 = dx * dx + dy * dy
    if l2 < 1e-12:
        return math.hypot(p[0] - ax, p[1] - ay)
    t = max(0.0, min(1.0, ((p[0] - ax) * dx + (p[1] - ay) * dy) / l2))
    return math.hypot(p[0] - (ax + t * dx), p[1] - (ay + t * dy))

def seg_seg_dist(a, b, c, d):
    def intersect():
        (x1, y1), (x2, y2), (x3, y3), (x4, y4) = a, b, c, d
        den = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4)
        if abs(den) < 1e-12:
            return False
        t = ((x1 - x3) * (y3 - y4) - (y1 - y3) * (x3 - x4)) / den
        u = -((x1 - x2) * (y1 - y3) - (y1 - y2) * (x1 - x3)) / den
        return -1e-9 <= t <= 1 + 1e-9 and -1e-9 <= u <= 1 + 1e-9
    if intersect():
        return 0.0
    return min(seg_dist_pt_seg(a, c, d), seg_dist_pt_seg(b, c, d),
               seg_dist_pt_seg(c, a, b), seg_dist_pt_seg(d, a, b))

def rect_rect_dist(r1, r2):
    ax0, ay0, ax1, ay1 = r1
    bx0, by0, bx1, by1 = r2
    gx = max(ax0 - bx1, bx0 - ax1, 0.0)
    gy = max(ay0 - by1, by0 - ay1, 0.0)
    if gx > 0 and gy > 0:
        return math.hypot(gx, gy)
    return max(gx, gy)

def seg_rect_dist(a, b, r):
    x0, y0, x1, y1 = r
    sbb = (min(a[0], b[0]), min(a[1], b[1]), max(a[0], b[0]), max(a[1], b[1]))
    if rect_rect_dist(sbb, r) > 0:
        corners = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
        ds = [seg_dist_pt_seg(c, a, b) for c in corners]
        sides = [seg_seg_dist(a, b, corners[k], corners[(k + 1) % 4]) for k in range(4)]
        return min(min(ds), min(sides))
    return 0.0

def get_viewbox(raw):
    m = re.search(r'<svg\b[^>]*\bviewBox\s*=\s*"([^"]*)"', raw) or \
        re.search(r"<svg\b[^>]*\bviewBox\s*=\s*'([^']*)'", raw)
    if not m:
        return None
    try:
        v = [float(x) for x in m.group(1).split()]
        return tuple(v[:4]) if len(v) >= 4 else None
    except ValueError:
        return None

# ------------------------------ 分类 ------------------------------
def classify(shapes, viewBox):
    """返回 (roles, obstacles_seg, obstacles_rect, platforms, lines_track)。"""
    vb_area = (viewBox[2] * viewBox[3]) if viewBox else 1e9
    roles = {}
    platforms = []
    obstacles_seg, obstacles_rect = [], []   # (geom, order)
    lines_track = []
    for i, s in enumerate(shapes):
        s['order'] = i

    for s in shapes:
        if s['in_defs'] or s['tag'] in ('text', 'tspan'):
            roles[id(s)] = 'text' if s['tag'] in ('text', 'tspan') else 'defs'
            continue
        if s['attrs'].get('clip-path') or s['own'].get('clip-path'):
            roles[id(s)] = 'clipped'  # 被裁剪元素：不处理，仅计障碍
            g = rect_geo(s['attrs']) if s['tag'] == 'rect' else None
            if g:
                x, y, w, h = g
                obstacles_rect.append(((x, y, x + w, y + h), s['order']))
            continue

    # 站台（浅色填充细长形）
    for s in shapes:
        if id(s) in roles:
            continue
        tag, attrs = s['tag'], s['attrs']
        fill = resolved_fill(s)
        if tag == 'rect':
            g = rect_geo(attrs)
            if not g:
                continue
            x, y, w, h = g
            if w * h > BG_AREA_FRAC_MAX * vb_area:
                roles[id(s)] = 'background'
                continue
            short, long_ = min(w, h), max(w, h)
            if fill in LIGHT_FILLS and long_ / max(short, 1e-9) >= PLATFORM_ASPECT_MIN \
               and short >= PLATFORM_SHORT_MIN:
                roles[id(s)] = 'platform'
                platforms.append({'shape': s, 'geo': g, 'kind': 'rect'})
        elif tag == 'path':
            subs, ok = parse_d_pts(attrs.get('d') or '')
            if not ok or not subs or fill not in LIGHT_FILLS or len(subs) != 1:
                continue
            pts = subs[0]
            if len(pts) >= 2 and abs(pts[0][0]-pts[-1][0]) < 1e-6 and abs(pts[0][1]-pts[-1][1]) < 1e-6:
                pts = pts[:-1]
            if len(pts) == 4:
                xs = sorted(set(round(p[0], 3) for p in pts))
                ys = sorted(set(round(p[1], 3) for p in pts))
                if len(xs) == 2 and len(ys) == 2:
                    x0, x1, y0, y1 = xs[0], xs[1], ys[0], ys[1]
                    w, h = x1 - x0, y1 - y0
                    short, long_ = min(w, h), max(w, h)
                    if w * h <= BG_AREA_FRAC_MAX * vb_area and \
                       long_ / max(short, 1e-9) >= PLATFORM_ASPECT_MIN and short >= PLATFORM_SHORT_MIN:
                        roles[id(s)] = 'platform'
                        platforms.append({'shape': s, 'geo': (x0, y0, w, h), 'kind': 'path'})

    # 其余
    for s in shapes:
        if id(s) in roles:
            continue
        tag, attrs = s['tag'], s['attrs']
        fill = resolved_fill(s)
        stroke = resolved_stroke(s)
        if tag == 'line':
            try:
                a = (float(attrs.get('x1', 0)), float(attrs.get('y1', 0)))
                b = (float(attrs.get('x2', 0)), float(attrs.get('y2', 0)))
            except ValueError:
                roles[id(s)] = 'other'
                continue
            roles[id(s)] = 'track'
            obstacles_seg.append(((a, b), s['order']))
            lines_track.append({'shape': s, 'a': a, 'b': b})
            continue
        if tag in ('path', 'polyline'):
            if stroke and stroke != 'none':
                # 描边孪生（与某站台同几何的正交闭合 path）→ 站台描边
                subs, ok = parse_d_pts(attrs.get('d') or '') if tag == 'path' else (None, False)
                if ok and subs and len(subs) == 1:
                    pts = subs[0]
                    if len(pts) >= 2 and abs(pts[0][0]-pts[-1][0]) < 1e-6 and abs(pts[0][1]-pts[-1][1]) < 1e-6:
                        pts = pts[:-1]
                    if len(pts) == 4:
                        xs = sorted(set(round(p[0], 3) for p in pts))
                        ys = sorted(set(round(p[1], 3) for p in pts))
                        if len(xs) == 2 and len(ys) == 2:
                            g = (xs[0], ys[0], xs[1]-xs[0], ys[1]-ys[0])
                            if any(abs(g[0]-p['geo'][0]) < 0.05 and abs(g[1]-p['geo'][1]) < 0.05 and
                                   abs(g[2]-p['geo'][2]) < 0.05 and abs(g[3]-p['geo'][3]) < 0.05
                                   for p in platforms):
                                roles[id(s)] = 'platform-outline'
                                continue
                roles[id(s)] = 'track'
                if tag == 'path':
                    subs, ok = parse_d_pts(attrs.get('d') or '')
                    if ok and subs:
                        for sub in subs:
                            for k in range(len(sub) - 1):
                                obstacles_seg.append(((sub[k], sub[k + 1]), s['order']))
                else:
                    nums = [float(v) for v in NUM_RE.findall(attrs.get('points') or '')]
                    pp = list(zip(nums[0::2], nums[1::2]))
                    for k in range(len(pp) - 1):
                        obstacles_seg.append(((pp[k], pp[k + 1]), s['order']))
                continue
            # 无描边：压扁条带或填充形
            roles[id(s)] = 'track-flat' if tag == 'path' else 'filled-shape'
            if tag == 'path':
                subs, ok = parse_d_pts(attrs.get('d') or '')
                if ok and subs:
                    for sub in subs:
                        xs = [p[0] for p in sub]; ys = [p[1] for p in sub]
                        if xs and ys:
                            obstacles_rect.append(((min(xs), min(ys), max(xs), max(ys)), s['order']))
            else:
                nums = [float(v) for v in NUM_RE.findall(attrs.get('points') or '')]
                pp = list(zip(nums[0::2], nums[1::2]))
                if pp:
                    xs = [p[0] for p in pp]; ys = [p[1] for p in pp]
                    obstacles_rect.append(((min(xs), min(ys), max(xs), max(ys)), s['order']))
            continue
        if tag == 'rect':
            g = rect_geo(attrs)
            if not g:
                roles[id(s)] = 'other'
                continue
            x, y, w, h = g
            short, long_ = min(w, h), max(w, h)
            if stroke and stroke != 'none':
                twin = any(abs(x-p['geo'][0]) < 0.05 and abs(y-p['geo'][1]) < 0.05 and
                           abs(w-p['geo'][2]) < 0.05 and abs(h-p['geo'][3]) < 0.05
                           for p in platforms)
                if twin:
                    roles[id(s)] = 'platform-outline'
                else:
                    roles[id(s)] = 'track'
                    obstacles_rect.append(((x, y, x + w, y + h), s['order']))
            elif fill not in (None, 'none') and short <= 2.0 and long_ / max(short, 1e-9) >= 3:
                roles[id(s)] = 'track-flat'
                obstacles_rect.append(((x, y, x + w, y + h), s['order']))
            elif fill not in (None, 'none'):
                roles[id(s)] = 'filled-shape'
                obstacles_rect.append(((x, y, x + w, y + h), s['order']))
            else:
                roles[id(s)] = 'other'
            continue
        if tag in ('polygon', 'ellipse', 'circle'):
            roles[id(s)] = 'filled-shape'
            if tag == 'polygon' and attrs.get('points'):
                nums = [float(v) for v in NUM_RE.findall(attrs['points'])]
                pp = list(zip(nums[0::2], nums[1::2]))
                if pp:
                    xs = [p[0] for p in pp]; ys = [p[1] for p in pp]
                    obstacles_rect.append(((min(xs), min(ys), max(xs), max(ys)), s['order']))
            elif tag in ('ellipse', 'circle'):
                try:
                    cx = float(attrs.get('cx', 0)); cy = float(attrs.get('cy', 0))
                    if tag == 'circle':
                        r = float(attrs.get('r', 0))
                        rx = ry = r
                    else:
                        rx = float(attrs.get('rx', 0)); ry = float(attrs.get('ry', 0))
                    obstacles_rect.append(((cx-rx, cy-ry, cx+rx, cy+ry), s['order']))
                except ValueError:
                    pass
            continue
        roles[id(s)] = 'other'
    return roles, obstacles_seg, obstacles_rect, platforms, lines_track

# ------------------------------ 间隙校验 ------------------------------
def corner_collision(px, py, sx, sy, r, seg_list, rect_list):
    def local(p):
        return (p[0] - px) * sx, (p[1] - py) * sy
    for a, b in seg_list:
        la, lb = local(a), local(b)
        t0, t1 = 0.0, 1.0
        dx, dy = lb[0] - la[0], lb[1] - la[1]
        ok = True
        for p, q in ((-dx, la[0]), (dx, r - la[0]), (-dy, la[1]), (dy, r - la[1])):
            if abs(p) < 1e-12:
                if q < 0:
                    ok = False
                    break
            else:
                t = q / p
                if p < 0:
                    if t > t1:
                        ok = False
                        break
                    t0 = max(t0, t)
                else:
                    if t < t0:
                        ok = False
                        break
                    t1 = min(t1, t)
        if not ok or t0 > t1:
            continue
        for t in (t0, t1):
            ax, ay = la[0] + t * dx, la[1] + t * dy
            if 0 <= ax <= r and 0 <= ay <= r and (ax * ax + ay * ay) > r * r + 1e-9:
                return True
    for (x0, y0, x1, y1) in rect_list:
        l = [local((x0, y0)), local((x1, y1))]
        ix0, ix1 = max(0.0, min(l[0][0], l[1][0])), min(r, max(l[0][0], l[1][0]))
        iy0, iy1 = max(0.0, min(l[0][1], l[1][1])), min(r, max(l[0][1], l[1][1]))
        if ix0 <= ix1 and iy0 <= iy1 and ix1 * ix1 + iy1 * iy1 > r * r + 1e-9:
            return True
    return False

def platform_safe_radius(p, all_seg, all_rect, area_loss_max):
    x, y, w, h = p['geo']
    pord = p['shape'].get('order', 10 ** 9)
    seg_geo = [g for g, o in all_seg]
    rect_geo_all = [g for g, o in all_rect]
    seg_under = [g for g, o in all_seg if o < pord]
    rect_under = [g for g, o in all_rect if o < pord]
    short = min(w, h)
    r_nom = max(PLATFORM_R_MIN, min(PLATFORM_R_MAX, PLATFORM_R_RATIO * short))
    r_area = math.sqrt(area_loss_max * w * h / (4 - math.pi))
    r_cand = min(r_nom, r_area)
    prect = (x, y, x + w, y + h)
    gaps = [seg_rect_dist(a, b, prect) for a, b in seg_geo]
    gaps += [rect_rect_dist(prect, r_) for r_ in rect_geo_all]
    min_gap = min(gaps) if gaps else float('inf')
    if r_cand < PLATFORM_R_MIN - 1e-9:
        return None, min_gap, ('area_conflict' if r_area < r_nom else 'below_min')
    r = r_cand
    while r >= PLATFORM_R_MIN - 1e-9:
        if not any(corner_collision(cx, cy, sx, sy, r, seg_under, rect_under)
                   for (cx, cy, sx, sy) in
                   ((x, y, 1, 1), (x+w, y, -1, 1), (x, y+h, 1, -1), (x+w, y+h, -1, -1))):
            return r, min_gap, None
        r -= COLLISION_STEP
    return None, min_gap, 'gap_conflict'

# ------------------------------ fillet ------------------------------
def fillet_params(P, V, Q, r, avail_before, avail_after):
    """返回 (t_eff, r_eff, p1, p2, sweep) 或 None（无拐点/不可行）。"""
    v1 = (V[0]-P[0], V[1]-P[1]); v2 = (Q[0]-V[0], Q[1]-V[1])
    l1, l2 = math.hypot(*v1), math.hypot(*v2)
    if l1 < 1e-9 or l2 < 1e-9:
        return None
    v1 = (v1[0]/l1, v1[1]/l1); v2 = (v2[0]/l2, v2[1]/l2)
    cross = v1[0]*v2[1] - v1[1]*v2[0]
    dot = v1[0]*v2[0] + v1[1]*v2[1]
    if abs(cross) < 1e-9:
        return None
    denom = max(1 - dot, 1e-9)          # 内角 φ: tan(φ/2)=|cross|/(1-dot)
    t = r * denom / abs(cross)
    t_max = 0.45 * min(avail_before, avail_after)
    if t <= 1e-6 or t_max <= 1e-6:
        return None
    t_eff = min(t, t_max)
    r_eff = t_eff * abs(cross) / denom
    p1 = (V[0] - v1[0]*t_eff, V[1] - v1[1]*t_eff)
    p2 = (V[0] + v2[0]*t_eff, V[1] + v2[1]*t_eff)
    return t_eff, r_eff, p1, p2, (1 if cross > 0 else 0)

def fillet_subpath(pts, r):
    """折线点列 → (新 d, fillet 数, 每顶点切距)。"""
    n = len(pts)
    if n < 3:
        return None, 0, {}
    seg_len = [math.hypot(pts[i+1][0]-pts[i][0], pts[i+1][1]-pts[i][1]) for i in range(n-1)]
    cuts = {}
    for k in range(1, n-1):
        avail_b = seg_len[k-1] - cuts.get(k-1, 0.0)
        avail_a = seg_len[k]
        fp = fillet_params(pts[k-1], pts[k], pts[k+1], r, avail_b, avail_a)
        if fp:
            cuts[k] = fp[0]
    if not cuts:
        return None, 0, {}
    d = [f"M {fmt(pts[0][0])} {fmt(pts[0][1])}"]
    for k in range(1, n-1):
        if k in cuts:
            fp = fillet_params(pts[k-1], pts[k], pts[k+1], r,
                               seg_len[k-1] - cuts.get(k-1, 0.0), seg_len[k])
            _, r_eff, p1, p2, sweep = fp
            d.append(f"L {fmt(p1[0])} {fmt(p1[1])}")
            d.append(f"A {fmt(r_eff)} {fmt(r_eff)} 0 0 {sweep} {fmt(p2[0])} {fmt(p2[1])}")
        else:
            d.append(f"L {fmt(pts[k][0])} {fmt(pts[k][1])}")
    d.append(f"L {fmt(pts[-1][0])} {fmt(pts[-1][1])}")
    return " ".join(d), len(cuts), cuts

# ------------------------------ 变换 ------------------------------
def add_mark(tag_text, extra_attrs=''):
    core = tag_text.rstrip()
    if core.endswith('/>'):
        return core[:-2].rstrip() + extra_attrs + f' {MARK_ATTR}="{VERSION}"/>'
    if core.endswith('>'):
        return core[:-1].rstrip() + extra_attrs + f' {MARK_ATTR}="{VERSION}">'
    return None

def round_rect_tag(tag_text, r):
    return add_mark(tag_text, f' rx="{fmt(r)}" ry="{fmt(r)}"')

def rounded_rect_d(x, y, w, h, r):
    x1, y1 = x + w, y + h
    return (f"M {fmt(x+r)} {fmt(y)} L {fmt(x1-r)} {fmt(y)} "
            f"A {fmt(r)} {fmt(r)} 0 0 1 {fmt(x1)} {fmt(y+r)} L {fmt(x1)} {fmt(y1-r)} "
            f"A {fmt(r)} {fmt(r)} 0 0 1 {fmt(x1-r)} {fmt(y1)} L {fmt(x+r)} {fmt(y1)} "
            f"A {fmt(r)} {fmt(r)} 0 0 1 {fmt(x)} {fmt(y1-r)} L {fmt(x)} {fmt(y+r)} "
            f"A {fmt(r)} {fmt(r)} 0 0 1 {fmt(x+r)} {fmt(y)} Z")

def style_key_of_line(s):
    own = s['own']
    return (norm_color(own.get('stroke') or s['inherited'].get('stroke')),
            own.get('stroke-width') or s['inherited'].get('stroke-width'),
            own.get('stroke-dasharray') or s['inherited'].get('stroke-dasharray') or '',
            s['attrs'].get('class') or '')

def transform_file(raw, area_loss_max=AREA_LOSS_MAX_DEFAULT):
    vb = get_viewbox(raw)
    try:
        css, shapes = build_context(raw)
        roles, ob_seg, ob_rect, platforms, lines_track = classify(shapes, vb)
    except Exception as e:
        return raw, {'status': 'error', 'reason': f'context:{e}'}
    rep = {'status': 'clean', 'platforms': [], 'track_fillets': 0, 'corners_rounded': 0,
           'skipped': [], 'platform_rounded': 0}
    holders = extremum_holders(shapes)
    edits = []      # (span, new_text)
    inserts = []    # (pos, text)

    # ---------- 站台 ----------
    plat_radius = {}  # geo → r（供描边孪生复用）
    for p in platforms:
        s = p['shape']
        if MARK_ATTR in s['attrs'] or s['has_transform']:
            rep['skipped'].append(('platform', 'marked' if MARK_ATTR in s['attrs'] else 'transform'))
            continue
        r, min_gap, reason = platform_safe_radius(p, ob_seg, ob_rect, area_loss_max)
        geo = [round(v, 2) for v in p['geo']]
        if r is not None and p['kind'] == 'path':
            x, y, w, h = p['geo']
            if any(is_sole_extremum(c, holders) for c in
                   ((x, y), (x+w, y), (x, y+h), (x+w, y+h))):
                r, reason = None, 'bbox_extremum'
        if r is None:
            rep['skipped'].append(('platform', reason))
            rep['platforms'].append({'geo': geo, 'r': None, 'reason': reason,
                                     'min_gap': round(min_gap, 3) if math.isfinite(min_gap) else None})
            continue
        tag_text = raw[s['span'][0]:s['span'][1]]
        if p['kind'] == 'rect':
            new_tag = round_rect_tag(tag_text, r)
        else:
            x, y, w, h = p['geo']
            new_d = rounded_rect_d(x, y, w, h, r)
            body = re.sub(r'\bd\s*=\s*"[^"]*"', f'd="{new_d}"', tag_text, count=1)
            new_tag = add_mark(body)
        if new_tag:
            edits.append((s['span'], new_tag))
            plat_radius[tuple(geo)] = r
            rep['platform_rounded'] += 1
            rep['platforms'].append({'geo': geo, 'r': round(r, 3),
                                     'min_gap': round(min_gap, 3) if math.isfinite(min_gap) else None,
                                     'area_loss_pct': round(r*r*(4-math.pi)/(p['geo'][2]*p['geo'][3])*100, 3)})
    for s in shapes:
        if roles.get(id(s)) != 'platform-outline' or MARK_ATTR in s['attrs']:
            continue
        if s['tag'] == 'rect':
            g = rect_geo(s['attrs'])
            if not g:
                continue
            key = tuple(round(v, 2) for v in g)
            if key not in plat_radius:
                continue
            tag_text = raw[s['span'][0]:s['span'][1]]
            new_tag = round_rect_tag(tag_text, plat_radius[key])
            if new_tag:
                edits.append((s['span'], new_tag))
        elif s['tag'] == 'path':
            subs, ok = parse_d_pts(s['attrs'].get('d') or '')
            if not ok or not subs or len(subs) != 1:
                continue
            pts = subs[0]
            if len(pts) >= 2 and abs(pts[0][0]-pts[-1][0]) < 1e-6 and abs(pts[0][1]-pts[-1][1]) < 1e-6:
                pts = pts[:-1]
            if len(pts) != 4:
                continue
            xs = sorted(set(round(p[0], 3) for p in pts))
            ys = sorted(set(round(p[1], 3) for p in pts))
            if len(xs) != 2 or len(ys) != 2:
                continue
            key = (round(xs[0], 2), round(ys[0], 2), round(xs[1]-xs[0], 2), round(ys[1]-ys[0], 2))
            if key not in plat_radius:
                continue
            r = plat_radius[key]
            new_d = rounded_rect_d(xs[0], ys[0], xs[1]-xs[0], ys[1]-ys[0], r)
            tag_text = raw[s['span'][0]:s['span'][1]]
            body = re.sub(r'\bd\s*=\s*"[^"]*"', f'd="{new_d}"', tag_text, count=1)
            new_tag = add_mark(body)
            if new_tag:
                edits.append((s['span'], new_tag))

    # ---------- 线路：度=2 接合点 fillet ----------
    ep_map = {}  # rounded point → [line idx]
    for i, lt in enumerate(lines_track):
        s = lt['shape']
        if MARK_ATTR in s['attrs'] or s['has_transform']:
            continue
        for pt in (lt['a'], lt['b']):
            key = (round(pt[0], 2), round(pt[1], 2))
            ep_map.setdefault(key, []).append(i)
    # 所有 line 端点（含已标记的）用于度判定：标记过的端点视为不可再动
    all_ep = {}
    for i, lt in enumerate(lines_track):
        for pt in (lt['a'], lt['b']):
            key = (round(pt[0], 2), round(pt[1], 2))
            all_ep.setdefault(key, []).append(i)

    # 逐接合点处理（度=2、同样式、非共线）：阶段1 收集 fillet 计划
    line_new_endpoints = {}  # line idx → {'a': pt, 'b': pt}（阶段3 写回）
    junc_stats = {'eligible': 0, 'filleted': 0, 'deg_ge3': 0, 'style_mismatch': 0,
                  'collinear': 0, 'too_short': 0, 'bbox_extremum': 0}
    plan = []
    for key, idxs in sorted(ep_map.items()):
        if len(idxs) != 2:
            continue
        i, j = idxs
        if len(all_ep.get(key, [])) != 2:
            junc_stats['deg_ge3'] += 1
            continue
        si, sj = lines_track[i]['shape'], lines_track[j]['shape']
        if style_key_of_line(si) != style_key_of_line(sj):
            junc_stats['style_mismatch'] += 1
            continue
        V = (key[0], key[1])
        # 取两条线在 V 之外的另一端
        def other(lt, vkey):
            a_k = (round(lt['a'][0], 2), round(lt['a'][1], 2))
            return lt['b'] if a_k == vkey else lt['a']
        P = other(lines_track[i], key)
        Q = other(lines_track[j], key)
        # 接合点附近不得有其他几何（避免交叉处误圆）
        near = False
        for (a, b), _o in ob_seg:
            if seg_dist_pt_seg(V, a, b) < JUNC_EPS and \
               not ((abs(a[0]-V[0]) < JUNC_EPS and abs(a[1]-V[1]) < JUNC_EPS) or
                    (abs(b[0]-V[0]) < JUNC_EPS and abs(b[1]-V[1]) < JUNC_EPS)):
                near = True
                break
        if not near:
            for rr, _o in ob_rect:
                if rr[0]-JUNC_EPS <= V[0] <= rr[2]+JUNC_EPS and rr[1]-JUNC_EPS <= V[1] <= rr[3]+JUNC_EPS:
                    # 排除自身两条线的包围盒
                    continue_check = False
                    for lt in (lines_track[i], lines_track[j]):
                        bb = (min(lt['a'][0], lt['b'][0])-0.01, min(lt['a'][1], lt['b'][1])-0.01,
                              max(lt['a'][0], lt['b'][0])+0.01, max(lt['a'][1], lt['b'][1])+0.01)
                        if abs(rr[0]-bb[0]) < 0.02 and abs(rr[1]-bb[1]) < 0.02 and \
                           abs(rr[2]-bb[2]) < 0.02 and abs(rr[3]-bb[3]) < 0.02:
                            continue_check = True
                            break
                    if not continue_check:
                        near = True
                        break
        if near:
            junc_stats['deg_ge3'] += 1
            continue
        sw = resolved_sw(si)
        if not sw:
            junc_stats['style_mismatch'] += 1
            continue
        r = TRACK_FILLET_K * sw
        l1 = math.hypot(V[0]-P[0], V[1]-P[1])
        l2 = math.hypot(Q[0]-V[0], Q[1]-V[1])
        fp = fillet_params(P, V, Q, r, l1, l2)
        junc_stats['eligible'] += 1
        if not fp:
            v1 = ((V[0]-P[0])/max(l1,1e-9), (V[1]-P[1])/max(l1,1e-9))
            v2 = ((Q[0]-V[0])/max(l2,1e-9), (Q[1]-V[1])/max(l2,1e-9))
            if abs(v1[0]*v2[1]-v1[1]*v2[0]) < 1e-9:
                junc_stats['collinear'] += 1
            else:
                junc_stats['too_short'] += 1
            continue
        plan.append({'key': key, 'key3': (round(V[0], 3), round(V[1], 3)),
                     'i': i, 'j': j, 'fp': fp, 'si': si})

    # 阶段2：bbox 极值过滤——某全局极值坐标的去重持有者全部将被切掉时，撤该接合点
    gpts = geometry_points(shapes)
    dpts = sorted(set((round(p[0], 3), round(p[1], 3)) for p in gpts))
    extr = []
    for axis in (0, 1):
        vals = [p[axis] for p in dpts]
        for ev in (min(vals), max(vals)):
            extr.append((axis, ev, [p for p in dpts if p[axis] == ev]))
    while True:
        trim_set = set(pl['key3'] for pl in plan)
        victim = None
        for axis, ev, holders in extr:
            if holders and all(h in trim_set for h in holders):
                victim = holders[0]
                break
        if victim is None:
            break
        plan = [pl for pl in plan if pl['key3'] != victim]
        junc_stats['bbox_extremum'] += 1

    # 阶段3：写回切点与圆弧
    for pl in plan:
        key, i, j, fp, si = pl['key'], pl['i'], pl['j'], pl['fp'], pl['si']
        t_eff, r_eff, p1, p2, sweep = fp
        def trim(lt_idx, p_new):
            lt = lines_track[lt_idx]
            a_k = (round(lt['a'][0], 2), round(lt['a'][1], 2))
            ne = line_new_endpoints.setdefault(lt_idx, {'a': lt['a'], 'b': lt['b']})
            if a_k == key:
                ne['a'] = p_new
            else:
                ne['b'] = p_new
        trim(i, p1)
        trim(j, p2)
        # 插入圆弧 path（沿用同样式）
        cls = si['attrs'].get('class')
        style_attr = si['attrs'].get('style')
        attrs_out = []
        if cls:
            attrs_out.append(f'class="{cls}"')
        if style_attr:
            attrs_out.append(f'style="{style_attr}"')
        if not cls and not style_attr:
            stroke = si['own'].get('stroke') or si['inherited'].get('stroke') or '#000000'
            swv = si['own'].get('stroke-width') or si['inherited'].get('stroke-width') or '1'
            attrs_out.append(f'fill="none" stroke="{stroke}" stroke-width="{swv}"')
        arc_d = f"M {fmt(p1[0])} {fmt(p1[1])} A {fmt(r_eff)} {fmt(r_eff)} 0 0 {sweep} {fmt(p2[0])} {fmt(p2[1])}"
        span_end = max(lines_track[i]['shape']['span'][1], lines_track[j]['shape']['span'][1])
        inserts.append((span_end, '\n<' + 'path ' + ' '.join(attrs_out) +
                        f' d="{arc_d}" {MARK_ATTR}="{VERSION}"/>'))
        junc_stats['filleted'] += 1
        rep['corners_rounded'] += 1

    # 写回被修剪的 line 端点 + 标记
    for idx, ne in line_new_endpoints.items():
        s = lines_track[idx]['shape']
        tag_text = raw[s['span'][0]:s['span'][1]]
        def sub_attr(txt, name, val):
            pat = rf'\b{name}\s*=\s*"[^"]*"'
            if re.search(pat, txt):
                return re.sub(pat, f'{name}="{fmt(val)}"', txt, count=1)
            return txt[:-2].rstrip() + f' {name}="{fmt(val)}"/>' if txt.endswith('/>') else txt
        tag_text = sub_attr(tag_text, 'x1', ne['a'][0])
        tag_text = sub_attr(tag_text, 'y1', ne['a'][1])
        tag_text = sub_attr(tag_text, 'x2', ne['b'][0])
        tag_text = sub_attr(tag_text, 'y2', ne['b'][1])
        tag_text = add_mark(tag_text)
        edits.append((s['span'], tag_text))
        rep['track_fillets'] += 1

    # ---------- 描边 path/polyline 内部拐点（仓库罕见，兜底支持） ----------
    for s in shapes:
        if roles.get(id(s)) != 'track' or s['tag'] not in ('path', 'polyline'):
            continue
        if MARK_ATTR in s['attrs'] or s['has_transform']:
            continue
        if s['attrs'].get('clip-path') or s['own'].get('clip-path'):
            continue
        sw = resolved_sw(s)
        if not sw:
            continue
        r = TRACK_FILLET_K * sw
        if s['tag'] == 'path':
            subs, ok = parse_d_pts(s['attrs'].get('d') or '')
            if not ok or not subs:
                continue
            new_subs, total, changed = [], 0, False
            for sub in subs:
                closed = len(sub) >= 2 and abs(sub[0][0]-sub[-1][0]) < 1e-9 and abs(sub[0][1]-sub[-1][1]) < 1e-9
                core = sub[:-1] if closed else sub
                frag, cnt, _ = fillet_subpath(core if closed else sub, r)
                if frag and cnt:
                    if closed:
                        frag += ' Z'
                    new_subs.append(frag)
                    total += cnt
                    changed = True
                else:
                    dd = f"M {fmt(sub[0][0])} {fmt(sub[0][1])}" + \
                         ''.join(f" L {fmt(q[0])} {fmt(q[1])}" for q in sub[1:])
                    if closed:
                        dd += ' Z'
                    new_subs.append(dd)
            if not changed:
                continue
            tag_text = raw[s['span'][0]:s['span'][1]]
            body = re.sub(r'\bd\s*=\s*"[^"]*"', f'd="{" ".join(new_subs)}"', tag_text, count=1)
            edits.append((s['span'], add_mark(body)))
            rep['corners_rounded'] += total
        else:
            nums = [float(v) for v in NUM_RE.findall(s['attrs'].get('points') or '')]
            if len(nums) < 6:
                continue
            pts = list(zip(nums[0::2], nums[1::2]))
            frag, cnt, _ = fillet_subpath(pts, r)
            if not frag:
                continue
            attrs = {k: v for k, v in s['attrs'].items() if k != 'points'}
            rest = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
            sc = '/' if s['selfc'] else ''
            edits.append((s['span'], f'<path {rest} d="{frag}" {MARK_ATTR}="{VERSION}"{sc}>'.replace('  ', ' ')))
            rep['corners_rounded'] += cnt

    rep['junc_stats'] = junc_stats
    if not edits and not inserts:
        if rep['skipped']:
            rep['status'] = 'skipped_geometry'
        return raw, rep

    edits.sort(key=lambda e: e[0][0])
    # 校验无重叠 edit
    for a, b in zip(edits, edits[1:]):
        if a[0][1] > b[0][0]:
            return raw, {'status': 'error', 'reason': 'overlapping_edits'}
    out, prev = [], 0
    ins_sorted = sorted(inserts, key=lambda x: x[0])
    ei = ii = 0
    cursor = 0
    events = [((a, b), t, 'edit') for (a, b), t in edits] + \
             [((p, p), t, 'insert') for p, t in ins_sorted]
    events.sort(key=lambda e: (e[0][0], 0 if e[2] == 'edit' else 1))
    for (a, b), txt, kind in events:
        out.append(raw[cursor:a])
        out.append(txt)
        cursor = b if kind == 'edit' else a
    out.append(raw[cursor:])
    new_raw = ''.join(out)
    rep['status'] = 'changed'
    rep['edits'] = len(edits) + len(inserts)
    return new_raw, rep

# ------------------------------ 校验 ------------------------------
def geometry_points(shapes):
    """全部可见几何顶点（与 drawing_bbox 同口径），用于极值统计。"""
    pts = []
    for s in shapes:
        if s['in_defs'] or s['tag'] in ('text', 'tspan'):
            continue
        tag, attrs = s['tag'], s['attrs']
        if tag == 'line':
            try:
                pts.append((float(attrs.get('x1', 0)), float(attrs.get('y1', 0))))
                pts.append((float(attrs.get('x2', 0)), float(attrs.get('y2', 0))))
            except ValueError:
                pass
        elif tag == 'rect':
            g = rect_geo(attrs)
            if g:
                x, y, w, h = g
                pts += [(x, y), (x + w, y), (x, y + h), (x + w, y + h)]
        elif tag == 'path':
            subs, ok = parse_d_pts(attrs.get('d') or '')
            if ok and subs:
                for sub in subs:
                    pts += sub
        elif tag == 'polyline' and attrs.get('points'):
            nums = [float(v) for v in NUM_RE.findall(attrs['points'])]
            pts += list(zip(nums[0::2], nums[1::2]))
    return pts

def extremum_holders(shapes):
    """返回 {(axis, rounded_value): count}，仅统计全局极值坐标的持有者数量。"""
    pts = geometry_points(shapes)
    if not pts:
        return {}
    xs = [round(p[0], 3) for p in pts]
    ys = [round(p[1], 3) for p in pts]
    holders = {}
    for axis, vals in (('x', xs), ('y', ys)):
        lo, hi = min(vals), max(vals)
        holders[(axis, lo)] = vals.count(lo)
        holders[(axis, hi)] = vals.count(hi)
    return holders

def is_sole_extremum(v, holders):
    vx, vy = round(v[0], 3), round(v[1], 3)
    for axis, val in (('x', vx), ('y', vy)):
        for (a, ev), cnt in holders.items():
            if a == axis and abs(ev - val) < 1e-9 and cnt == 1:
                return True
    return False

def drawing_bbox(raw):
    """全部可见几何的 bbox（line/rect/path 顶点），用于变换前后对比。"""
    xs, ys = [], []
    try:
        css, shapes = build_context(raw)
    except Exception:
        return None
    for s in shapes:
        if s['in_defs'] or s['tag'] in ('text', 'tspan'):
            continue
        tag, attrs = s['tag'], s['attrs']
        if tag == 'line':
            try:
                xs += [float(attrs.get('x1', 0)), float(attrs.get('x2', 0))]
                ys += [float(attrs.get('y1', 0)), float(attrs.get('y2', 0))]
            except ValueError:
                pass
        elif tag == 'rect':
            g = rect_geo(attrs)
            if g:
                x, y, w, h = g
                xs += [x, x + w]
                ys += [y, y + h]
        elif tag == 'path':
            subs, ok = parse_d_pts(attrs.get('d') or '')
            if ok and subs:
                for sub in subs:
                    xs += [p[0] for p in sub]
                    ys += [p[1] for p in sub]
        elif tag == 'polyline' and attrs.get('points'):
            nums = [float(v) for v in NUM_RE.findall(attrs['points'])]
            xs += nums[0::2]
            ys += nums[1::2]
    if not xs:
        return None
    return min(xs), min(ys), max(xs), max(ys)

def validate(raw_orig, raw_new):
    probs = []
    try:
        ET.fromstring(raw_new)
    except ET.ParseError as e:
        probs.append(f'xml_parse:{e}')
    if get_viewbox(raw_orig) != get_viewbox(raw_new):
        probs.append('viewBox_changed')
    if not re.search(r'<svg\b[^>]*>', raw_new):
        probs.append('svg_tag_missing')
    if not raw_new.rstrip().endswith('</svg>'):
        probs.append('not_closed')
    for m in re.finditer(r'\bd="([^"]*)"', raw_new):
        if not re.fullmatch(r'[MLHVZACSQTEmlhvzacsqte\d\s.,+\-]+', m.group(1)):
            probs.append('bad_d_chars')
            break
    b_o, b_n = drawing_bbox(raw_orig), drawing_bbox(raw_new)
    if b_o and b_n:
        w_o, h_o = max(b_o[2]-b_o[0], 1e-6), max(b_o[3]-b_o[1], 1e-6)
        for i, name in enumerate(('x0', 'y0', 'x1', 'y1')):
            ref = w_o if i % 2 == 0 else h_o
            if abs(b_n[i]-b_o[i]) / ref > 0.005:
                probs.append(f'bbox_shift_{name}:{round(b_n[i]-b_o[i],4)}')
    return (len(probs) == 0), probs

# ------------------------------ 子命令 ------------------------------
def iter_svg_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', '__pycache__')]
        for f in sorted(filenames):
            if f.endswith('.svg'):
                yield os.path.join(dirpath, f)

def cmd_scan(args):
    root = args.root
    total = corrupted = 0
    corrupt_list = []
    tag_role_counts = {}
    style_role_table = {}
    candidates = {'multi_platform_branch': [], 'adjacent_gap_lt2': [], 'path_platform': []}
    plat_stats = {'total': 0, 'roundable': 0, 'area_conflict': 0, 'gap_conflict': 0, 'other_skip': 0}
    track_stats = {'lines': 0, 'paths_stroked': 0, 'flat_paths': 0, 'flat_rects': 0,
                   'junc_deg2_samestyle': 0}
    ep_global = {}
    for fp in iter_svg_files(root):
        total += 1
        rel = os.path.relpath(fp, root)
        raw = open(fp, 'rb').read().decode('utf-8', errors='replace')
        closed = raw.rstrip().endswith('</svg>')
        parse_ok, err = True, None
        try:
            ET.fromstring(raw)
        except ET.ParseError as e:
            parse_ok, err = False, str(e)
        if not closed or not parse_ok:
            corrupted += 1
            corrupt_list.append({'path': rel, 'bytes': len(raw.encode('utf-8')),
                                 'closed': closed, 'parse_ok': parse_ok, 'reason': err})
            continue
        vb = get_viewbox(raw)
        try:
            css, shapes = build_context(raw)
            roles, ob_seg, ob_rect, platforms, lines_track = classify(shapes, vb)
        except Exception as e:
            corrupted += 1
            corrupt_list.append({'path': rel, 'bytes': len(raw.encode('utf-8')),
                                 'closed': True, 'parse_ok': True, 'reason': f'classify:{e}'})
            continue
        n_plat = sum(1 for s in shapes if roles.get(id(s)) == 'platform')
        n_track = sum(1 for s in shapes if roles.get(id(s)) in ('track', 'track-flat'))
        for s in shapes:
            role = roles.get(id(s), 'other')
            tag_role_counts[(s['tag'], role)] = tag_role_counts.get((s['tag'], role), 0) + 1
            own = s['own']
            sig = []
            if own.get('fill'):
                sig.append('fill:' + (norm_color(own.get('fill')) or ''))
            if own.get('stroke'):
                sig.append('stroke:' + (norm_color(own.get('stroke')) or '') + '/sw=' + str(own.get('stroke-width', '?')))
            key = (role, s['tag'], ';'.join(sig) or '(default/inherit)')
            style_role_table[key] = style_role_table.get(key, 0) + 1
        track_stats['lines'] += sum(1 for s in shapes if s['tag'] == 'line' and roles.get(id(s)) == 'track')
        track_stats['paths_stroked'] += sum(1 for s in shapes if s['tag'] == 'path' and roles.get(id(s)) == 'track')
        track_stats['flat_paths'] += sum(1 for s in shapes if roles.get(id(s)) == 'track-flat' and s['tag'] == 'path')
        track_stats['flat_rects'] += sum(1 for s in shapes if roles.get(id(s)) == 'track-flat' and s['tag'] == 'rect')
        # 度=2 同样式接合点
        ep = {}
        for lt in lines_track:
            s = lt['shape']
            if MARK_ATTR in s['attrs'] or s['has_transform']:
                continue
            for pt in (lt['a'], lt['b']):
                k = (round(pt[0], 2), round(pt[1], 2))
                ep.setdefault(k, []).append(style_key_of_line(s))
        for k, styles in ep.items():
            if len(styles) == 2 and styles[0] == styles[1]:
                track_stats['junc_deg2_samestyle'] += 1
        has_path_platform = any(p['kind'] == 'path' for p in platforms)
        min_gaps = []
        for p in platforms:
            plat_stats['total'] += 1
            r, mg, reason = platform_safe_radius(p, ob_seg, ob_rect, args.area_loss_max)
            min_gaps.append(mg)
            if r is None:
                if reason == 'gap_conflict':
                    plat_stats['gap_conflict'] += 1
                elif reason == 'area_conflict':
                    plat_stats['area_conflict'] += 1
                else:
                    plat_stats['other_skip'] += 1
            else:
                plat_stats['roundable'] += 1
        if has_path_platform:
            candidates['path_platform'].append(rel)
        if n_plat >= 2 and track_stats['junc_deg2_samestyle'] >= 0 and \
           sum(1 for k, st in ep.items() if len(st) >= 3) >= 0 and n_plat >= 2 and \
           any(len(st) == 2 and st[0] == st[1] for st in ep.values()):
            candidates['multi_platform_branch'].append(rel)
        if any(math.isfinite(g) and g < 2 for g in min_gaps):
            candidates['adjacent_gap_lt2'].append(rel)
    result = {
        'area_loss_max_used': args.area_loss_max,
        'total_svg': total,
        'corrupted': corrupted,
        'corrupt_list': corrupt_list,
        'tag_role_counts': [{'tag': k[0], 'role': k[1], 'n': v}
                            for k, v in sorted(tag_role_counts.items(), key=lambda x: -x[1])],
        'style_role_top': [{'role': k[0], 'tag': k[1], 'style': k[2], 'n': v}
                           for k, v in sorted(style_role_table.items(), key=lambda x: -x[1])[:50]],
        'platform_stats': plat_stats,
        'track_stats': track_stats,
        'candidates': {k: v[:15] for k, v in candidates.items()},
    }
    out = json.dumps(result, ensure_ascii=False, indent=1)
    if args.json_out:
        open(args.json_out, 'w').write(out)
    print(out)

def cmd_apply(args):
    root = args.root
    summary = {'changed': [], 'clean': 0, 'skipped_geometry': [], 'error': [], 'invalid': []}
    for fp in iter_svg_files(root):
        rel = os.path.relpath(fp, root)
        raw = open(fp, encoding='utf-8', newline='').read()
        if not raw.rstrip().endswith('</svg>'):
            summary['invalid'].append({'path': rel, 'reason': 'not_closed'})
            continue
        try:
            ET.fromstring(raw)
        except ET.ParseError:
            summary['invalid'].append({'path': rel, 'reason': 'xml_parse'})
            continue
        new_raw, rep = transform_file(raw, args.area_loss_max)
        rep['path'] = rel
        if rep['status'] == 'error':
            summary['error'].append(rep)
            continue
        if rep['status'] == 'changed':
            ok, probs = validate(raw, new_raw)
            if not ok:
                summary['invalid'].append({'path': rel, 'reason': ';'.join(probs)})
                continue
            again, _ = transform_file(new_raw, args.area_loss_max)
            if again != new_raw:
                summary['invalid'].append({'path': rel, 'reason': 'not_idempotent'})
                continue
            open(fp, 'w', encoding='utf-8', newline='').write(new_raw)
            summary['changed'].append(rep)
        elif rep['status'] == 'skipped_geometry':
            summary['skipped_geometry'].append(rep)
        else:
            summary['clean'] += 1
    print(json.dumps(summary, ensure_ascii=False, indent=1))

def cmd_verify(args):
    root = args.root
    files = list(iter_svg_files(root))
    if args.sample:
        random.seed(args.seed)
        files = random.sample(files, min(args.sample, len(files)))
    bad = []
    for fp in files:
        raw = open(fp, encoding='utf-8', newline='').read()
        ok, probs = validate(raw, raw)
        if not ok:
            bad.append({'path': os.path.relpath(fp, root), 'problems': probs})
    print(json.dumps({'checked': len(files), 'bad': bad}, ensure_ascii=False, indent=1))

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('scan')
    p.add_argument('--root', default='.')
    p.add_argument('--json-out')
    p.add_argument('--area-loss-max', type=float, default=AREA_LOSS_MAX_DEFAULT)
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser('apply')
    p.add_argument('--root', default='.')
    p.add_argument('--area-loss-max', type=float, default=AREA_LOSS_MAX_DEFAULT)
    p.set_defaults(fn=cmd_apply)
    p = sub.add_parser('verify')
    p.add_argument('--root', default='.')
    p.add_argument('--sample', type=int, default=0)
    p.add_argument('--seed', type=int, default=42)
    p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    args.fn(args)

if __name__ == '__main__':
    main()

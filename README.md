# 配線略図.net 配线图 SVG 存档

来源：https://www.haisenryakuzu.net/
许可：CC BY 4.0（需注明出处）

## 统计
- SVG 矢量配线图：**798 个**
- 缩略图（JPG/WebP）：12 个
- 总大小：约 16 MB
- 覆盖线路：203 条

## 目录结构
```
downloads/documents/
├── jr/
│   ├── east/       JR东日本（42线路, 329 SVG）
│   ├── west/       JR西日本（1线路, 17 SVG）
│   ├── tokai/      JR东海（2线路, 18 SVG）
│   ├── hokkaido/   JR北海道（1线路, 2 SVG）
│   └── shinkansen/ 新干线（2线路, 19 SVG）
├── pr/
│   ├── keisei/     京成电铁（5线路）
│   ├── tobu/       东武铁道（6线路）
│   ├── seibu/      西武铁道（11线路）
│   ├── keio/       京王电铁（6线路）
│   ├── odakyu/     小田急电铁（3线路）
│   ├── tokyu/      东急电铁（8线路）
│   ├── keikyu/     京滨急行（5线路）
│   ├── hankyu/     阪急电铁（10线路）
│   ├── hanshin/    阪神电铁（4线路）
│   ├── keihan/     京阪电铁（5线路）
│   ├── nankai/     南海电铁（8线路）
│   ├── kinki/      近畿日本铁道（20线路）
│   └── nagoya/     名古屋铁道（17线路）
└── metro/
    ├── tokyometro/ 东京地下铁（7线路）
    └── tokyotoei/  都电荒川线（1线路）
```

## 说明
- 每条线路的配线图被切分为多个 SVG 分块（命名规则 `XX0_YY.svg`，YY 是分块序号）
- SVG 为 Illustrator 导出的矢量图，可直接在浏览器/设计软件中打开
- 部分线路因服务器超时未完整下载（JR 西日本、JR 四国、JR 九州、JR 货物等覆盖较少）
- 详见 `线路索引.csv`

## 工具链说明
- 本工具链（tools/round_corners.py）会统一换行为 LF（以 newline='' 读写）；源文件原本为 CRLF 的会被归一为 LF（历史上 603 个文件因此整文件换行变化），几何/文字/样式内容不变。

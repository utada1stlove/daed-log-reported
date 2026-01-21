下面这个版本在你上一版基础上新增：

- `--csv`：生成 `connections.csv`

- `--csv-only`：只输出 CSV（不生成 md/html）

默认仍会生成 `report.md`（你可以用 `--no-md` 关闭）

HTML 默认不开启卡顿问题时，你可以直接用 `--no-html`（推荐）

1) 生成“Markdown + CSV”，不生成 HTML

```
python3 daed-log-report.py daed.log --no-html --csv
```

输出：

- `report.md`（总结 + 统计）

- `connections.csv`（表格可筛选）

2) 只要 CSV（最轻）
python3 daed-log-report.py daed.log --csv-only

CSV 在表格软件里怎么用得最舒服

打开 connections.csv 后，你最常用的几个筛选列通常是：

- `outbound`：筛出 direct / proxy / fast / tiktok

- `policy`：筛出 `!= fixed` 的动态策略

- `sniffed` 或 `target_domain`：按域名族过滤

- `dialer`：检查是否走了预期线路

- `network`：快速定位 IPv6（tcp6）

- 进一步减少体积的建议（可选）

- 如果日志特别大，CSV 也会大，你可以直接压缩：

```
gzip -9 connections.csv
```

Windows 也能解压，传输与归档都更方便。
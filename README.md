# daed-log
Automatic analysis of daed log files

---

# daed-log-report

一个用于 **daed 网络日志审计与可视化分析** 的轻量级工具。  
它可以将 daed 的原始日志自动解析为 **可读性极高的 Markdown / HTML 报告**，用于：

- 网络行为审计
- 分流策略验证
- 代理 / 直连 / 动态策略分析
- 长期归档与排查问题

无需理解 daed 内部实现，也不需要 Python 基础。

---

## ✨ 功能特性

- ✅ **自动解析 daed 日志**
  - 支持 `key=value` / `key="value"` 形式
  - 支持 IPv4 / IPv6
  - 支持带引号的 dialer 名称（如 `dialer="日本家宽"`）

- ✅ **智能流量分类**
  - 直连（direct）
  - 代理（proxy）
  - 应用专用出站（如 tiktok）
  - 动态策略出站（如 `policy=min_avg10`）

- ✅ **应用 / 域名聚合分析**
  - 自动识别 TikTok / Google / GitHub / JD / Microsoft / Twitch 等
  - 同一应用多出站策略会给出提示

- ✅ **时区感知（非常重要）**
  - 支持日志时间时区（默认 UTC）
  - 支持报告显示时区（默认北京时间 Asia/Shanghai）
  - 报告中明确标注时区信息，避免审计歧义

- ✅ **生成正式审计报告**
  - `report.md`：适合归档、发帖、Git 管理
  - `report.html`：直接浏览器打开查看
  - HTML 为单文件，无外部依赖

- ✅ **自动过滤噪音**
  - daed 内部 `warning` / GraphQL 类日志不会混入流量统计
  - 单独列在 Warnings 区域

---

## 📦 输出示例

生成的报告包含：

- Overview（时间范围、时区、设备信息）
- Traffic Summary（出站 / 策略 / 网络类型分布）
- Application & Domain Analysis（应用级审计）
- Connection Details（逐条连接，人类可读）
- Warnings & Internal Messages
- Automated Conclusions（自动总结）

适合直接作为 **网络审计报告** 使用。

---

## 🛠️ 使用方法

### 1️⃣ 基本用法（最常用）

```bash
python3 daed-log-report.py daed.log
```

生成文件：

* `report.md`
* `report.html`

---

### 2️⃣ 从标准输入读取（如 OpenWrt / logread）

```bash
logread | python3 daed-log-report.py
```

---

### 3️⃣ 指定时区（推荐）

daed 日志时间通常是 **UTC**，而你希望报告显示为北京时间：

```bash
python3 daed-log-report.py daed.log \
  --log-tz UTC \
  --display-tz Asia/Shanghai
```

报告中会明确标注：

```text
日志时区：UTC
显示时区：Asia/Shanghai
```

---

### 4️⃣ 常用参数一览

| 参数             | 说明                          |
| -------------- | --------------------------- |
| `--log-tz`     | 日志中 `time=` 字段的时区（默认 `UTC`） |
| `--display-tz` | 报告显示时区（默认 `Asia/Shanghai`）  |
| `-o, --outdir` | 输出目录                        |
| `--no-html`    | 不生成 HTML                    |
| `--no-md`      | 不生成 Markdown                |
| `--top N`      | Top 域名统计数量（默认 15）           |
| `--title`      | 报告标题                        |

---

## 🧠 适合哪些场景？

* 验证 **daed / sing-box 分流规则是否生效**
* 排查：

  * 为什么某些流量走了代理 / 没走代理
  * 为什么同一应用存在多条出站
* 审计：

  * 家庭 / 路由器 / 软路由 网络行为
  * IPv6 / 动态策略流量
* 归档：

  * 每天 / 每次变更前后生成对比报告

---

## ⚠️ 注意事项

* daed 日志中的时间 **不包含年份**
  当前版本默认使用“当前年份”，跨年日志如需精确处理可后续增强。
* 域名识别基于 sniffed / 目标地址
  无 SNI / IP 直连流量会被标记为 `Unknown`。
* 本工具是 **分析工具**，不会修改任何网络行为。

---

## 🚀 未来可能的扩展

* 自动生成规则优化建议
* 按天 / 按设备拆分报告
* systemd / cron 定时生成
* 输出 CSV / JSON
* Web Dashboard


---

## 🙏 致谢

感谢 daed / sing-box 项目提供稳定、可观测的网络基础设施。

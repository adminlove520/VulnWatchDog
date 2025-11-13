# VulnWatchdog

VulnWatchdog 是一个强大的自动化漏洞监控与分析平台，集成了多源数据采集、智能分析和实时通知功能，帮助安全团队高效跟踪和管理最新漏洞威胁。

## 核心功能

- 🔍 **多源数据采集**：自动监控 GitHub 上的 CVE 相关仓库、CISA KEV 目录和 OSCS 漏洞平台
- 📊 **漏洞情报整合**：统一获取并解析 CVE 漏洞详情、影响范围和技术细节
- 🤖 **智能风险分析**：利用 GPT/Gemini 进行漏洞严重性评估、POC 代码分析和投毒风险检测
- 📝 **多格式报告生成**：支持 Markdown、RSS 订阅和周期性周报，满足不同场景需求
- 🔔 **实时告警通知**：支持飞书、钉钉等多渠道通知，第一时间推送关键漏洞信息
- ⏱️ **自动化任务调度**：基于 GitHub Actions 的定时扫描和报告生成机制

## 部署说明

### GitHub Actions 自动部署

本项目使用 GitHub Actions 实现自动化监控、报告生成和通知推送。相关配置文件位于 `.github/workflows/` 目录。

1. 配置项目 Secrets (Settings -> Secrets and variables -> Actions):

```
# Webhook配置
WEBHOOK_URL: "你的webhook地址"
WEBHOOK_SECRET: "可选的webhook密钥"

# GPT/Gemini配置
GPT_API_KEY: "你的API密钥"
GPT_SERVER_URL: "可选的自定义服务器地址"

# 搜索配置
SEARXNG_URL: "SearXNG搜索服务地址"
SEARXNG_ENABLED: "false"  # 默认关闭SearXNG搜索功能，需要时设为"true"
```

2. 配置环境变量 (使用 `.env` 文件或 GitHub Secrets):

```
# 复制模板创建配置文件
cp .env.temp .env

# 编辑 .env 文件配置必要参数
```

3. 配置功能开关 (config.py):

```python
# 通知相关配置
ENABLE_NOTIFY = True  # 是否启用通知功能
NOTIFY_TYPE = 'feishu'  # 通知类型: feishu, dingtalk

# AI分析相关配置
ENABLE_GPT = True  # 是否启用AI分析功能
GPT_MODEL = 'gemini-2.0-flash'  # 使用的模型名称

# 搜索相关配置
ENABLE_SEARCH = True  # 是否启用漏洞信息搜索
ENABLE_EXTENDED = True  # 是否启用扩展搜索
```

3. **Actions 自动化工作流**

本项目包含多个自动化工作流：
- **monitor.yml**: 每小时执行漏洞监控和分析
- **generate_rss.yml**: 生成漏洞RSS订阅源
- **generate_weekly_report.yml**: 每周生成漏洞统计报告

4. 监控结果处理:
- 分析报告保存至 `data/markdown/` 目录
- 通过配置的 Webhook 推送实时通知
- 自动提交更新到仓库中

## 本地部署说明

1. 克隆仓库
```bash
git clone https://github.com/adminlove520/VulnWatchdog.git
cd VulnWatchdog
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 配置环境变量
```bash
# 复制模板创建配置文件
cp .env.temp .env

# 编辑 .env 文件,配置必要的敏感参数
# 编辑 config.py 文件,配置功能开关
```

4. 运行程序
```bash
# 运行主程序
python main.py

# 生成RSS订阅源
python main.py --rss

# 生成周报
python generate_weekly_report.py
```

## 输出说明

### 分析报告

分析报告以 Markdown 格式输出，包含漏洞摘要、详细信息、风险评估和缓解建议等完整内容。

### 报告存储与访问

- **Markdown 报告**: 保存在 `data/markdown/` 目录,按年份分类存储
- **RSS 订阅源**: 支持通过 RSS 阅读器订阅最新漏洞信息
- **周报统计**: 每周生成包含漏洞趋势分析的综合报告

## 消息通知

消息通知模板请参考[NOTIFY.md](NOTIFY.md)

## 项目结构

```
VulnWatchdog/
├── main.py               # 主程序入口
├── config.py             # 配置管理
├── generate_weekly_report.py  # 周报生成脚本
├── libs/                 # 核心功能模块
│   ├── __init__.py
│   ├── cisa.py           # CISA 数据源集成
│   ├── cisa_oscs_checker.py  # CISA与OSCS数据对比
│   ├── utils.py          # 工具函数集合
│   ├── webhook.py        # 通知发送模块
│   ├── gpt_utils.py      # AI分析工具
│   ├── oscs.py           # OSCS 数据源集成
│   └── rss_generator.py  # RSS生成工具
├── models/
│   └── models.py         # 数据模型定义
├── data/                 # 数据存储目录
│   └── markdown/         # 按年份分类的分析报告
├── template/             # 消息和报告模板
│   ├── feishu.json       # 飞书消息模板
│   ├── dingtalk.json     # 钉钉消息模板
│   ├── custom.json       # 自定义消息模板
│   └── report.md         # 分析报告模板
├── .github/workflows/    # GitHub Actions配置
│   ├── monitor.yml
│   ├── generate_rss.yml
│   └── generate_weekly_report.yml
```

## 功能特性

### 数据源集成
- **GitHub 监控**: 自动跟踪 CVE 相关仓库和 POC 代码
- **CISA KEV**: 整合美国网络安全和基础设施安全局的已知被利用漏洞目录
- **OSCS**: 集成开源安全情报平台的漏洞信息

### 智能分析能力
- **漏洞严重性评级**: 基于 CVSS 评分和上下文信息的综合风险评估
- **POC 代码分析**: 检测代码可用性和潜在风险
- **投毒风险检测**: 识别可能被用于供应链攻击的恶意 POC

### 通知与报告
- **多渠道通知**: 支持飞书、钉钉等企业即时通讯工具
- **RSS 订阅**: 提供标准 RSS 格式的漏洞更新流
- **定期统计报告**: 每周自动生成漏洞趋势分析报告

## 开发与贡献

### 开发环境设置
1. 按照本地部署说明配置环境
2. 建议使用虚拟环境进行开发

### 贡献指南
欢迎提交 Issue 和 Pull Request。在提交 PR 前,请确保:
1. 代码风格符合项目规范
2. 功能测试通过
3. 更新相关文档和注释

## 许可证

MIT License

## 联系方式

如有问题，请提交 Issue

## 致谢
- 感谢 [Poc-Monitor](https://github.com/sari3l/Poc-Monitor) 项目提供的思路
- 感谢 [SearXNG](https://github.com/searxng/searxng) 项目提供的搜索引擎

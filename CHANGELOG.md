# Changelog

## [Unreleased]

## [1.1.0-b] - 2025-11-28
### 新增功能
- 优化钉钉推送内容格式，确保与报告格式一致
- 优化相关文章推送内容【先知社区、FreeBuf、securityvulnerability.io】
- 相关文章改为漏洞复现

### 改进
- 优化markdown格式，修复列表项之间的换行问题
- 提取markdown格式修复逻辑为独立函数，提高代码复用性
- 优化相关文章列表格式，确保每个链接前带有'-'

### 修复
- 修复钉钉推送内容格式与报告不一致的问题
- 修复列表项之间缺少换行的问题
- 解决Git推送失败问题，清理Git历史中的大文件
- 修复相关文章列表格式问题

### 变更
- 将vulns.db和所有数据库文件添加到.gitignore中
- 修改GitHub Actions workflow，排除数据库文件提交
- 默认关闭SearXNG搜索功能，可通过环境变量SEARXNG_ENABLED="true"开启
- 在GitHub Actions workflow中添加SEARXNG_ENABLED环境变量配置

### 安全
- 如果fastfpt返回敏感词问题，则认为该漏洞需跳过


## [1.0.0] - 2024-07-13

### 新增功能
- 多源数据采集系统，集成GitHub、CISA KEV和OSCS漏洞平台
- 智能漏洞分析引擎，使用Gemini 2.0 Flash进行风险评估
- 支持飞书和钉钉的多渠道通知系统
- RSS订阅源生成功能
- 每周自动统计报告生成
- 投毒风险检测机制

### 改进
- 优化配置管理系统，使用.env文件进行环境变量配置
- 重构代码结构，模块化设计提高可维护性
- 增强错误处理和日志记录
- 改进GitHub Actions工作流配置

### 修复
- 修复weekly_report.yml中的语法错误
- 修复generate_weekly_report.py中的三引号闭合问题
- 移除oscs.py中测试代码和不必要的api_key功能
- 清理cisa.py中的测试代码部分

## 历史版本

### v0.9.0 - 2024-06-30
- 初始版本发布
- 基础GitHub仓库监控功能
- 简单的漏洞信息分析
- 基本的通知功能

---

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
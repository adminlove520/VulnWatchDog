# VulnWatchdog 数据源说明

本文档详细说明 VulnWatchdog 项目中使用的所有漏洞数据源，包括数据源的基本信息、API 接口、提供的数据内容以及使用方式。

## 1. NVD (National Vulnerability Database)

### 基本信息
- **名称**：美国国家漏洞数据库
- **所属机构**：美国国家标准与技术研究院 (NIST)
- **URL**：https://nvd.nist.gov/

### API 信息
- **API 版本**：2.0
- **接口 URL**：`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}`
- **请求方法**：GET
- **响应格式**：JSON

### 提供的数据内容
- CVE 详细描述
- 发布日期和最后修改日期
- CVSS 评分和严重性等级
- 影响的软件产品
- 参考链接列表

### 项目中的使用位置
- 在 <mcfile name="gpt_utils.py" path="libs/gpt_utils.py"></mcfile> 中的 `_fetch_from_nvd` 函数
- 在 <mcfile name="utils.py" path="libs/utils.py"></mcfile> 中的 `get_cve_info` 函数

## 2. CISA (Cybersecurity and Infrastructure Security Agency)

### 基本信息
- **名称**：美国网络安全和基础设施安全局
- **所属机构**：美国国土安全部
- **URL**：https://www.cisa.gov/

### API 信息
- **接口 URL**：`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **请求方法**：GET
- **响应格式**：JSON

### 提供的数据内容
- 已知被利用的漏洞列表
- 漏洞概述
- 发现和利用信息
- 与勒索软件相关的情报
- 缓解和修复建议

### 项目中的使用位置
- 在 <mcfile name="gpt_utils.py" path="libs/gpt_utils.py"></mcfile> 中的 `_fetch_from_cisa` 函数
- 在 <mcfile name="utils.py" path="libs/utils.py"></mcfile> 中的 `_check_cisa` 方法
- 在 <mcfile name="cisa.py" path="libs/cisa.py"></mcfile> 中实现了完整的 CISA 数据源处理

## 3. OSCS (Open Source Cyber Security Center)

### 基本信息
- **名称**：开源网络安全中心
- **所属机构**：奇安信集团
- **URL**：https://www.oscs1024.com/

### API 信息
- **接口 URL**：`https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{cve_id}`
- **请求方法**：GET
- **响应格式**：JSON

### 提供的数据内容
- 漏洞标题
- 漏洞描述
- 影响版本
- 危害等级
- 修复建议

### 项目中的使用位置
- 在 <mcfile name="gpt_utils.py" path="libs/gpt_utils.py"></mcfile> 中的 `_fetch_from_oscs` 函数
- 在 <mcfile name="utils.py" path="libs/utils.py"></mcfile> 中的 `_check_oscs` 方法
- 在 <mcfile name="oscs.py" path="libs/oscs.py"></mcfile> 中实现了完整的 OSCS 数据源处理

## 4. GitHub Search API

### 基本信息
- **名称**：GitHub 搜索 API
- **所属机构**：GitHub
- **URL**：https://docs.github.com/en/rest/search

### API 信息
- **接口 URL**：`https://api.github.com/search/repositories?q={query}`
- **请求方法**：GET
- **响应格式**：JSON
- **认证方式**：可选的 GitHub Token (用于提高速率限制)

### 提供的数据内容
- 与特定 CVE 相关的代码仓库
- 漏洞利用代码 (POC)
- 安全研究资料
- 修复补丁

### 项目中的使用位置
- 在 <mcfile name="utils.py" path="libs/utils.py"></mcfile> 中的 `search_github` 和 `_check_github_poc` 函数
- 在 <mcfile name="cisa_oscs_checker.py" path="libs/cisa_oscs_checker.py"></mcfile> 中用于搜索相关仓库

## 5. CVE CIRCL API

### 基本信息
- **名称**：欧洲 CERT 协调中心 CVE API
- **所属机构**：CERT Coordination Center Luxembourg
- **URL**：https://www.circl.lu/services/cve-search/

### API 信息
- **接口 URL**：`https://cve.circl.lu/api/cve/{cve_id}`
- **请求方法**：GET
- **响应格式**：JSON

### 提供的数据内容
- CVE 详细信息
- 影响的软件包
- 参考链接
- 漏洞分类

### 项目中的使用位置
- 在 <mcfile name="utils.py" path="libs/utils.py"></mcfile> 中的 `get_cve_info` 函数中有提及，但当前主要使用 NVD API

## 6. Gemini API

### 基本信息
- **名称**：Google Gemini API
- **所属机构**：Google
- **URL**：https://ai.google.dev/

### API 信息
- **接口 URL**：`https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}`
- **请求方法**：POST
- **响应格式**：JSON
- **认证方式**：需要 Google API 密钥

### 提供的数据内容
- AI 辅助分析的漏洞信息
- 漏洞严重性评估
- 技术细节解释
- 修复建议

### 项目中的使用位置
- 在 <mcfile name="gpt_utils.py" path="libs/gpt_utils.py"></mcfile> 中的 `ask_gpt` 函数
- 用于自动分析漏洞信息和生成报告

## 数据源优先级和集成方式

VulnWatchdog 项目通过以下方式集成和使用这些数据源：

1. **多源数据聚合**：通过 <mcfile name="gpt_utils.py" path="libs/gpt_utils.py"></mcfile> 中的 `get_cve_info` 函数，从多个数据源收集信息并整合

2. **数据验证**：在 <mcfile name="utils.py" path="libs/utils.py"></mcfile> 中的 `CVEChecker` 类实现了 CVE 有效性验证，按优先级依次检查 CISA、OSCS 和 GitHub

3. **补充信息**：对于每个 CVE，系统会尝试从所有可用的数据源获取信息，以提供最全面的漏洞情报

4. **缓存机制**：实现了缓存机制以减少 API 调用，提高性能并避免达到速率限制

## 注意事项

- 部分 API 可能有速率限制，系统实现了错误处理和重试机制
- API 密钥配置在 `config.py` 中，建议根据需要设置相应的 API 密钥
- 数据源可能会更新其 API，必要时需要更新代码以适应这些变化
- 某些数据源可能需要付费或注册才能获取完整功能或更高的访问限制
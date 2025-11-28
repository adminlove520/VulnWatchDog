from datetime import datetime, timezone, timedelta
import json
import time
import traceback
import os
import logging
import sys
from typing import List, Dict, Optional
from config import get_config
from libs.search_engine import search_duckduckgo, search_bing, search_github, get_github_poc, SearchError
from libs.report_generator import write_to_markdown, generate_rss_feed, get_template
from libs.scheduler import start_scheduler, stop_scheduler, get_cve_checker
from libs.cve_checker import CVEChecker
from libs.gpt_utils import ask_gpt, get_cve_info
from libs.gpt_queue import queue_gpt_retry
from libs.webhook import send_webhook
from models.models import get_db, get_db_session, CVE, Repository, func

# 配置日志
logging.basicConfig(
    level=logging.DEBUG if get_config('DEBUG') else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 从配置文件加载功能开关
enable_gpt = get_config('ENABLE_GPT')
enable_notify = get_config('ENABLE_NOTIFY') 
enable_search = get_config('ENABLE_SEARCH')
enable_extended = get_config('ENABLE_EXTENDED')

def build_prompt(cve_info: Dict, search_results: List[Dict], poc_results_str: str) -> str:
    """
    构建发送给GPT的提示文本
    
    Args:
        cve_info: CVE漏洞信息字典
        search_results: 搜索结果列表
        poc_results_str: POC代码内容
        
    Returns:
        str: 格式化的提示文本
    """
    try:
        # 格式化搜索结果
        search_results_str = ""
        for i, result in enumerate(search_results):
            search_results_str += f"[webpage {i} begin] [title] {result.get('title', '')}\n [description] {result.get('content', '')}\n [link] {result.get('url', '')}\n [webpage {i} end]\n"
        
        if search_results_str:
            search_results_str = f"""
            ## 以下内容是基于此漏洞的搜索结果:
                {search_results_str}
            """
        cve_info = json.dumps(cve_info)
        
        # 构建完整提示文本

        prompt = f"""
      请根据以下漏洞信息、搜索结果和漏洞利用代码，生成一份详细的漏洞分析报告，包含有效性分析、投毒风险分析、利用方式、代码分析等内容。请注意以下几点：

    **信息来源：**

    *   **漏洞库信息：**
        ```
        {cve_info}
        ```
    *   **搜索引擎结果：**
        ```
        {search_results_str}
        ```
    *   **漏洞利用代码：**
        ```
        {poc_results_str}
        ```

    **你的角色：** 你是一名专业的网络安全分析师，擅长分析CVE漏洞信息。

    **任务：**

    1.  **CVE有效性：** 分析此CVE是否为真实存在的有效漏洞。请综合考虑CVE编号格式、漏洞描述的完整性、参考链接的存在、漏洞的技术细节等因素。
    2.  **POC有效性：** 判断提供的POC代码是否有效，是否能实际利用此漏洞，并分析其有效性。
    3.  **投毒风险：** 分析POC代码内容,判断此仓库中是否存在作者隐藏的投毒代码,分析结果使用百分比。务必不要把POC验证的后门代码判定为投毒代码。
    4.  **利用方式：** 详细分析并总结漏洞的利用方式，包括攻击步骤、所需条件等。
    5.  **代码分析：** 详细分析POC代码的工作原理、关键组件和执行流程。
    6.  **排序优先级:** 搜索引擎结果 >  漏洞利用代码 > 漏洞库信息
    7.  **输出内容:** 务必使用中文
    8.  **markdown内容:** 务必使用markdown格式，包含以下部分：
        - 漏洞概述
        - 有效性分析
        - 投毒风险分析
        - 利用方式
        - 代码分析
    **输出格式：**  你**必须**严格按照以下 **JSON** 格式输出，**不要包含任何额外的文字、说明或前缀/后缀**。JSON中的**所有键和字符串类型的值必须使用双引号**。请务必对特殊字符进行转义。

    **示例JSON:**```json
    {{
        "name": "CVE-2023-12345-ExampleApp-SQL注入",
        "type": "SQL注入",
        "app": "ExampleApp", 
        "risk": "高危，可能导致数据泄露和远程代码执行",
        "version": "<= 1.0",
        "condition": "需要网络访问和数据库端口开放",
        "poc_available": "是",
        "poison": "90%",
        "cve_valid": "是",
        "markdown": "# 漏洞概述\n\n该漏洞存在于ExampleApp的登录模块,攻击者可以通过构造恶意的SQL语句绕过身份验证...\n\n## 有效性分析\n\n根据CVE编号格式、漏洞描述的完整性、参考链接的存在等因素，该CVE是真实有效的...\n\n## 投毒风险分析\n\n该仓库存在较高的投毒风险，主要原因是...\n\n## 利用方式\n\n1.  攻击者需要网络访问权限\n2.  构造恶意的SQL语句\n3.  发送到目标系统\n4.  绕过身份验证，获取系统访问权限\n\n## 代码分析\n\n主要代码组件包括：\n- `exploit.py`: 主漏洞利用脚本\n- `payloads.py`: 包含各种SQL注入payload\n- `utils.py`: 辅助工具函数\n\n代码执行流程：\n1.  连接到目标数据库\n2.  构造恶意SQL语句\n3.  发送到目标系统\n4.  解析响应，获取敏感信息\n",
        "repo_name": "example/repo",
        "repo_url": "https://github.com/example/repo",
        "cve_url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345"
    }}
        """
        
        # 记录各部分长度
        logger.info(f"提示文本总长度: {len(prompt)}")
        logger.info(f"漏洞信息长度: {len(cve_info)}")
        logger.info(f"搜索结果长度: {len(search_results_str)}")
        logger.info(f"POC代码长度: {len(poc_results_str)}")
        
        # 调试日志
        logger.debug("提示文本构建完成")
        logger.debug(f"漏洞信息: {cve_info}")
        logger.debug(f"搜索结果: {search_results_str}")
        logger.debug(f"POC代码: {poc_results_str}")
        
        return prompt
        
    except Exception as e:
        logger.error(f"构建提示文本失败: {str(e)}")
        logger.debug(traceback.format_exc())
        return None

def process_cve(cve_id: str, repo: Dict, db_session) -> Dict:
    """
    处理单个CVE信息
    
    Args:
        cve_id: CVE编号
        repo: 仓库信息
        engine: 数据库连接
    """
    result = {}
    try:
        # 获取CVE检查器实例
        cve_checker = get_cve_checker()
        
        # 检查CVE有效性
        is_valid, source = cve_checker.check_cve_validity(cve_id)
        if not is_valid:
            logger.warning(f"CVE {cve_id} 被标记为无效，跳过处理")
            return result
        
        # 提取仓库基本信息
        repo_pushed_at = repo.get('pushed_at', '')
        repo_link = repo.get('html_url', '')
        repo_name = repo.get('name', '')
        repo_description = repo.get('description', '')
        repo_full_name = repo.get('full_name', '')
        
        logger.info(f"开始处理仓库: {repo_full_name}")

        # 检查仓库是否已存在
        repo_data = db_session.query(Repository).filter(Repository.github_id == repo['id']).order_by(Repository.id.desc()).first()
        if repo_data:
            logger.info(f"仓库已存在: {repo_link}")
            # 始终处理仓库以确保markdown文件更新
            action_log = 'update'
        else:
            logger.info(f"发现新仓库: {repo_link}")
            action_log = 'new'

        # 获取POC代码
        logger.info(f"获取POC代码: {repo_link}")
        code_prompt = get_github_poc(repo_link)
        # 如果无法获取POC代码，使用仓库URL作为备选，不跳过处理
        if not code_prompt:
            logger.warning(f"无法获取仓库 {repo_link} 的POC代码，使用仓库URL作为备选")
            code_prompt = repo_link

        # 获取或创建CVE信息
        cve = db_session.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            logger.info(f"获取CVE信息: {cve_id}")
            cve_info = get_cve_info(cve_id)
            if not cve_info:
                logger.error(f"获取CVE信息失败")
                cve_info = {}
            else:    
                try:
                    cve_data = CVE(
                        cve_id=cve_id,
                        title=cve_info.get('title'),
                        description=cve_info.get('description',{}).get('value'),
                        cve_data=cve_info
                    )
                    db_session.add(cve_data)
                    db_session.commit()
                    logger.info(f"保存CVE信息成功")
                except Exception as e:
                    logger.error(f"保存CVE信息失败: {str(e)}")
                    db_session.rollback()
                
        else:
            cve_info = cve.cve_data
        result['cve'] = cve_info
        result['repo'] = repo

        # GPT分析
        gpt_results = None
        # 初始化related_articles_str变量
        related_articles_str = '暂无相关文章'
        if enable_gpt:
            search_result = []
            if enable_search:
                logger.info(f"搜索漏洞相关信息: {cve_id}")
                # 使用更精准的搜索关键词，移除site:语法
                search_query = f"{cve_id} Vulnerability 漏洞分析 PoC EXP Exploit"
                
                # 获取搜索引擎配置
                search_engine = get_config('SEARCH_ENGINE')
                search_result = []
                
                # 网站优先级列表，使用完整域名和名称
                priority_sites = [
                    ('先知社区', 'xz.aliyun.com'),
                    ('FreeBuf', 'freebuf.com'),
                    ('securityvulnerability.io', 'securityvulnerability.io')
                ]
                
                # 根据配置选择搜索引擎
                if search_engine in ['duckduckgo', 'all']:
                    # 使用DuckDuckGo搜索
                    duckduckgo_results = search_duckduckgo(search_query)
                    search_result.extend(duckduckgo_results)
                    logger.info(f"DuckDuckGo搜索到 {len(duckduckgo_results)} 条结果")
                
                if search_engine in ['bing', 'all']:
                    # 使用Bing搜索
                    bing_results = search_bing(search_query)
                    search_result.extend(bing_results)
                    logger.info(f"Bing搜索到 {len(bing_results)} 条结果")
                
                # 去重搜索结果
                seen_urls = set()
                unique_results = []
                for result in search_result:
                    url = result.get('url')
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        unique_results.append(result)
                search_result = unique_results
                logger.info(f"去重后搜索结果: {len(search_result)} 条")
                
                # 将搜索结果转换为相关文章格式
                if search_result:
                    # 过滤和排序搜索结果
                    priority_results = []
                    normal_results = []
                    
                    for result in search_result:
                        if result.get('title') and result.get('url'):
                            title = result['title']
                            url = result['url']
                            content = result.get('content', '')
                            
                            # 过滤掉知乎结果
                            if 'zhihu.com' in url:
                                logger.debug(f"跳过知乎结果: {url}")
                                continue
                            
                            # 检查是否为相关结果
                            is_related = False
                            # 更严格的相关结果判断，确保只保留与漏洞相关的结果
                            if cve_id in title or cve_id in content:
                                is_related = True
                            elif any(keyword in title.lower() or keyword in content.lower() for keyword in ['漏洞', 'vulnerability', 'exploit', 'poc', 'cve', 'exploitation', 'exploit code']):
                                is_related = True
                            
                            if is_related:
                                # 检查是否为优先级网站
                                is_priority = False
                                for site_name, site_domain in priority_sites:
                                    # 更严格的域名匹配，确保准确识别优先级网站
                                    if site_domain.lower() in url.lower():
                                        is_priority = True
                                        logger.debug(f"匹配到优先级网站: {site_name}，URL: {url}")
                                        break
                                
                                if is_priority:
                                    priority_results.append(f"- [{title}]({url})")
                                else:
                                    # 只保留与漏洞直接相关的普通结果
                                    if any(keyword in title.lower() or keyword in content.lower() for keyword in [cve_id.lower(), '漏洞', 'exploit', 'poc']):
                                        normal_results.append(f"- [{title}]({url})")
                    
                    # 合并结果：优先级网站结果在前，普通结果在后
                    related_articles = priority_results + normal_results
                    
                    # 最多保留10条结果
                    related_articles = related_articles[:10]
                    
                    if related_articles:
                        related_articles_str = '\n'.join(related_articles)
                        logger.info(f"生成相关文章列表，共 {len(related_articles)} 条")
                        logger.info(f"优先级网站结果: {len(priority_results)} 条，普通结果: {len(normal_results)} 条")
                    else:
                        related_articles_str = '暂无相关文章'
            else:
                logger.info(f"搜索功能已禁用，跳过搜索: {cve_id}")

            logger.info("构建GPT提示文本")
            prompt = build_prompt(cve_info, search_result, code_prompt[:5000])
            if not prompt:
                logger.error("构建提示文本失败")
                return result
                
            logger.info("请求GPT分析")
            gpt_results = ask_gpt(prompt)
            logger.info(f"GPT 分析结果长度: {len(gpt_results) if gpt_results else 0}")

            if gpt_results:
                # 检查GPT分析结果中的CVE有效性
                cve_valid = gpt_results.get('cve_valid', '是')
                if cve_valid.lower() in ['否', 'no', '无效', 'invalid']:
                    logger.warning(f"GPT分析结果表明CVE {cve_id} 无效，跳过后续处理")
                    return result
                
                # 从CVE ID中提取年份，格式为CVE-YYYY-XXXX
                year = cve_id.split('-')[1]
                filepath = f"data/markdown/{year}/{cve_id}-{repo_full_name.replace('/', '_')}.md"
                
                # 确保所有模板需要的字段都存在（添加默认值）
                template_fields = {
                    'name': gpt_results.get('name', f'{cve_id} 漏洞'),
                    'type': gpt_results.get('type', '未知类型'),
                    'app': gpt_results.get('app', '未知应用'),
                    'risk': gpt_results.get('risk', '未评级'),
                    'version': gpt_results.get('version', '未知版本'),
                    'condition': gpt_results.get('condition', '未知条件'),
                    'poc_available': gpt_results.get('poc_available', '未知'),
                    'poison': gpt_results.get('poison', '未评估'),
                    'markdown': gpt_results.get('markdown', gpt_results.get('description', '暂无详细分析')),
                }
                
                # 添加reference_url字段，包含各数据源的URL
                reference_urls = []
                if source:
                    reference_urls.append(source)
                reference_urls.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                reference_urls.append(f"https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{cve_id}")
                
                # 合并所有字段
                gpt_results.update(template_fields)
                gpt_results.update({
                    'cve_id': cve_id,
                    'repo_name': repo_full_name,
                    'repo_url': repo_link,
                    'cve_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    'reference_url': ' | '.join(reference_urls),
                    'action_log': '新增' if action_log == 'new' else '更新',
                    'git_url': filepath,
                    'related_articles': related_articles_str
                })
                
                result['gpt'] = gpt_results
                
                # 写入markdown（添加错误处理）
                try:
                    write_to_markdown(gpt_results, filepath)
                    logger.info(f'✅ 成功生成分析报告: {filepath}')
                except Exception as e:
                    logger.error(f"❌ 生成markdown失败: {e}")
                    logger.debug(f"GPT结果字段: {list(gpt_results.keys())}")
                    logger.debug(traceback.format_exc())
            else:
                logger.warning(f"⚠️ GPT分析失败，生成基础报告: {cve_id}")
                # 初始化related_articles_str变量
                related_articles_str = '暂无相关文章'
                # 将失败的请求加入重试队列
                if enable_gpt and prompt:
                    logger.info(f"将CVE {cve_id} 的GPT请求加入重试队列")
                    queue_gpt_retry(cve_id, prompt)
                # 即使GPT失败也生成基础markdown
                gpt_results = {
                    'name': f'{cve_id} 漏洞分析（GPT暂时失败）',
                    'type': '待GPT分析',
                    'app': repo_full_name.split('/')[1] if '/' in repo_full_name else repo_full_name,
                    'risk': '待评估',
                    'version': '待确认',
                    'condition': '待分析',
                    'poc_available': f'PoC代码: {repo_link}',
                    'poison': '未评估',
                    'markdown': f'''## ⚠️ GPT分析暂时失败

Gemini API暂时无法完成分析，可能原因：
- API速率限制(429)
- 请求格式问题(400)
- 其他临时性错误

## 基础信息

**CVE编号**: {cve_id}  
**GitHub仓库**: [{repo_full_name}]({repo_link})  
**仓库描述**: {repo_description or "无描述"}

## 下一步

请稍后查看此文件，系统会在后续更新中补充完整的GPT分析结果。''',
                    'cve_valid': '是'
                }

        # 保存仓库信息
        try:
            repo_data = Repository(
                github_id=repo['id'],
                cve_id=cve_id,
                name=repo_name,
                description=repo_description,
                url=repo_link,
                action_log=action_log,
                repo_data=repo,
                repo_pushed_at=repo_pushed_at,
                gpt_analysis=gpt_results
            )
            db_session.add(repo_data)
            db_session.commit()
            logger.info("保存仓库信息成功")
        except Exception as e:
            logger.error(f"保存仓库信息失败: {str(e)}")
            db_session.rollback()

        # 发送通知
        # 判断仓库push时间是否为今天,统一时区,如果为当天则发送通知，否则只入库
        tz = timezone(timedelta(hours=8))  # UTC+8 for Asia/Shanghai
        today = datetime.now(tz).date()
        repo_date = datetime.strptime(repo_pushed_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).astimezone(tz).date()
        push_today = today == repo_date
        
        if enable_notify and push_today:
            logger.info("发送通知")
            # 重新组织数据结构以匹配webhook模板
            # 为gpt_results添加timestamp字段
            if gpt_results:
                gpt_results['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            webhook_data = {
                'cve': {
                    'title': cve_id,
                    'id': cve_id,
                },
                'repo': {
                    'full_name': repo_full_name,
                    'html_url': repo_link,
                    'description': repo_description or '无描述'
                },
                'gpt': gpt_results if gpt_results else {}
            }
            # 使用统一的通知发送函数
            send_webhook(webhook_data)
        
        return result

    except Exception as e:
        logger.error(f"处理CVE异常: {str(e)}")
        logger.debug(traceback.format_exc())


def main():
    """
    主函数:搜索并分析CVE漏洞信息

    """
    try:
        # 记录当前使用的GPT服务提供商
        gpt_provider = get_config('GPT_PROVIDER')
        logger.info(f"使用GPT服务提供商: {gpt_provider}")
        
        # 从配置中获取CVE年份范围，默认为"2020-2025"
        year_range = get_config('CVE_YEAR_RANGE')
        if not year_range:
            year_range = "2020-2025"
        
        logger.info(f"使用CVE年份范围: {year_range}")
        
        # 移除年份范围生成查询前缀的逻辑，直接使用完整的CVE格式进行搜索
        query = "CVE-"
        
        # 获取CVE检查器实例
        cve_checker = get_cve_checker()
        
        # 搜索GitHub仓库
        cve_list, repo_list = search_github(query)
        if not repo_list:
            logger.warning("未找到相关仓库")
            return

        # 使用数据库会话上下文管理器
        with get_db_session() as db_session:
            # 扩展搜索
            if enable_extended:
                logger.info("执行扩展搜索")
                for cve_id in cve_list:
                    # 检查CVE有效性
                    is_valid, source = cve_checker.check_cve_validity(cve_id)
                    if not is_valid:
                        logger.warning(f"CVE {cve_id} 被标记为无效，跳过处理")
                        continue
                    
                    _, cve_items = search_github(cve_id)
                    for item in cve_items:
                        if cve_id == item['cve_id']:
                            process_cve(cve_id, item['repo'], db_session)
                    time.sleep(get_config('SLEEP_INTERVAL'))
            else:
                # 处理每个仓库
                for repo in repo_list:
                    try:    
                        cve_id = repo['cve_id']
                        
                        # 检查CVE有效性
                        is_valid, source = cve_checker.check_cve_validity(cve_id)
                        if not is_valid:
                            logger.warning(f"CVE {cve_id} 被标记为无效，跳过处理")
                            continue
                        
                        logger.info(f"处理CVE: {cve_id}")
                        result = process_cve(cve_id, repo['repo'], db_session)
                        time.sleep(get_config('SLEEP_INTERVAL'))
                    except Exception as e:
                        logger.error(f"处理CVE异常: {str(e)} {repo}")
                        logger.debug(traceback.format_exc())
            logger.info("搜索分析完成")
        
    except Exception as e:
        logger.error(f"程序执行异常: {traceback.format_exc()}")
        sys.exit(1)

def generate_daily_rss_feed():
    """
    生成每日漏洞RSS订阅源
    """
    try:
        logger.info("开始生成每日漏洞RSS订阅源")
        
        # 获取今天的日期
        tz = timezone(timedelta(hours=8))  # UTC+8 for Asia/Shanghai
        today = datetime.now(tz).strftime('%Y-%m-%d')
        
        # 从数据库获取今日漏洞数据
        with get_db_session() as db_session:
            # 查询今天的漏洞，使用created_at字段
            today_vulnerabilities = db_session.query(CVE).filter(
                CVE.created_at.like(f"{today}%")
            ).all()
            
            # 转换为字典列表（在session内完成，避免DetachedInstanceError）
            vuln_list = []
            for vuln in today_vulnerabilities:
                vuln_dict = {
                    'cve_id': vuln.cve_id,
                    'title': vuln.title or f"{vuln.cve_id} - 未命名漏洞",
                    'description': vuln.description or "暂无详细描述",
                    'created_at': vuln.created_at.isoformat() if vuln.created_at else None,
                    'validation_source': vuln.validation_source or "未知",
                    'is_valid': vuln.is_valid
                }
                
                # 直接查询关联仓库（在同一个session内）
                poc_info = []
                repos = db_session.query(Repository).filter(
                    Repository.cve_id == vuln.cve_id
                ).all()
                for repo in repos:
                    poc_info.append({
                        'repo': {
                            'name': repo.name,
                            'html_url': repo.url,
                            'description': repo.description
                        }
                    })
                vuln_dict['poc_info'] = poc_info
                vuln_list.append(vuln_dict)
        
        if vuln_list:
            # 生成RSS内容
            rss_content = generate_rss_feed(
                vuln_list,
                title="VulnWatchdog每日漏洞订阅",
                description=f"{today}安全漏洞信息"
            )
            
            # 保存RSS文件
            rss_dir = "rss_feeds"
            if not os.path.exists(rss_dir):
                os.makedirs(rss_dir)
            
            rss_file = os.path.join(rss_dir, f"vuln_feed_{today.replace('-', '')}.xml")
            with open(rss_file, 'w', encoding='utf-8') as f:
                f.write(rss_content)
            
            # 同时保存一份最新的RSS文件
            latest_rss_file = os.path.join(rss_dir, "latest_vuln_feed.xml")
            with open(latest_rss_file, 'w', encoding='utf-8') as f:
                f.write(rss_content)
            
            logger.info(f"每日漏洞RSS订阅源生成成功，共包含 {len(vuln_list)} 个漏洞")
            logger.info(f"RSS文件已保存至: {rss_file}")
            logger.info(f"最新RSS文件已保存至: {latest_rss_file}")
            return True
        else:
            logger.warning(f"今日({today})未发现新漏洞")
            return False
            
    except Exception as e:
        logger.error(f"生成RSS订阅源时发生错误: {str(e)}")
        logger.debug(traceback.format_exc())
        return False

def generate_weekly_report():
    """
    生成每周漏洞报告
    存储在data/WeeklyReport/年份-月份-当月第几周/Weekly_当前日期.md
    """
    try:
        logger.info("开始生成每周漏洞报告")
        
        # 获取当前日期信息
        tz = timezone(timedelta(hours=8))  # UTC+8 for Asia/Shanghai
        now = datetime.now(tz)
        today_str = now.strftime('%Y-%m-%d')
        year = now.year
        month = now.month
        
        # 计算本周的开始和结束日期
        # 本周一
        week_start = now - timedelta(days=now.weekday())
        # 本周日
        week_end = week_start + timedelta(days=6)
        
        # 计算当月第几周
        # 方法：计算本月第一天是星期几，然后计算当前日期是第几周
        first_day_of_month = datetime(year, month, 1, tzinfo=tz)
        # 本月第一天是星期几（0=周一，6=周日）
        first_day_weekday = first_day_of_month.weekday()
        # 计算当前日期距离本月第一天的天数
        days_since_first = (now - first_day_of_month).days
        # 计算当月第几周（向上取整）
        week_of_month = (days_since_first + first_day_weekday + 1 + 6) // 7
        
        # 创建目录结构
        dir_path = f"data/WeeklyReport/{year}-{month:02d}-W{week_of_month}"
        os.makedirs(dir_path, exist_ok=True)
        
        # 报告文件路径
        report_file = os.path.join(dir_path, f"Weekly_{today_str}.md")
        
        # 格式化日期字符串
        week_start_str = week_start.strftime('%Y-%m-%d')
        week_end_str = week_end.strftime('%Y-%m-%d')
        
        # 从数据库获取本周的漏洞数据
        with get_db_session() as db_session:
            # 查询本周的漏洞
            # 获取本周新增的CVE记录，修复查询条件
            weekly_vulnerabilities = db_session.query(CVE).filter(
                CVE.cve_id.in_(
                    db_session.query(Repository.cve_id).filter(
                        Repository.repo_pushed_at >= week_start_str,
                        Repository.repo_pushed_at <= week_end_str
                    ).distinct()
                )
            ).all()
            
            # 生成报告内容
            report_content = []
            report_content.append(f"# 每周漏洞报告 - {today_str}")
            report_content.append("")
            report_content.append(f"## 报告概览")
            report_content.append(f"- **报告周期**: {week_start_str} 至 {week_end_str}")
            report_content.append(f"- **新增漏洞数量**: {len(weekly_vulnerabilities)}")
            report_content.append("")
            
            # 按严重程度分类
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0}
            vuln_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Unknown': []}
            
            for vuln in weekly_vulnerabilities:
                severity = vuln.severity if vuln.severity else 'Unknown'
                severity_count[severity] += 1
                vuln_by_severity[severity].append(vuln)
            
            report_content.append("## 严重程度统计")
            for sev, count in severity_count.items():
                if count > 0:
                    report_content.append(f"- **{sev}**: {count} 个")
            report_content.append("")
            
            # 详细漏洞列表
            report_content.append("## 漏洞详情")
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Unknown']:
                if vuln_by_severity[severity]:
                    report_content.append(f"### {severity} 级漏洞")
                    report_content.append("")
                    for vuln in vuln_by_severity[severity]:
                        report_content.append(f"#### {vuln.cve_id}")
                        report_content.append(f"- **标题**: {vuln.title or '暂无'}")
                        report_content.append(f"- **描述**: {vuln.description[:200] if vuln.description else '暂无'}...")
                        report_content.append(f"- **发布日期**: {vuln.published_date or '暂无'}")
                        report_content.append(f"- **参考链接**: {' | '.join(vuln.references) if hasattr(vuln, 'references') and vuln.references else '暂无'}")
                        report_content.append("")
            
            # 保存报告
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_content))
            
            logger.info(f"每周漏洞报告生成成功: {report_file}")
            return report_file
            
    except Exception as e:
        logger.error(f"生成每周漏洞报告时发生错误: {str(e)}")
        logger.debug(traceback.format_exc())
        return None

def run_scheduled_tasks():
    """
    运行定时任务
    """
    # 启动我们自定义的任务调度器
    start_scheduler()
    
    # 启动RSS生成（立即执行一次）
    generate_daily_rss_feed()
    
    logger.info("定时任务已启动")
    
    # 主循环 - 保持程序运行
    try:
        while True:
            time.sleep(60)  # 每分钟检查一次
    except KeyboardInterrupt:
        logger.info("正在停止定时任务...")
        stop_scheduler()
        logger.info("定时任务已停止")

if __name__ == "__main__":
    logger.info(f"运行参数:")
    logger.info(f"  运行模式: {get_config('DEBUG')}")
    logger.info(f"  GPT 开关: {'启用' if get_config('ENABLE_GPT')==True else '禁用'}")
    logger.info(f"  搜索开关: {'启用' if get_config('ENABLE_SEARCH')==True else '禁用'}")
    logger.info(f"  搜索引擎: {get_config('SEARCH_ENGINE')}")
    logger.info(f"  扩展搜索开关: {'启用' if get_config('ENABLE_EXTENDED')==True else '禁用'}")
    logger.info(f"  通知开关: {'启用' if get_config('ENABLE_NOTIFY')==True else '禁用'}")
    logger.info(f"  通知类型: {get_config('NOTIFY_TYPE')}")
    
    # 检查是否只运行定时任务
    if len(sys.argv) > 1 and sys.argv[1] == "--schedule":
        run_scheduled_tasks()
    else:
        # 正常运行主程序
        main()
        # 主程序完成后，启动一次RSS生成
        generate_daily_rss_feed()

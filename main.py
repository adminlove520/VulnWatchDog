from datetime import datetime, timezone, timedelta
import json
import time
import traceback
import os
import logging
import sys
from typing import List, Dict, Optional
from config import get_config
from libs.search_engine import search_github, search_duckduckgo, get_github_poc, SearchError
from libs.report_generator import write_to_markdown, generate_rss_feed, get_template
from libs.scheduler import start_scheduler, stop_scheduler, get_cve_checker
from libs.cve_checker import CVEChecker
from libs.gpt_utils import ask_gpt, get_cve_info
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
      请根据以下漏洞信息、搜索结果和漏洞利用代码，评估漏洞的有效性、POC代码的有效性、是否存在投毒风险，并分析漏洞利用方式。请注意以下几点：

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

    **你的角色：** 你是一名搜索助理和网络漏洞研究员。

    **任务：**

    1.  **CVE有效性：** 分析此CVE是否为真实存在的有效漏洞。请综合考虑CVE编号格式、漏洞描述的完整性、参考链接的存在、漏洞的技术细节等因素。
    2.  **POC有效性：** 判断提供的POC代码是否有效，是否能实际利用此漏洞。
    3.  **投毒风险：** 分析POC代码内容,判断此仓库中是否存在作者隐藏的投毒代码,分析结果使用百分比。务必不要把POC验证的后门代码判定为投毒代码。
    4.  **利用方式：** 分析并总结漏洞的利用方式。
    5.  **排序优先级:** 搜索引擎结果 >  漏洞利用代码 > 漏洞库信息
    6.  **输出内容:** 务必使用中文
    7.  **markdown内容:** 务必使用markdown格式对提供的内容,围绕本次任务要求进行详细描述.
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
        "markdown": "该漏洞存在于ExampleApp的登录模块,攻击者可以通过构造恶意的SQL语句绕过身份验证..."
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
        if not code_prompt:
            logger.error(f"获取POC代码失败")
            return

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
        if enable_gpt:
            search_result = []
            if enable_search:
                logger.info(f"搜索漏洞相关信息: {cve_id}")
                # 增强搜索查询，添加PoC/EXP关键词
                search_result = search_duckduckgo(f"{cve_id} Vulnerability Analysis PoC EXP Exploit")
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
                    'git_url': f"{get_config('GIT_URL')}/blob/main/{filepath}" if get_config('GIT_URL') else ''
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
                logger.error(f"GPT分析失败,返回结果为空: {gpt_results}")

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
            # 使用统一的通知发送函数，内部会根据配置决定发送哪种类型的通知
            send_webhook(result)
        
        return result

    except Exception as e:
        logger.error(f"处理CVE异常: {str(e)}")
        logger.debug(traceback.format_exc())


def main():
    """
    主函数:搜索并分析CVE漏洞信息

    """
    try:
        # 从配置中获取CVE年份范围，默认为"2020-2025"
        year_range = get_config('CVE_YEAR_RANGE')
        if not year_range:
            year_range = "2020-2025"
        
        logger.info(f"使用CVE年份范围: {year_range}")
        
        # 向后兼容：如果设置了CVE_YEAR_PREFIX，则优先使用
        query_prefix = get_config('CVE_YEAR_PREFIX')
        if query_prefix:
            query = query_prefix
            logger.info(f"使用CVE年份前缀: {query}")
        else:
            # 解析年份范围
            try:
                start_year, end_year = map(int, year_range.split('-'))
                # 生成查询逻辑（这里使用年份前缀，后续可扩展更精确的查询）
                # 对于范围查询，使用起始年份的前缀
                query = f"CVE-{start_year//10}"
                logger.info(f"基于年份范围生成查询前缀: {query}")
            except:
                logger.warning(f"年份范围格式错误，使用默认值: 2020-2025")
                query = "CVE-2025"
        
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
        
        # 计算当月第几周
        # 简单计算：用当前日期是第几天除以7并向上取整
        week_of_month = (now.day + 6) // 7
        
        # 创建目录结构
        dir_path = f"data/WeeklyReport/{year}-{month:02d}-W{week_of_month}"
        os.makedirs(dir_path, exist_ok=True)
        
        # 报告文件路径
        report_file = os.path.join(dir_path, f"Weekly_{today_str}.md")
        
        # 计算本周的开始和结束日期
        week_start = now - timedelta(days=now.weekday())  # 本周一
        week_end = week_start + timedelta(days=6)  # 本周日
        
        # 从数据库获取本周的漏洞数据
        with get_db_session() as db_session:
            # 查询本周的漏洞
            week_start_str = week_start.strftime('%Y-%m-%d')
            week_end_str = week_end.strftime('%Y-%m-%d')
            
            # 获取本周新增的CVE记录（修复join查询问题）
            weekly_vulnerabilities = db_session.query(CVE).filter(
                CVE.cve_id.in_(
                    db_session.query(Repository.cve_id).filter(
                        Repository.repo_pushed_at >= week_start_str
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
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            vuln_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
            
            for vuln in weekly_vulnerabilities:
                severity = vuln.severity if vuln.severity else 'Unknown'
                if severity in severity_count:
                    severity_count[severity] += 1
                    vuln_by_severity[severity].append(vuln)
            
            report_content.append("## 严重程度统计")
            for sev, count in severity_count.items():
                if count > 0:
                    report_content.append(f"- **{sev}**: {count} 个")
            report_content.append("")
            
            # 详细漏洞列表
            report_content.append("## 漏洞详情")
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if vuln_by_severity[severity]:
                    report_content.append(f"### {severity} 级漏洞")
                    report_content.append("")
                    for vuln in vuln_by_severity[severity]:
                        report_content.append(f"#### {vuln.cve_id}")
                        report_content.append(f"- **标题**: {vuln.title}")
                        report_content.append(f"- **描述**: {vuln.description[:200]}...")
                        report_content.append(f"- **发布日期**: {vuln.published_date}")
                        report_content.append(f"- **参考链接**: {vuln.reference or '暂无'}")
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

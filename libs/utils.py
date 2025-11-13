from datetime import datetime
import logging
import hashlib
import json
import os
import re
import subprocess
import traceback
import requests
import time
import schedule
import feedparser
import concurrent.futures
from config import get_config
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
from libs.files2prompt import process_path
from libs.cisa_oscs_checker import get_cve_checker
import xml.etree.ElementTree as ET
from xml.dom import minidom
import threading

# GPT相关导入
try:
    from libs.gpt_utils import ask_gpt, get_cve_info
except ImportError:
    logger = logging.getLogger(__name__)
    logger.warning("未找到GPT工具模块，GPT分析功能将不可用")
    
    def ask_gpt(prompt):
        """GPT调用的占位函数"""
        return None
    
    def get_cve_info(cve_id):
        """获取CVE信息的占位函数"""
        return {}

logger = logging.getLogger(__name__)

# 定义全局调度器实例和CVE检查器实例
_scheduler_lock = threading.RLock()
_scheduler = None
_cve_checker = None


class CVEChecker:
    """
    CVE可用性检查器，集成CISA和OSCS数据源以验证CVE的有效性
    """
    def __init__(self):
        self.cisa_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        self.oscs_url = "https://www.oscs1024.com/feed"
        self.cisa_data = []
        self.oscs_data = []
        self.last_update = None
        self.update_interval = 3600  # 1小时更新一次缓存
        
    def update_data_sources(self):
        """
        更新CISA和OSCS数据源
        """
        now = time.time()
        if self.last_update and now - self.last_update < self.update_interval:
            return  # 未到更新时间
        
        try:
            # 更新CISA数据
            self._update_cisa_data()
            
            # 更新OSCS数据
            self._update_oscs_data()
            
            self.last_update = now
            logger.info("CVE检查器数据源更新完成")
            
        except Exception as e:
            logger.error(f"更新CVE检查器数据源时出错: {str(e)}")
    
    def _update_cisa_data(self):
        """
        更新CISA漏洞数据
        """
        try:
            # 简化实现，实际可能需要更复杂的解析
            response = requests.get(self.cisa_url, timeout=30)
            response.raise_for_status()
            
            # 解析HTML中的CVE ID列表
            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
            cves = set(cve_pattern.findall(response.text))
            self.cisa_data = list(cves)
            logger.info(f"成功更新CISA数据源，获取到 {len(cves)} 个CVE")
            
        except Exception as e:
            logger.error(f"更新CISA数据源失败: {str(e)}")
    
    def _update_oscs_data(self):
        """
        更新OSCS漏洞数据
        """
        try:
            # 使用feedparser解析RSS源
            feed = feedparser.parse(self.oscs_url)
            
            cves = []
            for entry in feed.entries:
                # 提取CVE ID
                cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
                found_cves = cve_pattern.findall(entry.summary or '')
                cves.extend(found_cves)
                
                # 从标题中查找
                if not found_cves:
                    found_cves = cve_pattern.findall(entry.title or '')
                    cves.extend(found_cves)
            
            self.oscs_data = list(set(cves))
            logger.info(f"成功更新OSCS数据源，获取到 {len(self.oscs_data)} 个CVE")
            
        except Exception as e:
            logger.error(f"更新OSCS数据源失败: {str(e)}")
    
    def check_cve_validity(self, cve_id):
        """
        检查CVE是否有效
        优先级：1. CISA数据源 2. OSCS数据源 3. 检查GitHub PoC仓库 4. GPT分析判断
        """
        # 首先更新数据源
        self.update_data_sources()
        
        # 1. 检查CISA数据源
        if cve_id in self.cisa_data:
            logger.info(f"CVE {cve_id} 在CISA数据源中找到，确认有效")
            return True, "CISA"
        
        # 2. 检查OSCS数据源
        if cve_id in self.oscs_data:
            logger.info(f"CVE {cve_id} 在OSCS数据源中找到，确认有效")
            return True, "OSCS"
        
        # 3. 检查GitHub PoC仓库
        if self._check_github_poc(cve_id):
            logger.info(f"CVE {cve_id} 在GitHub PoC仓库中找到，确认有效")
            return True, "GitHub PoC"
        
        # 4. 使用GPT分析判断CVE有效性
        gpt_result = self._check_with_gpt(cve_id)
        if gpt_result:
            is_valid, confidence = gpt_result
            if is_valid and confidence >= 0.7:  # 高可信度的有效判断
                logger.info(f"GPT分析确认CVE {cve_id} 有效（置信度: {confidence:.2f}）")
                return True, "GPT Analysis"
            elif not is_valid and confidence >= 0.8:  # 极高可信度的无效判断
                logger.warning(f"GPT分析确认CVE {cve_id} 无效（置信度: {confidence:.2f}）")
                return False, "GPT Analysis"
            else:
                logger.info(f"GPT分析结果不确定（置信度: {confidence:.2f}），返回默认判断")
        
        logger.warning(f"CVE {cve_id} 在所有数据源中均未找到，可能无效")
        return False, "None"
    
    def _check_with_gpt(self, cve_id):
        """
        使用GPT分析判断CVE的有效性
        
        返回:
            (is_valid, confidence) 或 None（分析失败）
        """
        try:
            # 获取CVE的基本信息
            cve_info = get_cve_info(cve_id)
            
            # 构建分析提示词
            prompt = f"""
            请分析以下CVE信息，并判断其是否为有效的漏洞。
            
            CVE ID: {cve_id}
            CVE信息: {json.dumps(cve_info, ensure_ascii=False)}
            
            请考虑以下因素:
            1. CVE编号格式是否正确（CVE-年份-数字）
            2. 年份是否在合理范围内（1999年至今）
            3. 是否有详细的漏洞描述
            4. 是否有发布日期和修改日期
            5. 是否有CVSS评分或其他严重性指标
            6. 是否有参考链接
            7. 是否有相关的技术细节
            8. 综合判断这个CVE是否真实存在且被广泛认可
            
            请以JSON格式返回分析结果，包含以下字段:
            - is_valid: 布尔值，表示CVE是否有效
            - confidence: 浮点数（0-1），表示判断的置信度
            - reasoning: 字符串，解释判断理由
            """
            
            # 调用GPT进行分析
            result = ask_gpt(prompt)
            
            if result and isinstance(result, dict):
                is_valid = result.get('is_valid', False)
                confidence = result.get('confidence', 0.0)
                reasoning = result.get('reasoning', '')
                
                logger.debug(f"GPT分析结果 - CVE: {cve_id}, 有效: {is_valid}, 置信度: {confidence}, 理由: {reasoning}")
                return is_valid, confidence
            
        except Exception as e:
            logger.error(f"使用GPT分析CVE {cve_id} 有效性时出错: {str(e)}")
            logger.debug(traceback.format_exc())
        
        return None
    
    def _check_github_poc(self, cve_id):
        """
        检查GitHub上是否存在该CVE的PoC仓库
        """
        try:
            # 使用GitHub Search API
            headers = {}
            github_token = get_config('GITHUB_TOKEN')
            if github_token:
                headers['Authorization'] = f'token {github_token}'
            
            # 增强搜索查询，添加更多PoC/EXP相关关键词
            search_terms = [
                'poc', 'proof of concept', 'exploit', 'exp', 
                'vulnerability', 'exploit code', 'attack', 
                'payload', 'exploit-db', 'shell', 'remote code execution'
            ]
            
            # 构建查询字符串
            query = f"{cve_id} "
            query += " OR ".join(search_terms)
            
            url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc&per_page=1"
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                total_count = data.get('total_count', 0)
                
                if total_count > 0:
                    logger.info(f"找到 {total_count} 个与 {cve_id} 相关的PoC/EXP仓库")
                    return True
                
                # 如果直接搜索没有结果，尝试更宽泛的搜索
                broad_query = f"{cve_id}"
                url = f"https://api.github.com/search/repositories?q={broad_query}&sort=updated&order=desc&per_page=1"
                response = requests.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    broad_data = response.json()
                    if broad_data.get('total_count', 0) > 0:
                        logger.info(f"通过宽泛搜索找到与 {cve_id} 相关的仓库")
                        return True
            
        except Exception as e:
            logger.error(f"检查GitHub PoC仓库时出错: {str(e)}")
        
        return False


class TaskScheduler:
    """
    任务调度器，管理定期执行的检查和更新任务
    """
    def __init__(self):
        self.running = False
        self.thread = None
        self.cve_checker = CVEChecker()
    
    def start(self):
        """
        启动调度器
        """
        if self.running:
            logger.warning("调度器已经在运行中")
            return
        
        self.running = True
        
        # 设置定时任务
        # 每小时更新一次CVE检查器数据源
        schedule.every(1).hour.do(self.update_cve_data)
        
        # 每天早上8点生成RSS
        schedule.every().day.at("08:00").do(self.generate_daily_rss)
        
        # 每周一早上9点生成每周漏洞报告
        schedule.every().monday.at("09:00").do(self.generate_weekly_report)
        
        # 每天凌晨2点检查数据库中的CVE有效性
        schedule.every().day.at("02:00").do(self.validate_all_cves)
        
        # 创建并启动调度线程
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()
        
        logger.info("任务调度器已启动")
        
        # 立即执行一次数据源更新
        self.update_cve_data()
    
    def stop(self):
        """
        停止调度器
        """
        if not self.running:
            logger.warning("调度器未在运行")
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)  # 等待线程结束，最多5秒
        
        # 清除所有定时任务
        schedule.clear()
        
        logger.info("任务调度器已停止")
    
    def _run_scheduler(self):
        """
        调度器运行循环
        """
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # 每分钟检查一次待执行任务
            except Exception as e:
                logger.error(f"调度器运行错误: {str(e)}")
                logger.debug(traceback.format_exc())
                time.sleep(60)  # 出错后等待一分钟再试
    
    def update_cve_data(self):
        """
        更新CVE检查器数据源
        """
        logger.info("开始更新CVE检查器数据源")
        try:
            self.cve_checker.update_data_sources()
            logger.info("CVE检查器数据源更新完成")
        except Exception as e:
            logger.error(f"更新CVE检查器数据源失败: {str(e)}")
    
    def generate_daily_rss(self):
        """
        生成每日RSS订阅源
        """
        logger.info("调度器触发每日RSS生成")
        
        # 导入需要的模块，避免循环导入
        from main import generate_daily_rss_feed
        generate_daily_rss_feed()
    
    def validate_all_cves(self):
        """
        验证数据库中所有CVE的有效性
        """
        logger.info("开始验证数据库中所有CVE的有效性")
        
        db_session = None
        try:
            db_session = get_db_session()
            
            # 获取所有CVE记录
            all_cves = db_session.query(CVE).all()
            logger.info(f"开始验证 {len(all_cves)} 个CVE")
            
            invalid_count = 0
            for cve in all_cves:
                # 检查CVE有效性
                is_valid, source = self.cve_checker.check_cve_validity(cve.cve_id)
                
                if not is_valid:
                    # 标记无效CVE
                    logger.warning(f"发现无效CVE: {cve.cve_id}")
                    invalid_count += 1
                    
                    # 更新数据库标记
                    cve.is_valid = False
                    db_session.commit()
                else:
                    # 更新为有效，同时记录源
                    if not cve.is_valid or not cve.validation_source:
                        cve.is_valid = True
                        cve.validation_source = source
                        db_session.commit()
            
            logger.info(f"CVE验证完成，发现 {invalid_count} 个无效CVE")
            
        except Exception as e:
            logger.error(f"验证CVE有效性时出错: {str(e)}")
            logger.debug(traceback.format_exc())
            if db_session:
                db_session.rollback()
        finally:
            if db_session:
                db_session.close()
    
    def get_cve_checker(self):
        """
        获取CVE检查器实例
        """
        return self.cve_checker


def generate_rss_feed(vulnerabilities: List[Dict], title: str, description: str) -> str:
    """
    生成RSS订阅源XML内容
    
    Args:
        vulnerabilities: 漏洞列表，每个元素是包含漏洞信息的字典
        title: RSS标题
        description: RSS描述
    
    Returns:
        RSS XML格式的字符串
    """
    # 创建根元素
    rss = ET.Element('rss', version='2.0')
    channel = ET.SubElement(rss, 'channel')
    
    # 添加频道信息
    ET.SubElement(channel, 'title').text = title
    ET.SubElement(channel, 'description').text = description
    ET.SubElement(channel, 'link').text = 'http://vulnwatchdog.local'
    ET.SubElement(channel, 'lastBuildDate').text = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0800')
    ET.SubElement(channel, 'generator').text = 'VulnWatchdog'
    
    # 添加每个漏洞作为一个条目
    for vuln in vulnerabilities:
        item = ET.SubElement(channel, 'item')
        
        # 基本信息
        ET.SubElement(item, 'title').text = f"{vuln.get('cve_id', 'Unknown')} - {vuln.get('title', 'Untitled')}"
        
        # 构建描述内容
        desc_parts = []
        desc_parts.append(f"<strong>严重程度:</strong> {vuln.get('severity', 'Unknown')}")
        desc_parts.append(f"<strong>发布日期:</strong> {vuln.get('published_date', 'Unknown')}")
        desc_parts.append(f"<strong>来源:</strong> {vuln.get('source', 'Unknown')}")
        desc_parts.append(f"<strong>描述:</strong> {vuln.get('description', 'No description available')}")
        
        # 添加PoC信息
        poc_info = vuln.get('poc_info', [])
        if poc_info:
            desc_parts.append("<strong>相关PoC:</strong>")
            for poc in poc_info:
                repo = poc.get('repo', {})
                if repo:
                    name = repo.get('name', 'Unknown')
                    url = repo.get('html_url', '#')
                    desc = repo.get('description', '')
                    desc_parts.append(f"<a href='{url}'>{name}</a>: {desc}")
        
        description_text = '<br>'.join(desc_parts)
        ET.SubElement(item, 'description').text = description_text
        
        # 链接和唯一ID
        # 使用NVD官方链接作为默认引用URL
        link = vuln.get('reference_url', f"https://nvd.nist.gov/vuln/detail/{vuln.get('cve_id', 'unknown')}")
        ET.SubElement(item, 'link').text = link
        ET.SubElement(item, 'guid', isPermaLink='false').text = vuln.get('cve_id', f"unknown-{hash(link)}")
        
        # 发布日期
        pub_date = vuln.get('published_date', datetime.now().isoformat())
        # 转换日期格式为RFC 822
        try:
            if isinstance(pub_date, str):
                # 尝试解析不同格式的日期字符串
                date_formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%SZ',
                    '%Y-%m-%d'
                ]
                parsed_date = None
                for fmt in date_formats:
                    try:
                        parsed_date = datetime.strptime(pub_date[:len(fmt)], fmt)
                        break
                    except ValueError:
                        continue
                
                if parsed_date:
                    pub_date_str = parsed_date.strftime('%a, %d %b %Y %H:%M:%S +0800')
                else:
                    pub_date_str = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0800')
            else:
                pub_date_str = pub_date.strftime('%a, %d %b %Y %H:%M:%S +0800')
        except Exception:
            pub_date_str = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0800')
        
        ET.SubElement(item, 'pubDate').text = pub_date_str
    
    # 将ElementTree转换为美观的XML字符串
    rough_string = ET.tostring(rss, encoding='utf-8', method='xml')
    reparsed = minidom.parseString(rough_string)
    
    # 添加XML声明
    xml_string = reparsed.toprettyxml(indent="  ")
    
    return xml_string


def start_scheduler():
    """
    启动任务调度器
    """
    global _scheduler
    with _scheduler_lock:
        if _scheduler is None:
            _scheduler = TaskScheduler()
        _scheduler.start()
    return _scheduler


def stop_scheduler():
    """
    停止任务调度器
    """
    global _scheduler
    with _scheduler_lock:
        if _scheduler:
            _scheduler.stop()
            _scheduler = None


def get_cve_checker():
    """
    获取CVE检查器实例
    """
    global _cve_checker, _scheduler
    with _scheduler_lock:
        if _cve_checker is None:
            if _scheduler is None:
                _scheduler = start_scheduler()
            _cve_checker = _scheduler.get_cve_checker()
    return _cve_checker


def search_github(query: str, per_page: int = 30, max_retries: int = 3) -> Tuple[set, List[Dict]]:
    """
    搜索GitHub仓库中的CVE信息，并验证CVE可用性，支持批量处理和重试机制
    
    参数:
        query: 搜索关键词
        per_page: 每页返回的结果数量
        max_retries: 最大重试次数
        
    返回:
        (cve_id集合, 仓库信息列表)
    """
    current_year = datetime.now().year
    # 增强的CVE正则表达式，支持标准格式和一些常见变体
    re_cve = re.compile(r'(?i)CVE-(\d{4})-(\d{4,7})')
    
    # 获取代理配置（先尝试不使用代理）
    proxy = None  # 暂时禁用代理以避免SSL连接问题
    # 获取CVE检查器
    cve_checker = get_cve_checker(proxy)
    
    # 简化搜索查询，减少逻辑运算符数量
    enhanced_query = f"{query}+(poc+OR+exploit)+NOT+test"
    
    # 生成完整的查询URL，不再限制语言
    url = f"https://api.github.com/search/repositories?q={enhanced_query}&sort=updated&order=desc&per_page={per_page}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    
    # 使用GitHub Token（如果配置了）
    github_token = get_config('GITHUB_TOKEN')
    if github_token:
        headers['Authorization'] = f"token {github_token}"
    
    # 暂时不使用代理
    proxies = {}
    
    # 重试机制
    for retry in range(max_retries):
        try:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=20)
            
            # 处理速率限制
            if resp.status_code == 403 and 'rate limit' in resp.text.lower():
                reset_time = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                wait_time = max(1, reset_time - time.time())
                logger.warning(f"GitHub API速率限制，等待 {wait_time:.1f} 秒...")
                time.sleep(wait_time)
                continue
            
            resp.raise_for_status()
            break
        except requests.exceptions.RequestException as e:
            if retry == max_retries - 1:
                logger.error(f"访问GitHub API失败（已重试{max_retries}次）: {e}")
                return set(), []
            
            wait_time = 2 ** retry  # 指数退避
            logger.warning(f"访问GitHub API失败，{wait_time}秒后重试 ({retry+1}/{max_retries}): {e}")
            time.sleep(wait_time)
            continue

    # 提取仓库数据
    items = resp.json().get('items', [])
    logger.info(f"GitHub搜索到 {len(items)} 个仓库")
    
    cve_list = set()
    repo_list = []
    
    # 批量收集需要验证的CVE
    cve_to_verify = {}
    
    for item in items:
        try:
            name = item.get('name', '')
            desc = item.get('description', '')
            readme = ""  # 可以考虑异步获取README以提高CVE检测率
            
            # 在仓库名称、描述中搜索CVE
            content_to_search = f"{name} {desc} {readme}"
            cve_matches = re_cve.finditer(content_to_search)
            
            found_cves = set()
            for match in cve_matches:
                cve_id = match.group(0).upper()
                cve_year = int(match.group(1))
                
                # 基本验证：年份检查
                if cve_year > current_year or cve_year < 1999:  # CVE系统始于1999年
                    logger.warning(f"CVE年份异常: {cve_id}")
                    continue
                
                found_cves.add(cve_id)
            
            # 批量添加到待验证列表
            for cve_id in found_cves:
                if cve_id not in cve_to_verify:
                    cve_to_verify[cve_id] = []
                cve_to_verify[cve_id].append(item)
                
        except Exception as e:
            logger.error(f"处理仓库信息异常: {e}")
            continue
    
    # 批量验证CVE可用性，采用并行方式提高效率
    # 这里使用简单的顺序验证，实际项目中可以考虑使用多线程/协程
    for cve_id, repos in cve_to_verify.items():
        try:
            if cve_checker.verify_cve_availability(cve_id):
                cve_list.add(cve_id)
                for repo in repos:
                    repo_list.append({'cve_id': cve_id, 'repo': repo})
                    logger.debug(f"找到有效CVE: {cve_id}, 仓库: {repo['html_url']}")
            else:
                logger.warning(f"跳过无效CVE: {cve_id}")
            
            # 适当延迟避免API限流
            time.sleep(0.5)
            
        except Exception as e:
            logger.error(f"验证CVE {cve_id} 可用性异常: {e}")
    
    logger.info(f"共找到 {len(cve_list)} 个有效CVE, {len(repo_list)} 个相关仓库")
    return cve_list, repo_list

# CVE信息缓存
_cve_info_cache = {}
_cache_expiry = 3600  # 缓存有效期，单位：秒


def get_cve_info(cve_id: str) -> Dict:
    """
    从多个来源获取CVE详细信息，支持缓存机制和增强的错误处理
    
    参数:
        cve_id: CVE编号
        
    返回:
        CVE信息字典
    """
    # 检查缓存
    if cve_id in _cve_info_cache:
        cached_data, timestamp = _cve_info_cache[cve_id]
        if time.time() - timestamp < _cache_expiry:
            logger.debug(f"使用缓存的CVE信息: {cve_id}")
            return cached_data
        else:
            # 缓存过期，删除
            del _cve_info_cache[cve_id]
    
    # 尝试多个信息源
    sources = [
        {
            'name': 'CVE Circl',
            'url': f"https://cve.circl.lu/api/cve/{cve_id}",
            'timeout': 10
        },
        {
            'name': 'NVD API',
            'url': f"https://services.nvd.nist.gov/rest/json/cves/1.0/{cve_id}",
            'timeout': 15
        }
    ]
    
    for source in sources:
        try:
            logger.info(f"从{source['name']}获取CVE信息: {cve_id}")
            # 获取代理配置
            proxy = get_config('PROXY')
            proxies = {}
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy
                }
            
            # 添加更健壮的请求配置
            resp = requests.get(
                source['url'], 
                timeout=source['timeout'], 
                proxies=proxies,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                verify=False  # 在开发环境下禁用SSL验证
            )
            
            # 检查状态码
            if resp.status_code != 200:
                logger.error(f"API返回非200状态码: {resp.status_code}, 来源: {source['name']}")
                continue
            
            # 尝试解析JSON
            try:
                data = resp.json()
            except json.JSONDecodeError as e:
                logger.error(f"解析JSON失败: {str(e)}, 来源: {source['name']}")
                continue
            
            # 处理不同API返回格式
            if source['name'] == 'NVD API':
                # 转换NVD API格式为统一格式，增加健壮性检查
                try:
                    if 'result' in data and 'CVE_Items' in data['result'] and data['result']['CVE_Items']:
                        nvd_item = data['result']['CVE_Items'][0]
                        formatted_data = {
                            'id': nvd_item.get('cve', {}).get('CVE_data_meta', {}).get('ID', cve_id),
                            'summary': nvd_item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'No description available'),
                            'published': nvd_item.get('publishedDate', ''),
                            'last_modified': nvd_item.get('lastModifiedDate', ''),
                            'cvss': nvd_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
                        }
                        # 缓存结果
                        _cve_info_cache[cve_id] = (formatted_data, time.time())
                        logger.info(f"从{source['name']}获取CVE信息成功: {cve_id}")
                        return formatted_data
                    else:
                        logger.warning(f"NVD API返回的数据结构不符合预期: {data}")
                except (IndexError, KeyError, TypeError) as e:
                    logger.error(f"处理NVD API数据时出错: {str(e)}")
            else:
                # CVE Circl API格式，增加健壮性检查
                if data:
                    # 确保数据格式正确
                    safe_data = {
                        'id': data.get('id', cve_id),
                        'summary': data.get('summary', 'No description available'),
                        'Published': data.get('Published', ''),
                        'Modified': data.get('Modified', ''),
                        'cvss': data.get('cvss', {}),
                        'references': data.get('references', [])
                    }
                    # 缓存结果
                    _cve_info_cache[cve_id] = (safe_data, time.time())
                    logger.info(f"从{source['name']}获取CVE信息成功: {cve_id}")
                    return safe_data
        
        except requests.exceptions.RequestException as e:
            logger.error(f"从{source['name']}请求CVE API失败: {e}")
            logger.debug(traceback.format_exc())
        except Exception as e:
            logger.error(f"从{source['name']}获取CVE信息异常: {e}")
            logger.debug(traceback.format_exc())
    
    # 所有源都失败，返回基本信息结构
    logger.error(f"所有数据源均无法获取CVE信息: {cve_id}")
    # 返回基本结构，确保调用方不会因为缺少键而崩溃
    return {
        'id': cve_id,
        'summary': f'无法获取CVE-{cve_id}的详细信息',
        'published': '',
        'last_modified': '',
        'cvss': {},
        'references': []
    }

class SearchError(Exception):
    """搜索相关错误的自定义异常"""
    pass

def search_searxng(query: str, num_results: int = 5) -> List[Dict]:
    """
    使用Searx执行搜索
    
    参数:
        query: 搜索关键词
        num_results: 返回结果数量
        
    返回:
        搜索结果列表
        
    异常:
        SearchError: 搜索失败
    """
    url = get_config('SEARXNG_URL')
    params = {
        "q": query,
        "format": "json",
        "pageno": 1,
        "engines": "google", 
        "max_results": num_results
    }
    
    try:
        response = requests.get(url, params=params, verify=True, timeout=10)
        response.raise_for_status()
        
        results = response.json().get("results", [])
        logger.info(f"搜索 '{query}' 获得 {len(results)} 个结果")
        return results
        
    except requests.exceptions.RequestException as e:
        logger.error(f"搜索请求失败: {e}")
        raise SearchError(f"搜索请求失败: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"解析搜索结果失败: {e}")
        raise SearchError(f"无效的搜索响应: {e}")

def ask_gpt(prompt: str) -> Optional[Dict]:
    """
    调用GPT API进行分析，支持OpenAI和Google Gemini格式
    
    参数:
        prompt: 提示文本
        
    返回:
        API响应解析后的字典,失败返回None
    """
    gpt_server_url = get_config('GPT_SERVER_URL')
    is_gemini = 'gemini' in gpt_server_url.lower()
    
    try:
        if is_gemini:
            # Google Gemini API格式
            headers = {
                "Authorization": f"Bearer {get_config('GPT_API_KEY')}",
                "Content-Type": "application/json"
            }
            
            data = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": prompt}]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 2048,
                    "responseMimeType": "application/json"
                }
            }
            
            response = requests.post(
                gpt_server_url,
                headers=headers,
                json=data,
                verify=True,
                timeout=60
            )
            response.raise_for_status()
            
            # 解析Gemini响应
            response_data = response.json()
            content = response_data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        else:
            # OpenAI API格式
            headers = {
                "Authorization": f"Bearer {get_config('GPT_API_KEY')}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": get_config('GPT_MODEL'),
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            }

            response = requests.post(
                gpt_server_url,
                headers=headers,
                json=data,
                verify=True,
                timeout=60
            )
            response.raise_for_status()
            
            # 解析OpenAI响应
            content = response.json()["choices"][0]["message"]["content"]
        
        content = re.sub(r'\s*\n\s*', ' ', content)
        logger.debug(f"GPT返回内容: {content}")
        if not content:
            logger.warning(f"GPT返回内容为空 prompt长度: {len(prompt)}")
            return None
            
        try:
            # 清理JSON格式
            if content.startswith('```json'):
                content = content[7:-3].strip()
            return json.loads(content.replace('\n', ''))
            
        except json.JSONDecodeError as e:
            logger.error(f"解析GPT响应JSON失败: {e} prompt长度: {len(prompt)}")
            logger.error(content)
            return None
            
    except requests.exceptions.RequestException as e:
        logger.error(f"请求GPT API失败: {e} prompt长度: {len(prompt)}")
        traceback.print_exc()
    except (KeyError, json.JSONDecodeError) as e:
        logger.error(f"处理GPT响应异常: {e} prompt长度: {len(prompt)}")
        traceback.print_exc()
    
    return None

def __clone_repo(url: str) -> Optional[str]:
    """
    克隆Git仓库
    
    参数:
        url: 仓库地址
        
    返回:
        克隆目录路径,失败返回None
    """
    unique_id = hashlib.md5(url.encode()).hexdigest()
    clone_path = Path('/tmp') / unique_id
    
    if clone_path.exists():
        logger.debug(f"使用已存在的仓库克隆: {clone_path}")
        return str(clone_path)
        
    try:
        logger.info(f"克隆仓库: {url}")
        subprocess.run(
            ['git', 'clone', url, str(clone_path)],
            check=True,
            capture_output=True
        )
        
        if clone_path.exists():
            return str(clone_path)
        else:
            logger.error("克隆成功但目录不存在")
            return None
            
    except subprocess.CalledProcessError as e:
        logger.error(f"克隆仓库失败: {e.stderr.decode()}")
        return None

def get_github_poc(github_link: str) -> str:
    """
    获取GitHub仓库中的POC代码
    
    参数:
        github_link: GitHub仓库链接
        
    返回:
        POC代码内容
    """
    try:
        clone_path = __clone_repo(github_link)
        if not clone_path:
            logger.error("克隆仓库失败")
            return ''
            
        outputs = process_path(
            path=clone_path,
            extensions=None,
            include_hidden=False,
            ignore_files_only=False,
            ignore_gitignore=False,
            gitignore_rules=[],
            ignore_patterns=[],
            claude_xml=False,
            markdown=False,
            line_numbers=False
        )
        
        logger.info(f"成功提取POC代码: {len(outputs)} 行")
        return '\n'.join(outputs)
        
    except Exception as e:
        logger.error(f"获取POC代码异常: {e}")
        return ''


def get_template():
    with open('template/report.md', 'r', encoding='utf-8') as file:
        return file.read()

def write_to_markdown(data: Dict, filename: str):
    """
    将内容写入markdown文件
    
    参数:
        data: 内容
        filename: 文件名
    """
    # 确保目录存在
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    template = get_template()
    content = template.format(**data)
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)

def generate_rss_feed(vulnerabilities: List[Dict], title: str = "每日漏洞订阅", description: str = "最新安全漏洞信息") -> str:
    """
    生成RSS格式的漏洞订阅
    
    参数:
        vulnerabilities: 漏洞信息列表
        title: RSS标题
        description: RSS描述
        
    返回:
        RSS格式的XML字符串
    """
    # 设置时区
    import pytz
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz)
    
    # 生成RSS头部
    rss = f'''
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>{title}</title>
        <description>{description}</description>
        <link>http://localhost:8000</link>
        <lastBuildDate>{now.strftime('%a, %d %b %Y %H:%M:%S %z')}</lastBuildDate>
        <generator>VulnWatchdog</generator>
        <language>zh-CN</language>
    '''
    
    # 添加漏洞条目
    for vuln in vulnerabilities:
        cve_id = vuln.get('cve_id', '未知CVE')
        vuln_title = vuln.get('title', '未知漏洞')
        
        # 安全转义标题中的特殊字符
        import html
        title_escaped = html.escape(f"{cve_id}: {vuln_title}")
        
        # 构建内容描述
        severity = vuln.get('severity', '未知')
        published_date = vuln.get('published_date', '未知')
        vuln_desc = vuln.get('description', '无描述')
        reference_url = vuln.get('reference_url', '#')
        
        # 根据严重级别添加颜色标记
        severity_color = "gray"
        if severity.lower() == "critical":
            severity_color = "red"
        elif severity.lower() == "high":
            severity_color = "orange"
        elif severity.lower() == "medium":
            severity_color = "yellow"
        elif severity.lower() == "low":
            severity_color = "green"
        
        description = f"""
<div>
    <p><strong>严重级别:</strong> <span style="color:{severity_color};">{severity}</span></p>
    <p><strong>发布日期:</strong> {published_date}</p>
    <p><strong>漏洞描述:</strong> {html.escape(vuln_desc)}</p>
    <p><strong>参考链接:</strong> <a href="{reference_url}">{reference_url}</a></p>
"""
        
        # 添加相关PoC信息（如果有）
        if vuln.get('poc_info'):
            description += "<h3>相关PoC:</h3><ul>"
            for poc in vuln.get('poc_info', [])[:5]:  # 限制最多显示5个PoC
                repo_name = poc.get('repo', {}).get('name', 'PoC')
                repo_url = poc.get('repo', {}).get('html_url', '#')
                description += f"<li><a href=\"{repo_url}\">{html.escape(repo_name)}</a></li>"
            description += "</ul>"
        
        # 添加来源信息
        source = vuln.get('source', '未知来源')
        description += f"<p><strong>情报来源:</strong> {source}</p></div>"
        
        # 添加到RSS
        pub_date = vuln.get('published_date', now.strftime('%Y-%m-%d'))
        try:
            # 尝试解析发布日期
            if isinstance(pub_date, str):
                pub_date_dt = datetime.strptime(pub_date, '%Y-%m-%d')
            else:
                pub_date_dt = pub_date
            pub_date_dt = tz.localize(pub_date_dt)
        except (ValueError, TypeError):
            pub_date_dt = now
        
        rss += f'''
            <item>
                <title>{title_escaped}</title>
                <description><![CDATA[{description}]]></description>
                <link>{reference_url}</link>
                <guid>{cve_id}</guid>
                <pubDate>{pub_date_dt.strftime('%a, %d %b %Y %H:%M:%S %z')}</pubDate>
            </item>
        '''
    
    # 结束RSS
    rss += '''
    </channel>
</rss>
    '''
    
    return rss


class CVEChecker:
    """
    CVE可用性验证器，通过查询CISA和OSCS数据源验证CVE的存在性
    """
    def __init__(self, proxy: Optional[str] = None):
        """
        初始化CVE验证器
        
        参数:
            proxy: 代理配置
        """
        self.proxy = proxy
        self.session = self._create_session()
        self.cache = {}
        self.cache_expiry = 3600  # 缓存过期时间（秒）
        
    def _create_session(self) -> requests.Session:
        """
        创建并配置请求会话
        """
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # 配置代理
        if self.proxy:
            session.proxies.update({
                'http': self.proxy,
                'https': self.proxy
            })
        
        return session
        
    def verify_cve_availability(self, cve_id: str) -> bool:
        """
        验证CVE ID的可用性，优先检查缓存
        
        参数:
            cve_id: CVE ID
            
        返回:
            是否可用
        """
        # 转换为大写格式
        cve_id = cve_id.upper()
        
        # 检查缓存
        if cve_id in self.cache:
            cached_time, result = self.cache[cve_id]
            if time.time() - cached_time < self.cache_expiry:
                logger.debug(f"从缓存返回CVE验证结果: {cve_id} = {result}")
                return result
        
        # 执行验证
        result = self._verify_cve(cve_id)
        
        # 更新缓存
        self.cache[cve_id] = (time.time(), result)
        
        # 限制缓存大小
        if len(self.cache) > 1000:
            # 删除最旧的缓存项
            oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][0])
            del self.cache[oldest_key]
        
        return result
        
    def _verify_cve(self, cve_id: str) -> bool:
        """
        验证CVE的实际逻辑
        
        优先级: 1. CISA -> 2. OSCS -> 3. GitHub仓库检查
        """
        try:
            # 1. 检查CISA数据源
            if self._check_cisa(cve_id):
                logger.info(f"CVE验证成功 (CISA): {cve_id}")
                return True
                
            # 2. 检查OSCS数据源
            if self._check_oscs(cve_id):
                logger.info(f"CVE验证成功 (OSCS): {cve_id}")
                return True
                
            # 3. 检查GitHub是否有相关PoC仓库
            if self._check_github_cve(cve_id):
                logger.info(f"CVE验证成功 (GitHub): {cve_id}")
                return True
                
            logger.warning(f"所有数据源验证失败: {cve_id}")
            return False
            
        except Exception as e:
            logger.error(f"验证CVE {cve_id} 时发生错误: {e}")
            return False
    
    def _check_cisa(self, cve_id: str) -> bool:
        """
        检查CISA数据源，使用更可靠的API调用方式
        """
        try:
            # 使用CISA的JSON格式API，更可靠且响应更快
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            
            # 获取CISA已知被利用漏洞目录
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            # 检查是否包含该CVE
            for vuln in vulnerabilities:
                if vuln.get('cveID') == cve_id:
                    return True
                    
        except Exception as e:
            logger.debug(f"CISA检查失败: {e}")
            return False
    
    def _check_oscs(self, cve_id: str) -> bool:
        """
        检查OSCS数据源，使用正确的API URL格式
        """
        try:
            # 使用正确的OSCS API URL格式
            url = f"https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{cve_id}"
            
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            # 检查返回状态
            if data.get('code') == 0 and data.get('data'):
                return True
                
        except Exception as e:
            logger.debug(f"OSCS检查失败: {e}")
            return False
            
        return False
    
    def _check_github_cve(self, cve_id: str) -> bool:
        """
        检查GitHub是否有相关PoC仓库
        """
        try:
            url = f"https://api.github.com/search/repositories"
            params = {
                'q': f'{cve_id}+(poc+OR+exploit)+in:name,description',
                'sort': 'updated',
                'order': 'desc',
                'per_page': 5
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            # 处理速率限制
            if response.status_code == 403 and 'rate limit' in response.text.lower():
                logger.warning(f"GitHub API速率限制，跳过GitHub验证")
                return False
                
            response.raise_for_status()
            
            data = response.json()
            # 如果有多个相关仓库，认为CVE可能有效
            return data.get('total_count', 0) >= 3
            
        except Exception as e:
            logger.debug(f"GitHub检查失败: {e}")
            return False
    
    def clear_cache(self):
        """
        清除缓存
        """
        self.cache.clear()
        logger.info("CVE验证缓存已清除")

def get_cve_checker(proxy: Optional[str] = None) -> Any:
    """
    获取CVE检查器实例
    
    参数:
        proxy: 代理配置
        
    返回:
        CVE检查器实例
    """
    return CVEChecker(proxy)


class TaskScheduler:
    """
    定时任务管理器，负责定期执行漏洞检查、验证和更新任务
    """
    def __init__(self):
        """
        初始化定时任务管理器
        """
        self.running = False
        self.scheduler_thread = None
        self.cve_checker = get_cve_checker()
        self.max_workers = 5  # 并发工作线程数
        
    def start(self):
        """
        启动定时任务调度器
        """
        if self.running:
            logger.warning("定时任务调度器已经在运行")
            return
        
        self.running = True
        
        # 设置定时任务
        # 每天凌晨2点执行CVE验证任务
        schedule.every().day.at("02:00").do(self.verify_vulnerabilities)
        
        # 每6小时检查PoC仓库可用性
        schedule.every(6).hours.do(self.check_poc_repositories)
        
        # 每周一上午9点生成报告
        schedule.every().monday.at("09:00").do(self.generate_weekly_report)
        
        # 每小时更新缓存
        schedule.every(1).hour.do(self.update_caches)
        
        # 在新线程中运行调度器
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("定时任务调度器已启动")
        
    def stop(self):
        """
        停止定时任务调度器
        """
        if not self.running:
            logger.warning("定时任务调度器未运行")
            return
        
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        schedule.clear()
        logger.info("定时任务调度器已停止")
        
    def _run_scheduler(self):
        """
        运行调度器的内部方法
        """
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # 每分钟检查一次是否有待执行的任务
            except Exception as e:
                logger.error(f"定时任务调度器异常: {e}")
                time.sleep(60)  # 出错后等待1分钟再继续
        
    def verify_vulnerabilities(self):
        """
        验证所有存储的漏洞信息的可用性
        """
        logger.info("开始执行漏洞验证任务")
        
        try:
            # 这里应该从数据库或文件中获取所有漏洞信息
            # 为简化示例，我们假设这里有一个获取漏洞列表的方法
            vulnerabilities = self._get_all_vulnerabilities()
            
            # 使用线程池并发验证漏洞
            invalid_cves = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # 提交任务到线程池
                future_to_cve = {
                    executor.submit(self.cve_checker.verify_cve_availability, vuln.get('cve_id')): 
                    vuln for vuln in vulnerabilities
                }
                
                # 处理结果
                for future in concurrent.futures.as_completed(future_to_cve):
                    vuln = future_to_cve[future]
                    cve_id = vuln.get('cve_id')
                    
                    try:
                        is_valid = future.result()
                        if not is_valid:
                            invalid_cves.append(cve_id)
                            logger.warning(f"发现无效漏洞: {cve_id}")
                    except Exception as e:
                        logger.error(f"验证漏洞 {cve_id} 时发生异常: {e}")
            
            # 处理无效的CVE
            if invalid_cves:
                logger.warning(f"共发现 {len(invalid_cves)} 个无效漏洞")
                self._handle_invalid_cves(invalid_cves)
            else:
                logger.info("所有漏洞验证通过")
                
        except Exception as e:
            logger.error(f"执行漏洞验证任务时发生异常: {e}")
            traceback.print_exc()
        
    def check_poc_repositories(self):
        """
        检查PoC仓库的可用性
        """
        logger.info("开始执行PoC仓库检查任务")
        
        try:
            # 这里应该从数据库或文件中获取所有PoC仓库信息
            poc_repos = self._get_all_poc_repositories()
            
            unavailable_repos = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # 提交任务到线程池
                future_to_repo = {
                    executor.submit(self._check_repo_availability, repo.get('url')): 
                    repo for repo in poc_repos
                }
                
                # 处理结果
                for future in concurrent.futures.as_completed(future_to_repo):
                    repo = future_to_repo[future]
                    repo_url = repo.get('url')
                    
                    try:
                        is_available = future.result()
                        if not is_available:
                            unavailable_repos.append(repo)
                            logger.warning(f"发现不可用的PoC仓库: {repo_url}")
                    except Exception as e:
                        logger.error(f"检查仓库 {repo_url} 时发生异常: {e}")
            
            # 处理不可用的仓库
            if unavailable_repos:
                logger.warning(f"共发现 {len(unavailable_repos)} 个不可用的PoC仓库")
                self._handle_unavailable_repos(unavailable_repos)
            else:
                logger.info("所有PoC仓库检查通过")
                
        except Exception as e:
            logger.error(f"执行PoC仓库检查任务时发生异常: {e}")
            traceback.print_exc()
        
    def generate_weekly_report(self):
        """
        生成每周漏洞报告
        报告存储在data/WeeklyReport/年份-月份-当月第几周/Weekly_当前日期.md
        """
        logger.info("开始生成每周漏洞报告")
        
        try:
            # 获取当前日期信息
            today = datetime.now()
            current_date_str = today.strftime('%Y-%m-%d')
            year = today.year
            month = today.month
            
            # 计算当月第几周
            first_day = today.replace(day=1)
            week_number = (today.day - 1 + first_day.weekday()) // 7 + 1
            
            # 创建存储目录
            report_dir = f'data/WeeklyReport/{year}-{month:02d}-第{week_number}周'
            os.makedirs(report_dir, exist_ok=True)
            
            # 报告文件路径
            report_file = f'{report_dir}/Weekly_{current_date_str}.md'
            
            # 计算本周的开始和结束日期
            start_of_week = today - timedelta(days=today.weekday())
            end_of_week = start_of_week + timedelta(days=6)
            
            # 获取本周的漏洞数据
            week_vulnerabilities = self._get_vulnerabilities_by_date_range(start_of_week, end_of_week)
            
            # 如果没有数据，从文件系统中收集
            if not week_vulnerabilities:
                week_vulnerabilities = self._collect_vulnerabilities_from_files(start_of_week, end_of_week)
            
            # 按严重级别分类
            by_severity = self._group_vulnerabilities_by_severity(week_vulnerabilities)
            
            # 生成报告内容
            report_content = self._generate_report_content(by_severity, start_of_week, end_of_week)
            
            # 保存报告
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            logger.info(f"每周漏洞报告已生成: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"生成每周漏洞报告时发生异常: {e}")
            traceback.print_exc()
        return None
        
    def _collect_vulnerabilities_from_files(self, start_date, end_date):
        """
        从文件系统中收集指定日期范围内的漏洞数据
        """
        vulnerabilities = []
        year = start_date.year
        
        # 遍历日期范围内的每一天
        current_day = start_date
        while current_day <= end_date:
            date_str = current_day.strftime('%Y-%m-%d')
            date_dir = f'data/markdown/{year}'
            
            if os.path.exists(date_dir):
                for filename in os.listdir(date_dir):
                    if filename.startswith(date_str):
                        file_path = os.path.join(date_dir, filename)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                
                                # 从文件名提取CVE ID
                                cve_id = filename.split('.')[0]
                                
                                # 提取标题和严重程度（如果有）
                                title = cve_id
                                severity = 'unknown'
                                
                                for line in content.split('\n'):
                                    if line.startswith('#'):
                                        title = line.strip('# ')
                                    elif '严重程度' in line:
                                        # 尝试提取严重程度
                                        import re
                                        match = re.search(r'严重程度[:：]\s*(\w+)', line)
                                        if match:
                                            severity = match.group(1).lower()
                                
                                vulnerabilities.append({
                                    'cve_id': cve_id,
                                    'title': title,
                                    'severity': severity,
                                    'published_date': date_str,
                                    'description': content[:200] + '...' if len(content) > 200 else content
                                })
                        except Exception as e:
                            logger.error(f"读取漏洞文件失败 {file_path}: {str(e)}")
            
            current_day += timedelta(days=1)
        
        return vulnerabilities
        
    def update_caches(self):
        """
        更新缓存数据
        """
        try:
            # 清除过期的缓存
            self.cve_checker.clear_cache()
            logger.info("缓存已更新")
            
        except Exception as e:
            logger.error(f"更新缓存时发生异常: {e}")
    
    def _check_repo_availability(self, repo_url: str) -> bool:
        """
        检查单个仓库的可用性
        """
        try:
            # 对于GitHub仓库，我们可以使用HEAD请求检查
            if 'github.com' in repo_url:
                # 转换为API URL以获取更好的响应
                api_url = repo_url.replace('github.com', 'api.github.com/repos').replace('.git', '')
                response = requests.head(api_url, timeout=5, allow_redirects=True)
                return response.status_code == 200
            else:
                # 对于其他仓库，尝试简单的GET请求
                response = requests.head(repo_url, timeout=5, allow_redirects=True)
                return response.status_code == 200
                
        except Exception as e:
            logger.debug(f"检查仓库 {repo_url} 可用性失败: {e}")
            return False
    
    # 以下方法需要在实际实现中根据项目的数据存储方式进行替换
    def _get_all_vulnerabilities(self) -> List[Dict]:
        """
        获取所有漏洞信息
        """
        # 这里应该从数据库或文件中获取所有漏洞
        # 为简化示例，返回空列表
        return []
    
    def _get_all_poc_repositories(self) -> List[Dict]:
        """
        获取所有PoC仓库信息
        """
        # 这里应该从数据库或文件中获取所有PoC仓库
        # 为简化示例，返回空列表
        return []
    
    def _get_vulnerabilities_by_date_range(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """
        获取指定日期范围内的漏洞信息
        """
        # 这里应该从数据库或文件中获取指定日期范围的漏洞
        # 为简化示例，返回空列表
        return []
    
    def _group_vulnerabilities_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """
        按严重级别对漏洞进行分组
        """
        grouped = {'critical': [], 'high': [], 'medium': [], 'low': [], 'unknown': []}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in grouped:
                grouped[severity].append(vuln)
            else:
                grouped['unknown'].append(vuln)
                
        return grouped
    
    def _generate_report_content(self, by_severity: Dict[str, List[Dict]], start_date: datetime, end_date: datetime) -> str:
        """
        生成报告内容
        """
        # 这里应该根据分组数据生成报告内容
        # 为简化示例，返回基本报告结构
        content = f"# 每周漏洞报告\n\n"
        content += f"报告周期: {start_date.strftime('%Y-%m-%d')} 至 {end_date.strftime('%Y-%m-%d')}\n\n"
        
        for severity in ['critical', 'high', 'medium', 'low', 'unknown']:
            vulns = by_severity.get(severity, [])
            if vulns:
                content += f"## {severity.upper()} ({len(vulns)})\n\n"
                for vuln in vulns:
                    cve_id = vuln.get('cve_id', '未知CVE')
                    title = vuln.get('title', '未知标题')
                    content += f"- {cve_id}: {title}\n"
                content += "\n"
                
        return content
    
    def _save_report(self, filename: str, content: str):
        """
        保存报告到文件
        """
        # 保存到reports目录
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            
        with open(os.path.join(reports_dir, filename), 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _handle_invalid_cves(self, invalid_cves: List[str]):
        """
        处理无效的CVE
        """
        # 这里应该实现如何处理无效的CVE，例如从数据库中标记或删除
        pass
    
    def _handle_unavailable_repos(self, unavailable_repos: List[Dict]):
        """
        处理不可用的仓库
        """
        # 这里应该实现如何处理不可用的仓库，例如从数据库中标记或删除
        pass


# 创建全局任务调度器实例
task_scheduler = TaskScheduler()


def start_scheduler():
    """
    启动定时任务调度器
    """
    task_scheduler.start()


def stop_scheduler():
    """
    停止定时任务调度器
    """
    task_scheduler.stop()
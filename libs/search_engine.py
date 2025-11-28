import logging
import re
import requests
import time
import hashlib
import subprocess
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from config import get_config
from libs.files2prompt import process_path
from libs.scheduler import get_cve_checker

logger = logging.getLogger(__name__)

class SearchError(Exception):
    """搜索相关错误的自定义异常"""
    pass

def search_bing(query: str, num_results: int = 5) -> List[Dict]:
    """
    使用Bing搜索引擎进行搜索
    
    参数:
        query: 搜索查询字符串
        num_results: 返回结果数量
        
    返回:
        搜索结果列表，每个结果包含 title, url, content
    """
    if not isinstance(query, str) or not query.strip():
        logger.warning("无效的搜索查询: 为空或不是字符串")
        return []
    
    if not get_config('ENABLE_SEARCH'):
        logger.info(f"搜索功能已禁用，跳过搜索: {query}")
        return []
    
    try:
        # 使用Bing API进行搜索
        # 这里使用duckduckgo_search库的Bing后端
        from duckduckgo_search import DDGS
        
        with DDGS() as ddgs:
            results = []
            # 使用Bing后端，设置中文语言
            for r in ddgs.text(query, max_results=num_results, region='cn-zh', safesearch='off', backend='bing'):
                results.append({
                    'title': r.get('title', ''),
                    'url': r.get('href', ''),
                    'content': r.get('body', '')
                })
            logger.info(f"Bing 搜索到 {len(results)} 条结果")
            return results
    except Exception as e:
        logger.error(f"Bing搜索失败: {e}")
        
    return []


def search_duckduckgo(query: str, num_results: int = 5) -> List[Dict]:
    """
    使用DuckDuckGo搜索引擎进行搜索
    
    参数:
        query: 搜索查询字符串
        num_results: 返回结果数量
        
    返回:
        搜索结果列表，每个结果包含 title, url, content
    """
    if not isinstance(query, str) or not query.strip():
        logger.warning("无效的搜索查询: 为空或不是字符串")
        return []
    
    if not get_config('ENABLE_SEARCH'):
        logger.info(f"搜索功能已禁用，跳过搜索: {query}")
        return []
    
    try:
        # 尝试使用 duckduckgo_search 库
        try:
            from duckduckgo_search import DDGS
            
            with DDGS() as ddgs:
                results = []
                # 添加语言参数，确保搜索结果为中文
                for r in ddgs.text(query, max_results=num_results, region='cn-zh', safesearch='off'):
                    results.append({
                        'title': r.get('title', ''),
                        'url': r.get('href', ''),
                        'content': r.get('body', '')
                    })
                logger.info(f"DuckDuckGo 搜索到 {len(results)} 条结果")
                return results
        except ImportError:
            logger.info("未安装 duckduckgo_search 库，使用基础HTTP请求方式")
            # 回退到基础的 HTML 解析方式
            url = "https://html.duckduckgo.com/html/"
            params = {
                'q': query.strip()
            }
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.post(url, data=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # 简单的HTML解析（这只是一个备选方案，结果可能不如库准确）
                from html.parser import HTMLParser
                
                class DDGParser(HTMLParser):
                    def __init__(self):
                        super().__init__()
                        self.results = []
                        self.current_result = {}
                        self.in_result = False
                        
                    def handle_starttag(self, tag, attrs):
                        attrs_dict = dict(attrs)
                        if tag == 'a' and attrs_dict.get('class') == 'result__a':
                            self.in_result = True
                            self.current_result = {'url': attrs_dict.get('href', '')}
                    
                    def handle_data(self, data):
                        if self.in_result and 'title' not in self.current_result:
                            self.current_result['title'] = data.strip()
                    
                    def handle_endtag(self, tag):
                        if tag == 'a' and self.in_result:
                            self.in_result = False
                            if self.current_result and len(self.results) < num_results:
                                self.current_result['content'] = self.current_result.get('title', '')
                                self.results.append(self.current_result)
                            self.current_result = {}
                
                parser = DDGParser()
                parser.feed(response.text)
                logger.info(f"DuckDuckGo 搜索到 {len(parser.results)} 条结果")
                return parser.results
            
    except Exception as e:
        logger.error(f"DuckDuckGo搜索失败: {e}")
        
    return []


def __clone_repo(url: str) -> Optional[str]:
    """
    克隆Git仓库
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
            
    except subprocess.CalledProcessError as e:
        logger.error(f"克隆仓库失败: {e.stderr.decode()}")
        
    return None

def get_github_poc(github_link: str) -> str:
    """
    获取GitHub仓库中的POC代码
    """
    try:
        clone_path = __clone_repo(github_link)
        if not clone_path:
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
        
        return '\n'.join(outputs)
        
    except Exception as e:
        logger.error(f"获取POC代码异常: {e}")
        return ''

def search_github(query: str, per_page: int = 30, max_retries: int = 3) -> Tuple[set, List[Dict]]:
    """
    搜索GitHub仓库中的CVE信息,并验证CVE可用性
    """
    current_year = datetime.now().year
    re_cve = re.compile(r'(?i)CVE-(\d{4})-(\d{4,7})')
    
    cve_checker = get_cve_checker()
    
    enhanced_query = f"{query}+(poc+OR+exploit)+NOT+test"
    url = f"https://api.github.com/search/repositories?q={enhanced_query}&sort=updated&order=desc&per_page={per_page}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    
    github_token = get_config('GITHUB_TOKEN')
    if github_token:
        headers['Authorization'] = f"token {github_token}"
    
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        items = resp.json().get('items', [])
    except Exception as e:
        logger.error(f"GitHub搜索失败: {e}")
        return set(), []

    logger.info(f"GitHub搜索到 {len(items)} 个仓库")
    
    cve_list = set()
    repo_list = []
    cve_to_verify = {}
    
    for item in items:
        try:
            name = item.get('name', '')
            desc = item.get('description', '')
            
            content_to_search = f"{name} {desc}"
            cve_matches = re_cve.finditer(content_to_search)
            
            found_cves = set()
            for match in cve_matches:
                cve_id = match.group(0).upper()
                cve_year = int(match.group(1))
                
                if cve_year > current_year or cve_year < 1999:
                    continue
                
                found_cves.add(cve_id)
            
            for cve_id in found_cves:
                if cve_id not in cve_to_verify:
                    cve_to_verify[cve_id] = []
                cve_to_verify[cve_id].append(item)
                
        except Exception as e:
            logger.error(f"处理仓库信息异常: {e}")
            continue
    
    for cve_id, repos in cve_to_verify.items():
        try:
            if cve_checker.verify_cve_availability(cve_id):
                cve_list.add(cve_id)
                for repo in repos:
                    repo_list.append({'cve_id': cve_id, 'repo': repo})
            
            time.sleep(0.5)
            
        except Exception as e:
            logger.error(f"验证CVE {cve_id} 可用性异常: {e}")
    
    return cve_list, repo_list

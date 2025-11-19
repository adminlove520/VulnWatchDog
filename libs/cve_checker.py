import requests
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

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
        
    def clear_cache(self):
        """
        清除缓存
        """
        self.cache.clear()
        logger.info("CVE验证缓存已清除")

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
        
    def check_cve_validity(self, cve_id: str) -> tuple[bool, Optional[str]]:
        """
        检查CVE有效性（兼容方法）
        
        参数:
            cve_id: CVE ID
            
        返回:
            (是否有效, 数据源)的元组
        """
        is_valid = self.verify_cve_availability(cve_id)
        # 简单返回，不追踪具体来源（为了兼容性）
        source = "CISA/OSCS/GitHub" if is_valid else None
        return is_valid, source
        
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
            # 检查返回的漏洞数据是否有效
            if data and isinstance(data, dict):
                # 检查是否包含cve_id字段且匹配
                if data.get('cve_id') == cve_id:
                    return True
                # 或者检查是否包含关键信息字段
                elif data.get('title') or data.get('description') or data.get('cvss_score') is not None:
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

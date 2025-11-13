import requests
import logging
import time
import re
from typing import Dict, Optional, List
from libs.oscs import OSCSAPI
from libs.cisa import CISAAPI

logger = logging.getLogger(__name__)

class CISAOSCSChecker:
    """
    CISA和OSCS漏洞检查器
    用于验证漏洞是否真实存在于CISA和OSCS数据库中
    """
    
    def __init__(self, proxies: Optional[Dict[str, str]] = None):
        """
        初始化检查器
        
        Args:
            proxies: 代理设置
        """
        self.proxies = proxies
        # 初始化API客户端
        self.oscs_api = OSCSAPI()
        self.cisa_api = CISAAPI()
    
    def check_cisa(self, cve_id: str) -> bool:
        """
        从CISA数据库检查CVE是否存在
        使用CISA已知被利用漏洞目录
        
        Args:
            cve_id: CVE编号
            
        Returns:
            bool: CVE是否存在
        """
        try:
            # 使用CISA API客户端获取漏洞信息
            vuln_info = self.cisa_api.get_vulnerability_by_cve(cve_id)
            if vuln_info:
                logger.info(f"CVE {cve_id} 在CISA已知被利用漏洞目录中找到")
                return True
            
            logger.warning(f"CVE {cve_id} 在CISA已知被利用漏洞目录中未找到")
            return False
            
        except Exception as e:
            logger.error(f"查询CISA数据库时出错: {str(e)}")
            return False
    
    def check_oscs(self, cve_id: str) -> bool:
        """
        从OSCS数据库检查CVE是否存在
        使用新的OSCS API格式
        
        Args:
            cve_id: CVE编号
            
        Returns:
            bool: CVE是否存在
        """
        try:
            # 使用OSCS API客户端获取漏洞信息
            vuln_info = self.oscs_api.get_cve_info(cve_id)
            if vuln_info:
                logger.info(f"CVE {cve_id} 在OSCS数据库中找到")
                return True
            
            logger.warning(f"CVE {cve_id} 在OSCS数据库中未找到")
            return False
            
        except Exception as e:
            logger.error(f"查询OSCS数据库时出错: {str(e)}")
            return False
    
    def check_github_poc(self, cve_id: str) -> bool:
        """
        检查GitHub上是否存在相关PoC仓库
        
        Args:
            cve_id: CVE编号
            
        Returns:
            bool: 是否存在PoC仓库
        """
        try:
            # GitHub搜索API
            url = f"https://api.github.com/search/repositories?q={cve_id}+poc+OR+exploit"
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(
                url,
                headers=headers,
                proxies=self.proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # 如果有结果，返回True
                if data.get('total_count', 0) > 0:
                    logger.info(f"CVE {cve_id} 在GitHub上找到相关PoC仓库")
                    return True
            
            logger.warning(f"CVE {cve_id} 在GitHub上未找到相关PoC仓库")
            return False
            
        except Exception as e:
            logger.error(f"查询GitHub PoC仓库时出错: {str(e)}")
            return False
    
    def verify_cve_availability(self, cve_id: str) -> bool:
        """
        验证CVE的可用性
        优先级: CISA/NVD > OSCS > GitHub PoC
        
        Args:
            cve_id: CVE编号
            
        Returns:
            bool: CVE是否可用
        """
        logger.info(f"开始验证CVE {cve_id} 的可用性")
        
        # 1. 首先检查CISA/NVD
        if self.check_cisa(cve_id):
            return True
        
        # 2. 如果CISA没有，则检查OSCS
        if self.check_oscs(cve_id):
            return True
        
        # 3. 如果官方数据库都没有，则检查GitHub上的PoC仓库
        if self.check_github_poc(cve_id):
            return True
        
        # 4. 所有渠道都没有找到，则认为CVE不可用
        logger.warning(f"CVE {cve_id} 在所有验证渠道中都未找到，认为其不可用")
        return False

# 单例实例
_cve_checker = None

def get_cve_checker(proxy: Optional[str] = None) -> CISAOSCSChecker:
    """
    获取CVE检查器单例
    
    Args:
        proxy: 代理地址
        
    Returns:
        CISAOSCSChecker: 检查器实例
    """
    global _cve_checker
    if _cve_checker is None:
        _cve_checker = CISAOSCSChecker(proxy)
    return _cve_checker
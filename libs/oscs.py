#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSCS API 工具模块
用于从 OSCS (Open Source Cyber Security) 平台获取漏洞信息
"""
import os
import json
import logging
import requests
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class OSCSAPI:
    """
    OSCS API 客户端类
    """
    
    def __init__(self, timeout: int = 30):
        """
        初始化 OSCS API 客户端
        
        Args:
            timeout: 请求超时时间（秒）
        """
        self.base_url = "https://www.oscs1024.com/oscs/v1"
        self.timeout = timeout
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "VulnWatchdog/1.0"
        }
    
    def get_vulnerability_info(self, vuln_id: str) -> Optional[Dict]:
        """
        获取单个漏洞的详细信息
        支持通过 CVE ID 或 MPS ID 查询
        
        Args:
            vuln_id: 漏洞标识符（CVE ID 或 MPS ID）
            
        Returns:
            漏洞信息字典，失败时返回 None
        """
        try:
            # 构建请求 URL
            url = f"{self.base_url}/vdb/vuln_info/{vuln_id}"
            
            # 发送请求
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            # 检查响应状态
            response.raise_for_status()
            
            # 解析响应数据
            data = response.json()
            
            if data.get("code") == 0:
                return data.get("data", {})
            else:
                logger.error(f"OSCS API 返回错误: {data.get('msg', 'Unknown error')}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"请求 OSCS API 失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析 OSCS API 响应失败: {str(e)}")
        except Exception as e:
            logger.error(f"获取漏洞信息时出错: {str(e)}")
        
        return None
    
    def get_cve_info(self, cve_id: str) -> Optional[Dict]:
        """
        通过 CVE ID 获取漏洞信息
        
        Args:
            cve_id: CVE 标识符
            
        Returns:
            漏洞信息字典，失败时返回 None
        """
        return self.get_vulnerability_info(cve_id)
    
    def get_mps_info(self, mps_id: str) -> Optional[Dict]:
        """
        通过 MPS ID 获取漏洞信息
        
        Args:
            mps_id: MPS 标识符
            
        Returns:
            漏洞信息字典，失败时返回 None
        """
        return self.get_vulnerability_info(mps_id)
    
    def search_vulnerabilities(self, keyword: str, page: int = 1, page_size: int = 20) -> Optional[List[Dict]]:
        """
        搜索漏洞
        
        Args:
            keyword: 搜索关键词
            page: 页码
            page_size: 每页大小
            
        Returns:
            漏洞列表，失败时返回 None
        """
        try:
            url = f"{self.base_url}/vdb/search"
            
            payload = {
                "keyword": keyword,
                "page": page,
                "page_size": page_size
            }
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            if data.get("code") == 0:
                return data.get("data", {}).get("list", [])
            else:
                logger.error(f"OSCS API 返回错误: {data.get('msg', 'Unknown error')}")
                return None
                
        except Exception as e:
            logger.error(f"搜索漏洞时出错: {str(e)}")
        
        return None
    
    def get_recent_vulnerabilities(self, days: int = 7) -> Optional[List[Dict]]:
        """
        获取最近几天的漏洞信息
        
        Args:
            days: 天数
            
        Returns:
            漏洞列表，失败时返回 None
        """
        try:
            url = f"{self.base_url}/vdb/recent"
            
            payload = {
                "days": days
            }
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            if data.get("code") == 0:
                return data.get("data", [])
            else:
                logger.error(f"OSCS API 返回错误: {data.get('msg', 'Unknown error')}")
                return None
                
        except Exception as e:
            logger.error(f"获取最近漏洞时出错: {str(e)}")
        
        return None
    
    def get_vulnerability_by_product(self, product: str, version: Optional[str] = None) -> Optional[List[Dict]]:
        """
        根据产品名称和版本获取相关漏洞
        
        Args:
            product: 产品名称
            version: 产品版本（可选）
            
        Returns:
            漏洞列表，失败时返回 None
        """
        try:
            url = f"{self.base_url}/vdb/product"
            
            payload = {
                "product": product
            }
            
            if version:
                payload["version"] = version
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            if data.get("code") == 0:
                return data.get("data", [])
            else:
                logger.error(f"OSCS API 返回错误: {data.get('msg', 'Unknown error')}")
                return None
                
        except Exception as e:
            logger.error(f"获取产品漏洞时出错: {str(e)}")
        
        return None


def format_vulnerability_data(vuln_data: Dict) -> Dict:
    """
    格式化漏洞数据，统一输出格式
    
    Args:
        vuln_data: OSCS 返回的原始漏洞数据
        
    Returns:
        格式化后的漏洞数据字典
    """
    formatted = {
        "id": vuln_data.get("id", ""),
        "title": vuln_data.get("title", ""),
        "description": vuln_data.get("detail", ""),
        "cve_id": vuln_data.get("cve", ""),
        "mps_id": vuln_data.get("mps_id", ""),
        "severity": vuln_data.get("severity", ""),
        "published_date": vuln_data.get("pub_date", ""),
        "updated_date": vuln_data.get("updated_at", ""),
        "affected_products": [],
        "references": [],
        "source": "OSCS"
    }
    
    # 处理影响产品
    affected_products = vuln_data.get("affected_products", [])
    if isinstance(affected_products, list):
        formatted["affected_products"] = affected_products
    elif isinstance(affected_products, str):
        formatted["affected_products"] = [affected_products]
    
    # 处理参考链接
    references = vuln_data.get("reference", [])
    if isinstance(references, list):
        formatted["references"] = references
    elif isinstance(references, str):
        formatted["references"] = [references]
    
    # 处理 CVSS 评分
    formatted["cvss_score"] = vuln_data.get("cvss_score", None)
    formatted["cvss_vector"] = vuln_data.get("cvss_vector", "")
    
    return formatted


# 创建全局实例
def get_oscs_api() -> OSCSAPI:
    """
    获取 OSCS API 实例
    
    Returns:
        OSCSAPI 实例
    """
    return OSCSAPI()
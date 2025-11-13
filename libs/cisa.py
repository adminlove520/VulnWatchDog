#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISA API 工具模块
用于从 CISA (Cybersecurity and Infrastructure Security Agency) 获取漏洞信息
"""
import os
import json
import logging
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CISAAPI:
    """
    CISA API 客户端类
    """
    
    def __init__(self, timeout: int = 30):
        """
        初始化 CISA API 客户端
        
        Args:
            timeout: 请求超时时间（秒）
        """
        self.base_url = "https://api.cisa.gov"
        self.timeout = timeout
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "VulnWatchdog/1.0",
            "Accept": "application/json"
        }
    
    def get_known_exploited_vulnerabilities(self, last_added_days: Optional[int] = None) -> Optional[List[Dict]]:
        """
        获取 CISA 已知被利用的漏洞列表
        
        Args:
            last_added_days: 可选，获取最近添加的漏洞天数
            
        Returns:
            漏洞列表，失败时返回 None
        """
        try:
            url = f"{self.base_url}/known-exploited-vulnerabilities/vulnerabilities.json"
            
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            # 如果指定了天数，过滤最近添加的漏洞
            if last_added_days:
                cutoff_date = datetime.now() - timedelta(days=last_added_days)
                filtered_vulnerabilities = []
                
                for vuln in vulnerabilities:
                    if "dateAdded" in vuln:
                        try:
                            added_date = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d")
                            if added_date >= cutoff_date:
                                filtered_vulnerabilities.append(vuln)
                        except ValueError:
                            logger.warning(f"无法解析日期格式: {vuln['dateAdded']}")
                
                return filtered_vulnerabilities
            
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            logger.error(f"请求 CISA API 失败: {str(e)}")
        except json.JSONDecodeError as e:
            logger.error(f"解析 CISA API 响应失败: {str(e)}")
        except Exception as e:
            logger.error(f"获取已知被利用漏洞时出错: {str(e)}")
        
        return None
    
    def get_vulnerability_by_cve(self, cve_id: str) -> Optional[Dict]:
        """
        通过 CVE ID 获取漏洞信息
        
        Args:
            cve_id: CVE 标识符
            
        Returns:
            漏洞信息字典，失败时返回 None
        """
        try:
            url = f"{self.base_url}/known-exploited-vulnerabilities/vulnerabilities.json"
            
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            # 查找特定的 CVE
            for vuln in vulnerabilities:
                if vuln.get("cveID") == cve_id:
                    return vuln
            
            logger.info(f"未找到 CVE: {cve_id}")
            return None
            
        except Exception as e:
            logger.error(f"获取 CVE 信息时出错: {str(e)}")
        
        return None
    
    def search_vulnerabilities(self, keyword: str) -> Optional[List[Dict]]:
        """
        搜索漏洞
        
        Args:
            keyword: 搜索关键词
            
        Returns:
            匹配的漏洞列表，失败时返回 None
        """
        try:
            all_vulnerabilities = self.get_known_exploited_vulnerabilities()
            
            if not all_vulnerabilities:
                return None
            
            # 简单的关键词搜索
            keyword_lower = keyword.lower()
            matched_vulnerabilities = []
            
            for vuln in all_vulnerabilities:
                # 在多个字段中搜索关键词
                search_fields = [
                    vuln.get("cveID", ""),
                    vuln.get("vendorProject", ""),
                    vuln.get("product", ""),
                    vuln.get("vulnerabilityName", ""),
                    vuln.get("shortDescription", ""),
                    vuln.get("requiredAction", "")
                ]
                
                for field in search_fields:
                    if keyword_lower in str(field).lower():
                        matched_vulnerabilities.append(vuln)
                        break
            
            return matched_vulnerabilities
            
        except Exception as e:
            logger.error(f"搜索漏洞时出错: {str(e)}")
        
        return None
    
    def get_vulnerabilities_by_vendor(self, vendor_name: str) -> Optional[List[Dict]]:
        """
        根据厂商名称获取相关漏洞
        
        Args:
            vendor_name: 厂商名称
            
        Returns:
            漏洞列表，失败时返回 None
        """
        try:
            all_vulnerabilities = self.get_known_exploited_vulnerabilities()
            
            if not all_vulnerabilities:
                return None
            
            # 过滤特定厂商的漏洞
            vendor_lower = vendor_name.lower()
            vendor_vulnerabilities = []
            
            for vuln in all_vulnerabilities:
                vendor = vuln.get("vendorProject", "").lower()
                if vendor_lower in vendor:
                    vendor_vulnerabilities.append(vuln)
            
            return vendor_vulnerabilities
            
        except Exception as e:
            logger.error(f"获取厂商漏洞时出错: {str(e)}")
        
        return None
    
    def get_vulnerabilities_by_product(self, product_name: str) -> Optional[List[Dict]]:
        """
        根据产品名称获取相关漏洞
        
        Args:
            product_name: 产品名称
            
        Returns:
            漏洞列表，失败时返回 None
        """
        try:
            all_vulnerabilities = self.get_known_exploited_vulnerabilities()
            
            if not all_vulnerabilities:
                return None
            
            # 过滤特定产品的漏洞
            product_lower = product_name.lower()
            product_vulnerabilities = []
            
            for vuln in all_vulnerabilities:
                product = vuln.get("product", "").lower()
                if product_lower in product:
                    product_vulnerabilities.append(vuln)
            
            return product_vulnerabilities
            
        except Exception as e:
            logger.error(f"获取产品漏洞时出错: {str(e)}")
        
        return None
    
    def get_vulnerabilities_by_date_range(self, start_date: str, end_date: str) -> Optional[List[Dict]]:
        """
        根据日期范围获取漏洞
        
        Args:
            start_date: 开始日期 (格式: YYYY-MM-DD)
            end_date: 结束日期 (格式: YYYY-MM-DD)
            
        Returns:
            漏洞列表，失败时返回 None
        """
        try:
            # 解析日期
            start = datetime.strptime(start_date, "%Y-%m-%d")
            end = datetime.strptime(end_date, "%Y-%m-%d")
            
            all_vulnerabilities = self.get_known_exploited_vulnerabilities()
            
            if not all_vulnerabilities:
                return None
            
            # 过滤日期范围内的漏洞
            date_range_vulnerabilities = []
            
            for vuln in all_vulnerabilities:
                if "dateAdded" in vuln:
                    try:
                        added_date = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d")
                        if start <= added_date <= end:
                            date_range_vulnerabilities.append(vuln)
                    except ValueError:
                        logger.warning(f"无法解析日期格式: {vuln['dateAdded']}")
            
            return date_range_vulnerabilities
            
        except ValueError as e:
            logger.error(f"日期格式错误: {str(e)}")
        except Exception as e:
            logger.error(f"获取日期范围漏洞时出错: {str(e)}")
        
        return None


def format_cisa_vulnerability(vuln_data: Dict) -> Dict:
    """
    格式化 CISA 漏洞数据，统一输出格式
    
    Args:
        vuln_data: CISA 返回的原始漏洞数据
        
    Returns:
        格式化后的漏洞数据字典
    """
    formatted = {
        "id": vuln_data.get("cveID", ""),
        "title": vuln_data.get("vulnerabilityName", ""),
        "description": vuln_data.get("shortDescription", ""),
        "cve_id": vuln_data.get("cveID", ""),
        "vendor": vuln_data.get("vendorProject", ""),
        "product": vuln_data.get("product", ""),
        "published_date": vuln_data.get("dateAdded", ""),
        "due_date": vuln_data.get("requiredActionDueDate", ""),
        "required_action": vuln_data.get("requiredAction", ""),
        "known_ransomware_campaign_use": vuln_data.get("knownRansomwareCampaignUse", "Unknown"),
        "references": [vuln_data.get("notes", "")] if vuln_data.get("notes") else [],
        "source": "CISA"
    }
    
    # 构建参考 URL
    if formatted["cve_id"]:
        formatted["references"].append(f"https://nvd.nist.gov/vuln/detail/{formatted['cve_id']}")
        formatted["references"].append(f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    
    # 去除空引用
    formatted["references"] = [ref for ref in formatted["references"] if ref]
    
    return formatted


def get_cisa_api() -> CISAAPI:
    """
    获取 CISA API 实例
    
    Returns:
        CISAAPI 实例
    """
    return CISAAPI()
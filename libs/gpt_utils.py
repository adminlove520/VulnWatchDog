import logging
import json
import requests
import time
import traceback
from typing import Dict, Any, Optional
from config import get_config

logger = logging.getLogger(__name__)


def get_cve_info(cve_id: str) -> Dict[str, Any]:
    """
    获取CVE的详细信息，从多个数据源收集数据
    
    参数:
        cve_id: CVE编号
    
    返回:
        包含CVE详细信息的字典
    """
    config = get_config()
    cve_info = {
        "cve_id": cve_id,
        "sources": [],
        "descriptions": [],
        "published_date": None,
        "last_modified_date": None,
        "cvss_score": None,
        "severity": None,
        "references": []
    }
    
    try:
        # 从NVD获取信息
        nvd_data = _fetch_from_nvd(cve_id)
        if nvd_data:
            cve_info["sources"].append("NVD")
            if "descriptions" in nvd_data:
                for desc in nvd_data["descriptions"]:
                    if desc.get("lang") == "en":
                        cve_info["descriptions"].append(desc.get("value", ""))
            cve_info["published_date"] = nvd_data.get("published", None)
            cve_info["last_modified_date"] = nvd_data.get("lastModified", None)
            
            # 获取CVSS评分
            if "metrics" in nvd_data and "cvssMetricV31" in nvd_data["metrics"]:
                cvss_data = nvd_data["metrics"]["cvssMetricV31"][0]
                cve_info["cvss_score"] = cvss_data.get("cvssData", {}).get("baseScore", None)
                cve_info["severity"] = cvss_data.get("cvssData", {}).get("baseSeverity", None)
            
            # 获取参考链接
            if "references" in nvd_data:
                for ref in nvd_data["references"]:
                    cve_info["references"].extend(ref.get("url", []))
        
        # 从CISA获取信息
        cisa_data = _fetch_from_cisa(cve_id)
        if cisa_data:
            cve_info["sources"].append("CISA")
            # 合并CISA的信息
            if "known_ransomware_campaign_use" in cisa_data:
                cve_info["ransomware_related"] = cisa_data["known_ransomware_campaign_use"]
        
        # 从OSCS获取信息
        oscs_data = _fetch_from_oscs(cve_id)
        if oscs_data:
            cve_info["sources"].append("OSCS")
            # 合并OSCS的信息
            if "title" in oscs_data:
                cve_info["descriptions"].append(f"标题: {oscs_data['title']}")
    
    except Exception as e:
        logger.error(f"获取CVE {cve_id} 信息时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return cve_info


def _fetch_from_nvd(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    从NVD获取CVE信息
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        if "vulnerabilities" in data and data["vulnerabilities"]:
            return data["vulnerabilities"][0].get("cve", {})
    except Exception as e:
        logger.error(f"从NVD获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def _fetch_from_cisa(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    从CISA获取CVE信息
    """
    try:
        url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return vuln
    except Exception as e:
        logger.error(f"从CISA获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def _fetch_from_oscs(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    从OSCS获取CVE信息
    """
    try:
        url = f"https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{cve_id}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"从OSCS获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def ask_gpt(prompt: str) -> Optional[Dict[str, Any]]:
    """
    调用Gemini API进行分析
    
    参数:
        prompt: 要发送给Gemini的提示词
    
    返回:
        Gemini的响应结果（JSON格式解析后的字典）或None
    """
    config = get_config()
    api_key = config.get("gemini", {}).get("api_key")
    model = config.get("gemini", {}).get("model", "models/gemini-1.5-flash-latest")
    
    if not api_key:
        logger.warning("未配置Gemini API密钥，无法使用Gemini分析功能")
        return None
    
    try:
        # 使用Gemini API
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        
        headers = {
            "Content-Type": "application/json"
        }
        
        data = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": "你是一个专业的网络安全分析师，擅长分析CVE漏洞信息。请严格按照要求的JSON格式输出结果。"
                        }
                    ]
                },
                {
                    "parts": [
                        {
                            "text": prompt
                        }
import logging
import json
import requests
import time
import traceback
from typing import Dict, Any, Optional
from config import get_config

logger = logging.getLogger(__name__)


def get_cve_info(cve_id: str) -> Dict[str, Any]:
    """
    获取CVE的详细信息，从多个数据源收集数据
    
    参数:
        cve_id: CVE编号
    
    返回:
        包含CVE详细信息的字典
    """
    config = get_config()
    cve_info = {
        "cve_id": cve_id,
        "sources": [],
        "descriptions": [],
        "published_date": None,
        "last_modified_date": None,
        "cvss_score": None,
        "severity": None,
        "references": []
    }
    
    try:
        # 从NVD获取信息
        nvd_data = _fetch_from_nvd(cve_id)
        if nvd_data:
            cve_info["sources"].append("NVD")
            if "descriptions" in nvd_data:
                for desc in nvd_data["descriptions"]:
                    if desc.get("lang") == "en":
                        cve_info["descriptions"].append(desc.get("value", ""))
            cve_info["published_date"] = nvd_data.get("published", None)
            cve_info["last_modified_date"] = nvd_data.get("lastModified", None)
            
            # 获取CVSS评分
            if "metrics" in nvd_data and "cvssMetricV31" in nvd_data["metrics"]:
                cvss_data = nvd_data["metrics"]["cvssMetricV31"][0]
                cve_info["cvss_score"] = cvss_data.get("cvssData", {}).get("baseScore", None)
                cve_info["severity"] = cvss_data.get("cvssData", {}).get("baseSeverity", None)
            
            # 获取参考链接
            if "references" in nvd_data:
                for ref in nvd_data["references"]:
                    cve_info["references"].extend(ref.get("url", []))
        
        # 从CISA获取信息
        cisa_data = _fetch_from_cisa(cve_id)
        if cisa_data:
            cve_info["sources"].append("CISA")
            # 合并CISA的信息
            if "known_ransomware_campaign_use" in cisa_data:
                cve_info["ransomware_related"] = cisa_data["known_ransomware_campaign_use"]
        
        # 从OSCS获取信息
        oscs_data = _fetch_from_oscs(cve_id)
        if oscs_data:
            cve_info["sources"].append("OSCS")
            # 合并OSCS的信息
            if "title" in oscs_data:
                cve_info["descriptions"].append(f"标题: {oscs_data['title']}")
    
    except Exception as e:
        logger.error(f"获取CVE {cve_id} 信息时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return cve_info


def _fetch_from_nvd(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    从NVD获取CVE信息
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        if "vulnerabilities" in data and data["vulnerabilities"]:
            return data["vulnerabilities"][0].get("cve", {})
    except Exception as e:
        logger.error(f"从NVD获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def _fetch_from_cisa(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    从CISA获取CVE信息
    """
    try:
        url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return vuln
    except Exception as e:
        logger.error(f"从CISA获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def _fetch_from_oscs(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    从OSCS获取CVE信息
    """
    try:
        url = f"https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{cve_id}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"从OSCS获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def ask_gpt(prompt: str) -> Optional[Dict[str, Any]]:
    """
    调用Gemini API进行分析
    
    参数:
        prompt: 要发送给Gemini的提示词
    
    返回:
        Gemini的响应结果（JSON格式解析后的字典）或None
    """
    config = get_config()
    api_key = config.get("gemini", {}).get("api_key")
    model = config.get("gemini", {}).get("model", "models/gemini-1.5-flash-latest")
    
    if not api_key:
        logger.warning("未配置Gemini API密钥，无法使用Gemini分析功能")
        return None
    
    try:
        # 使用Gemini API
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        
        headers = {
            "Content-Type": "application/json"
        }
        
        data = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": "你是一个专业的网络安全分析师，擅长分析CVE漏洞信息。请严格按照要求的JSON格式输出结果。"
                        }
                    ]
                },
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }
        
        # 指数退避重试逻辑
        max_retries = 3
        response = None
        
        for attempt in range(max_retries):
            response = requests.post(
                url,
                headers=headers,
                json=data,
                timeout=60
            )
            
            # 处理429速率限制 - 指数退避
            if response.status_code == 429:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 10  # 10s, 20s, 40s
                    logger.warning(f"Gemini API速率限制(429)，等待{wait_time}秒后第{attempt+2}次重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error("429错误：已达最大重试次数")
                    break
            
            # 处理400错误 - 记录详细信息
            if response.status_code == 400:
                logger.error(f"Gemini API请求错误(400) - 尝试{attempt+1}/{max_retries}")
                logger.error(f"当前模型: {model}")
                logger.debug(f"请求数据: {json.dumps(data, ensure_ascii=False)[:500]}")
                if attempt < max_retries - 1:
                    time.sleep(5)  # 等待5秒后重试
                    continue
                else:
                    break
            
            # 2xx成功
            if 200 <= response.status_code < 300:
                break
            
            # 其他错误
            if attempt < max_retries - 1:
                logger.warning(f"请求失败(状态码{response.status_code})，5秒后重试...")
                time.sleep(5)
            else:
                break
        
        response.raise_for_status()
        result = response.json()
        
        # 解析Gemini响应格式
        if ("candidates" in result and result["candidates"] and 
            "content" in result["candidates"][0] and 
            "parts" in result["candidates"][0]["content"] and 
            result["candidates"][0]["content"]["parts"]):
            
            content = result["candidates"][0]["content"]["parts"][0].get("text", "")
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                logger.error(f"Gemini返回的内容不是有效的JSON格式: {content}")
                # 尝试提取JSON部分
                import re
                json_match = re.search(r'\{[^}]*\}', content)
                if json_match:
                    try:
                        return json.loads(json_match.group())
                    except:
                        pass
    
    except Exception as e:
        logger.error(f"调用Gemini API时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return None
import logging
import json
import time
import traceback
import os
import re
from typing import Dict, Any, Optional
from config import get_config

logger = logging.getLogger(__name__)


def get_cve_info(cve_id: str) -> Dict[str, Any]:
    """获取CVE的详细信息，从多个数据源收集数据"""
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
        nvd_data = _fetch_from_nvd(cve_id)
        if nvd_data:
            cve_info["sources"].append("NVD")
            if "descriptions" in nvd_data:
                for desc in nvd_data["descriptions"]:
                    if desc.get("lang") == "en":
                        cve_info["descriptions"].append(desc.get("value", ""))
            cve_info["published_date"] = nvd_data.get("published", None)
            cve_info["last_modified_date"] = nvd_data.get("lastModified", None)
            
            if "metrics" in nvd_data and "cvssMetricV31" in nvd_data["metrics"]:
                cvss_data = nvd_data["metrics"]["cvssMetricV31"][0]
                cve_info["cvss_score"] = cvss_data.get("cvssData", {}).get("baseScore", None)
                cve_info["severity"] = cvss_data.get("cvssData", {}).get("baseSeverity", None)
            
            if "references" in nvd_data:
                for ref in nvd_data["references"]:
                    cve_info["references"].extend(ref.get("url", []))
        
        cisa_data = _fetch_from_cisa(cve_id)
        if cisa_data:
            cve_info["sources"].append("CISA")
            if "known_ransomware_campaign_use" in cisa_data:
                cve_info["ransomware_related"] = cisa_data["known_ransomware_campaign_use"]
        
        oscs_data = _fetch_from_oscs(cve_id)
        if oscs_data:
            cve_info["sources"].append("OSCS")
            if "title" in oscs_data:
                cve_info["descriptions"].append(f"标题: {oscs_data['title']}")
    
    except Exception as e:
        logger.error(f"获取CVE {cve_id} 信息时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return cve_info


def _fetch_from_nvd(cve_id: str) -> Optional[Dict[str, Any]]:
    """从NVD获取CVE信息"""
    try:
        import requests
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
    """从CISA获取CVE信息"""
    try:
        import requests
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
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
    """从OSCS获取CVE信息"""
    try:
        import requests
        url = f"https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{cve_id}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"从OSCS获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def _parse_json_response(text: str) -> Optional[Dict[str, Any]]:
    """解析JSON响应，处理各种格式问题"""
    try:
        clean_text = text.strip()
        if clean_text.startswith('```json'):
            clean_text = clean_text[7:].strip()
        elif clean_text.startswith('```'):
            clean_text = clean_text[3:].strip()
        if clean_text.endswith('```'):
            clean_text = clean_text[:-3].strip()
        
        clean_text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', clean_text)
        clean_text = re.sub(r'[\u200b-\u200f\ufeff]', '', clean_text)
        clean_text = re.sub(r'\r\n?', '\n', clean_text)
        clean_text = re.sub(r' +', ' ', clean_text)
        clean_text = re.sub(r'^ +| +$', '', clean_text, flags=re.MULTILINE)
        
        return json.loads(clean_text)
    except json.JSONDecodeError:
        json_match = re.search(r'\{[\s\S]*\}', clean_text, re.DOTALL)
        if json_match:
            try:
                extracted = json_match.group()
                extracted = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', extracted)
                extracted = re.sub(r'\s+', ' ', extracted)
                return json.loads(extracted)
            except:
                pass
    return None


def _call_minimax(prompt: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    调用MiniMax API进行分析
    
    MiniMax API endpoint: https://api.minimax.chat/v1/text/chatcompletion_v2
    必需 headers: group_id
    """
    api_key = config.get("api_key")
    model = config.get("model", "MiniMax-M2.7")
    group_id = config.get("group_id") or os.getenv("MINIMAX_GROUP_ID")
    
    if not api_key:
        logger.warning("未配置MiniMax API密钥")
        return None
    
    if not group_id:
        logger.warning("未配置MiniMax GROUP_ID")
        return None
    
    try:
        import requests
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "group_id": group_id
        }
        
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "你是一个专业的网络安全分析师，擅长分析CVE漏洞信息。请严格按照要求的JSON格式输出结果。"
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    "https://api.minimax.chat/v1/text/chatcompletion_v2",
                    headers=headers,
                    json=payload,
                    timeout=60
                )
                
                if response.status_code == 429:
                    if attempt < max_retries - 1:
                        wait_time = (2 ** attempt) * 15
                        logger.warning(f"MiniMax API速率限制，等待{wait_time}秒后重试...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error("MiniMax API速率限制：已达最大重试次数")
                        return None
                
                if response.status_code != 200:
                    logger.error(f"MiniMax API返回错误: {response.status_code} - {response.text[:500]}")
                    return None
                
                response_data = response.json()
                
                # MiniMax 返回格式
                text = ""
                if response_data.get("choices"):
                    for choice in response_data.get("choices", []):
                        msg = choice.get("messages", [{}])
                        for m in msg:
                            if m.get("role") == "assistant":
                                text += m.get("text", "")
                
                if not text:
                    logger.error(f"MiniMax返回的内容为空: {response_data}")
                    return None
                
                return _parse_json_response(text)
                
            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 10
                    logger.warning(f"MiniMax API超时，等待{wait_time}秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error("MiniMax API超时：已达最大重试次数")
                    return None
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 10
                    logger.warning(f"MiniMax API请求失败，等待{wait_time}秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"MiniMax API调用失败: {str(e)}")
                    return None
    
    except Exception as e:
        logger.error(f"调用MiniMax API时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return None


def _call_openai_compatible(prompt: str, config: Dict[str, Any], provider_name: str) -> Optional[Dict[str, Any]]:
    """
    调用OpenAI兼容的API进行分析
    """
    api_key = config.get("api_key")
    model = config.get("model", "gpt-4o-mini")
    base_url = config.get("base_url", "https://api.openai.com/v1")
    
    if not api_key:
        logger.warning(f"未配置{provider_name} API密钥")
        return None
    
    try:
        import requests
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "你是一个专业的网络安全分析师，擅长分析CVE漏洞信息。请严格按照要求的JSON格式输出结果。"
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "response_format": {"type": "json_object"}
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=60
                )
                
                if response.status_code == 429:
                    if attempt < max_retries - 1:
                        wait_time = (2 ** attempt) * 15
                        logger.warning(f"{provider_name} API速率限制，等待{wait_time}秒后重试...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error(f"{provider_name} API速率限制：已达最大重试次数")
                        return None
                
                response.raise_for_status()
                response_data = response.json()
                
                text = response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
                
                if not text:
                    logger.error(f"{provider_name}返回的内容为空")
                    return None
                
                return _parse_json_response(text)
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 10
                    logger.warning(f"{provider_name} API请求失败，等待{wait_time}秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"{provider_name} API调用失败: {str(e)}")
                    return None
    
    except Exception as e:
        logger.error(f"调用{provider_name} API时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return None


def ask_gpt(prompt: str) -> Optional[Dict[str, Any]]:
    """
    调用GPT API进行分析，根据配置选择使用MiniMax、OpenAI或FastGPT
    """
    config = get_config()
    provider = config.get("GPT_PROVIDER", "minimax").lower()
    
    logger.info(f"使用{provider}进行GPT分析")
    
    if provider == "minimax":
        return _call_minimax(prompt, config.get("minimax", {}))
    elif provider == "openai":
        return _call_openai_compatible(prompt, config.get("openai", {}), "OpenAI")
    elif provider == "fastgpt":
        return _call_openai_compatible(prompt, config.get("fastgpt", {}), "FastGPT")
    else:
        logger.error(f"不支持的GPT服务提供商: {provider}")
        return None
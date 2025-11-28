import logging
import json
import time
import traceback
import os
from typing import Dict, Any, Optional
import google.generativeai as genai
from google.api_core import exceptions as google_exceptions
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
    """
    从CISA获取CVE信息
    """
    try:
        import requests
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
        import requests
        url = f"https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{cve_id}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"从OSCS获取CVE {cve_id} 信息失败: {str(e)}")
    
    return None


def _call_fastgpt(prompt: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    调用FastGPT API进行分析
    
    参数:
        prompt: 要发送给FastGPT的提示词
        config: FastGPT配置
    
    返回:
        FastGPT的响应结果（JSON格式解析后的字典）或None
    """
    try:
        import requests
        
        api_key = config.get("api_key")
        api_url = config.get("api_url")
        model = config.get("model")
        
        if not api_key or not api_url:
            logger.warning("未配置FastGPT API密钥或URL，无法使用FastGPT分析功能")
            return None
        
        # 构造请求体
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
            "response_format": {
                "type": "json_object"
            }
        }
        
        # 指数退避重试逻辑
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                # 发送请求
                response = requests.post(api_url, headers=headers, json=payload, timeout=30)
                response.raise_for_status()
                
                # 获取响应数据
                response_data = response.json()
                
                # 提取生成的文本
                text = response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
                
                if not text:
                    logger.error("FastGPT返回的内容为空")
                    return None
                
                # 尝试解析JSON，先移除可能的markdown标记和无效字符
                try:
                    # 移除```json和```标记，处理各种格式情况
                    clean_text = text.strip()
                    # 移除开头的```json标记（可能带有换行符）
                    if clean_text.startswith('```json'):
                        clean_text = clean_text[7:].strip()
                    # 移除开头的```标记（如果没有json指定）
                    elif clean_text.startswith('```'):
                        clean_text = clean_text[3:].strip()
                    # 移除结尾的```标记
                    if clean_text.endswith('```'):
                        clean_text = clean_text[:-3].strip()
                    
                    # 移除无效的控制字符
                    import re
                    # 移除所有控制字符，包括Unicode控制字符
                    clean_text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', clean_text)
                    # 移除可能的特殊空白字符
                    clean_text = re.sub(r'[\u200b-\u200f\ufeff]', '', clean_text)
                    # 规范化换行符
                    clean_text = re.sub(r'\r\n?', '\n', clean_text)
                    # 只替换多余的空格，保留必要的换行符
                    clean_text = re.sub(r' +', ' ', clean_text)
                    # 移除行首和行尾的多余空格
                    clean_text = re.sub(r'^ +| +$', '', clean_text, flags=re.MULTILINE)
                    
                    # 确保只保留JSON部分
                    return json.loads(clean_text)
                except json.JSONDecodeError as e:
                    logger.error(f"FastGPT返回的内容不是有效的JSON格式: {text[:200]}... 错误: {str(e)}")
                    # 尝试使用更健壮的方式提取JSON部分
                    # 匹配完整的JSON对象，包括嵌套结构
                    json_match = re.search(r'\{[\s\S]*\}', clean_text, re.DOTALL)
                    if json_match:
                        try:
                            extracted_json = json_match.group()
                            # 移除无效的控制字符
                            extracted_json = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', extracted_json)
                            # 移除可能的多余空格和换行符
                            extracted_json = re.sub(r'\s+', ' ', extracted_json)
                            return json.loads(extracted_json)
                        except json.JSONDecodeError as e2:
                            logger.error(f"提取JSON后仍无法解析: {extracted_json[:100]}... 错误: {str(e2)}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                # 处理请求错误
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 10  # 10s, 20s, 40s
                    logger.warning(f"FastGPT API请求失败，等待{wait_time}秒后第{attempt+2}次重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"FastGPT API调用失败: {str(e)}")
                    break
            except Exception as e:
                # 其他错误
                logger.error(f"调用FastGPT API时出错: {str(e)}")
                break
                
    except Exception as e:
        logger.error(f"调用FastGPT API时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return None


def _call_gemini(prompt: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    调用Gemini API进行分析
    
    参数:
        prompt: 要发送给Gemini的提示词
        config: Gemini配置
    
    返回:
        Gemini的响应结果（JSON格式解析后的字典）或None
    """
    api_key = config.get("api_key")
    # 确保使用正确的模型名称，统一使用 gemini-2.0-flash
    model_name = config.get("model", "gemini-2.0-flash")
    
    if not api_key:
        # 尝试从环境变量获取
        api_key = os.getenv("GOOGLE_API_KEY")
        
    if not api_key:
        logger.warning("未配置Gemini API密钥，无法使用Gemini分析功能")
        return None
    
    try:
        # 配置Gemini API
        genai.configure(api_key=api_key)
        
        # 选择模型
        model = genai.GenerativeModel(model_name)
        
        # 设置生成配置
        generation_config = genai.types.GenerationConfig(
            candidate_count=1,
            # max_output_tokens=2048,
            temperature=0.7,
            response_mime_type="application/json"
        )
        
        # 构造完整的提示词
        system_prompt = "你是一个专业的网络安全分析师，擅长分析CVE漏洞信息。请严格按照要求的JSON格式输出结果。"
        full_prompt = f"{system_prompt}\n\n{prompt}"
        
        # 指数退避重试逻辑
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                # 发送请求
                response = model.generate_content(
                    full_prompt,
                    generation_config=generation_config
                )
                
                # 获取文本响应
                text = response.text
                
                # 尝试解析JSON
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    logger.error(f"Gemini返回的内容不是有效的JSON格式: {text[:200]}...")
                    # 尝试提取JSON部分
                    import re
                    json_match = re.search(r'\{.*\}', text, re.DOTALL)
                    if json_match:
                        try:
                            return json.loads(json_match.group())
                        except:
                            pass
                    return None
                    
            except google_exceptions.ResourceExhausted as e:
                # 处理429速率限制
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 10  # 10s, 20s, 40s
                    logger.warning(f"Gemini API速率限制，等待{wait_time}秒后第{attempt+2}次重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error("Gemini API速率限制：已达最大重试次数")
                    raise e
            except google_exceptions.InvalidArgument as e:
                # 处理400错误
                logger.error(f"Gemini API参数错误: {str(e)}")
                break
            except Exception as e:
                # 其他错误
                if attempt < max_retries - 1:
                    logger.warning(f"请求失败({str(e)})，5秒后重试...")
                    time.sleep(5)
                else:
                    logger.error(f"Gemini API调用失败: {str(e)}")
                    break
                    
    except Exception as e:
        logger.error(f"调用Gemini API时出错: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return None


def ask_gpt(prompt: str) -> Optional[Dict[str, Any]]:
    """
    调用GPT API进行分析，根据配置选择使用Gemini或FastGPT
    
    参数:
        prompt: 要发送给GPT的提示词
    
    返回:
        GPT的响应结果（JSON格式解析后的字典）或None
    """
    config = get_config()
    provider = config.get("GPT_PROVIDER", "gemini").lower()
    
    logger.info(f"使用{provider}进行GPT分析")
    
    if provider == "fastgpt":
        # 使用FastGPT
        fastgpt_config = config.get("fastgpt", {})
        return _call_fastgpt(prompt, fastgpt_config)
    elif provider == "gemini":
        # 使用Gemini
        gemini_config = config.get("gemini", {})
        return _call_gemini(prompt, gemini_config)
    else:
        logger.error(f"不支持的GPT服务提供商: {provider}")
        return None
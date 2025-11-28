import json
import os
import requests
import time
import hmac
import hashlib
import base64
from config import get_config
from libs.report_generator import fix_markdown_format
import logging

logger = logging.getLogger(__name__)


def clean_string(s):
    """
    清理字符串，移除无效的控制字符
    
    Args:
        s: 要清理的字符串
        
    Returns:
        清理后的字符串
    """
    if not isinstance(s, str):
        return s
    
    import re
    # 移除所有无效的控制字符，只保留可打印字符和换行符
    clean_text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', s)
    # 移除可能的特殊空白字符
    clean_text = re.sub(r'[\u200b-\u200f\ufeff]', '', clean_text)
    return clean_text


def parse_webhook_data(webhook_data, data):
    """
    解析webhook数据并替换变量
    
    Args:
        webhook_data: webhook消息模板,支持字符串或字典格式
                     模板中可使用${key}形式的变量,key为data中的字段路径
                     例如:
                     - ${cve.title} - CVE标题
                     - ${repo.html_url} - 仓库URL
                     - ${gpt.risk} - GPT分析的风险等级
                     
        data: 包含CVE、仓库、GPT分析结果的字典数据
    
    Returns:
        解析后的webhook数据:
        
    示例:
        webhook_data = {
            "text": "发现新漏洞 ${cve.title}",
            "desp": "风险等级: ${gpt.risk}\n详情: ${repo.html_url}"
        }
        
        data = {
            "cve": {"title": "RCE漏洞"},
            "gpt": {"risk": "高危"},
            "repo": {"html_url": "https://github.com/..."}
        }
        
        # 返回:
        {
            "text": "发现新漏洞 RCE漏洞", 
            "desp": "风险等级: 高危\n详情: https://github.com/..."
        }
    
    """
    if not data:
        return webhook_data
        
    # 将data扁平化为key-value形式
    flat_data = {}
    
    def flatten_dict(d, parent_key=''):
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                flatten_dict(v, new_key)
            else:
                # 处理markdown内容，确保格式正确
                if new_key == 'gpt.markdown':
                    # 对markdown内容进行格式化处理
                    formatted_content = fix_markdown_format(str(v))
                    flat_data[new_key] = clean_string(formatted_content)
                else:
                    # 清理值中的无效控制字符
                    flat_data[new_key] = clean_string(str(v))
    
    for section in ['cve', 'repo', 'gpt']:
        if section in data:
            flatten_dict(data[section], section)
    
    # 替换webhook_data中的变量
    if isinstance(webhook_data, dict):
        # 直接处理字典，避免json.dumps和json.loads导致的转义问题
        def replace_in_dict(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if isinstance(v, str):
                        # 先处理特殊字段
                        # 处理完整分析报告链接：如果git_url为空，不显示链接
                        if '{gpt.git_url}' in v:
                            git_url = flat_data.get('gpt.git_url', '')
                            if not git_url:
                                # 如果git_url为空，移除完整分析报告行
                                v = v.replace('**完整分析报告**: [查看详情]({gpt.git_url})\n', '')
                        
                        # 然后处理普通变量替换
                        for key, value in flat_data.items():
                            # 支持两种格式：${key} 和 {key}
                            v = v.replace(f"${{{key}}}", value)
                            v = v.replace(f"{{{key}}}", value)
                        # 清理替换后的字符串
                        d[k] = clean_string(v)
                    elif isinstance(v, (dict, list)):
                        replace_in_dict(v)
            elif isinstance(d, list):
                for i, item in enumerate(d):
                    if isinstance(item, (dict, list)):
                        replace_in_dict(item)
        
        # 创建字典副本，避免修改原始数据
        webhook_data_copy = webhook_data.copy()
        replace_in_dict(webhook_data_copy)
        return webhook_data_copy
    elif isinstance(webhook_data, str):
        # 处理字符串模板
        # 先处理特殊字段
        if '{gpt.git_url}' in webhook_data:
            git_url = flat_data.get('gpt.git_url', '')
            if not git_url:
                # 如果git_url为空，移除完整分析报告行
                webhook_data = webhook_data.replace('**完整分析报告**: [查看详情]({gpt.git_url})\n', '')
        
        # 然后处理普通变量替换
        for k, v in flat_data.items():
            # 支持两种格式：${key} 和 {key}
            webhook_data = webhook_data.replace(f"${{{k}}}", v)
            webhook_data = webhook_data.replace(f"{{{k}}}", v)
        # 清理替换后的字符串
        webhook_data = clean_string(webhook_data)
        return json.loads(webhook_data)

def send_webhook(data) -> bool:
    """
    发送webhook通知
    
    Args:
        data: 要发送的数据
        
    Returns:
        bool: 是否发送成功
    """
    try:
        enable_notify = get_config('ENABLE_NOTIFY')
        if not enable_notify:
            logger.info("通知功能未启用")
            return True
        
        notify_type = get_config('NOTIFY_TYPE')
        if not notify_type:
            logger.info("未配置通知类型")
            return True
        
        notify_types = [t.strip().lower() for t in notify_type.split(',')]
        success_count = 0
        
        # 发送飞书通知
        if 'feishu' in notify_types:
            feishu_url = get_config('FEISHU_WEBHOOK_URL')
            feishu_secret = get_config('FEISHU_SECRET')
            if feishu_url:
                if send_feishu_webhook(data, feishu_url, feishu_secret):
                    success_count += 1
            else:
                logger.warning("飞书webhook URL未配置")
        
        # 发送钉钉通知
        if 'dingtalk' in notify_types:
            dingtalk_url = get_config('DINGTALK_WEBHOOK_URL')
            dingtalk_secret = get_config('DINGTALK_SECRET')
            if dingtalk_url:
                if send_dingtalk_webhook(data, dingtalk_url, dingtalk_secret):
                    success_count += 1
            else:
                logger.warning("钉钉webhook URL未配置")
        
        return success_count > 0
    except Exception as e:
        logger.error(f"发送通知失败: {str(e)}")
        return False

def send_feishu_webhook(data, webhook_url, secret) -> bool:
    """
    发送飞书webhook通知
    
    Args:
        data: 要发送的数据
        webhook_url: 飞书webhook地址
        secret: 签名密钥
        
    Returns:
        bool: 是否发送成功
    """
    try:
        # 使用飞书模板
        template_path = 'template/feishu.json'
        if not os.path.exists(template_path):
            logger.error(f"消息模板文件不存在: {template_path}")
            return False
        with open(template_path, 'r', encoding='utf-8') as f:
            webhook_data = f.read()
        msg = parse_webhook_data(webhook_data, data)
        logger.debug(f"解析飞书webhook_data: {msg}")
        
        headers = {
            "Content-Type": "application/json",
            "charset": "utf-8"
        }
        
        if secret:
            timestamp = str(int(time.time()))
            string_to_sign = f"{timestamp}\n{secret}"
            hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
            sign = base64.b64encode(hmac_code).decode("utf-8")
            headers["X-Timestamp"] = timestamp
            headers["X-Signature"] = f"v1={sign}"
        
        response = requests.post(webhook_url, headers=headers, json=msg)
        response_data = response.json()
        if response_data.get("StatusCode") == 0:
            logger.info(f"飞书消息发送成功")
            return True
        else:
            logger.error(f"飞书消息发送失败: {response_data}")
            return False
    except Exception as e:
        logger.error(f"发送飞书webhook失败: {str(e)}")
        return False

def send_dingtalk_webhook(data, webhook_url, secret) -> bool:
    """
    发送钉钉webhook通知
    
    Args:
        data: 要发送的数据
        webhook_url: 钉钉webhook地址
        secret: 签名密钥
        
    Returns:
        bool: 是否发送成功
    """
    try:
        # 使用钉钉专用模板
        template_path = 'template/dingtalk.json'
        if not os.path.exists(template_path):
            logger.error(f"消息模板文件不存在: {template_path}")
            return False
        with open(template_path, 'r', encoding='utf-8') as f:
            webhook_data = f.read()
        msg = parse_webhook_data(webhook_data, data)
        logger.debug(f"解析钉钉webhook_data: {msg}")
        
        headers = {
            "Content-Type": "application/json",
            "charset": "utf-8"
        }
        
        # 钉钉签名计算：使用secret作为HMAC key
        timestamp = str(int(time.time() * 1000))
        if secret:
            string_to_sign = f"{timestamp}\n{secret}"
            hmac_code = hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
            sign = base64.b64encode(hmac_code).decode("utf-8")
            # URL编码sign参数
            import urllib.parse
            sign = urllib.parse.quote_plus(sign)
            webhook_url = f"{webhook_url}&timestamp={timestamp}&sign={sign}"
        else:
            webhook_url = f"{webhook_url}&timestamp={timestamp}"
        
        response = requests.post(webhook_url, headers=headers, json=msg)
        response_data = response.json()
        if response_data.get("errcode") == 0:
            logger.info(f"钉钉消息发送成功")
            return True
        else:
            logger.error(f"钉钉消息发送失败: {response_data}")
            return False
    except Exception as e:
        logger.error(f"发送钉钉webhook失败: {str(e)}")
        return False

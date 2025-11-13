import json
import os
import time
import hmac
import hashlib
import base64
import requests
from config import get_config
import logging
from libs.webhook import parse_webhook_data

logger = logging.getLogger(__name__)


def get_timestamp_sign():
    """
    生成钉钉所需的时间戳和签名
    
    Returns:
        dict: 包含timestamp和sign的字典
    """
    timestamp = str(round(time.time() * 1000))
    secret = get_config('DINGTALK_SECRET')
    
    # 如果没有提供密钥，则只返回时间戳
    if not secret:
        return {"timestamp": timestamp}
    
    # 构造签名字符串
    string_to_sign = f"{timestamp}\n{secret}"
    
    # 使用HMAC-SHA256算法计算签名
    hmac_code = hmac.new(
        secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    
    # 对签名进行Base64编码
    sign = base64.b64encode(hmac_code).decode('utf-8')
    
    return {"timestamp": timestamp, "sign": sign}


def send_dingtalk_notification(data):
    """
    发送钉钉通知
    
    Args:
        data: 包含CVE、仓库、GPT分析结果的字典数据
    """
    # 获取钉钉webhook URL
    webhook_url = get_config('DINGTALK_WEBHOOK_URL')
    if not webhook_url:
        logger.error("钉钉Webhook URL未配置")
        return False
    
    # 获取模板路径，直接使用钉钉模板
    template_path = 'template/dingtalk.json'
    
    if not os.path.exists(template_path):
        logger.error(f"消息模板文件不存在: {template_path}")
        return False
    
    # 读取模板
    with open(template_path, 'r', encoding='utf-8') as f:
        webhook_data = f.read()
    
    # 解析模板中的变量
    msg = parse_webhook_data(webhook_data, data)
    logger.debug(f"解析后的钉钉消息: {msg}")
    
    # 生成时间戳和签名
    timestamp_sign = get_timestamp_sign()
    
    # 构造完整的请求URL
    request_url = webhook_url
    if "sign" in timestamp_sign:
        request_url = f"{webhook_url}&timestamp={timestamp_sign['timestamp']}&sign={timestamp_sign['sign']}"
    elif "timestamp" in timestamp_sign:
        request_url = f"{webhook_url}&timestamp={timestamp_sign['timestamp']}"
    
    # 设置请求头
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        # 发送请求
        response = requests.post(request_url, json=msg, headers=headers)
        response.raise_for_status()  # 抛出HTTP错误
        
        # 解析响应
        response_data = response.json()
        
        if response_data.get("errcode") != 0:
            logger.error(f"钉钉通知发送失败: {response_data}")
            return False
        
        logger.debug(f"钉钉通知发送成功: {response_data}")
        return True
    except Exception as e:
        logger.error(f"钉钉通知发送异常: {str(e)}")
        return False
import os
import logging
from dotenv import load_dotenv


# 配置文件
DEBUG=False

load_dotenv()


# 是否启用通知功能
ENABLE_NOTIFY=True

# 通知类型从环境变量读取,支持飞书(feishu)和钉钉(dingtalk)

# 是否启用GPT功能进行漏洞分析
ENABLE_GPT=True

# Gemini模型名称
GEMINI_MODEL='gemini-2.0-flash'

# 是否启用漏洞信息搜索功能，需启用GPT分析
ENABLE_SEARCH=True

# 是否启用扩展搜索功能
ENABLE_EXTENDED=True

# 数据库URL
DB_URL='sqlite:///vulns.db'

if os.environ.get('DEBUG'):
    DEBUG = os.environ.get('DEBUG')

def get_config(key=None):
    config = {
        "DEBUG": 'DEBUG' if DEBUG =='true' else 'INFO',
        # 通知配置
        'ENABLE_NOTIFY': ENABLE_NOTIFY,
        'NOTIFY_TYPE': os.environ.get('NOTIFY_TYPE', ''),
        'WEBHOOK_URL': os.environ.get('WEBHOOK_URL'),
        # 钉钉通知配置
        'DINGTALK_WEBHOOK_URL': os.environ.get('DINGTALK_WEBHOOK_URL'),
        'DINGTALK_SECRET': os.environ.get('DINGTALK_SECRET'),
        # 飞书通知配置
        'FEISHU_WEBHOOK_URL': os.environ.get('FEISHU_WEBHOOK_URL'),
        'FEISHU_SECRET': os.environ.get('FEISHU_SECRET'),
        # GPT配置
        'ENABLE_GPT': ENABLE_GPT,
        'GPT_SERVER_URL': os.environ.get('GPT_SERVER_URL'),
        'GPT_API_KEY': os.environ.get('GPT_API_KEY'),
        'GPT_MODEL': os.environ.get('GPT_MODEL') if os.environ.get('GPT_MODEL') else 'gemini-2.0-flash',
        # Gemini配置
        'gemini': {
            'api_key': os.environ.get('GEMINI_API_KEY'),
            'model': os.environ.get('GEMINI_MODEL') if os.environ.get('GEMINI_MODEL') else GEMINI_MODEL
        },
        # 搜索配置
        'ENABLE_SEARCH': ENABLE_SEARCH,
        'SEARXNG_URL': os.environ.get('SEARXNG_URL'),
        # CVE配置
        'CVE_YEAR_PREFIX': os.environ.get('CVE_YEAR_PREFIX'),
        'CVE_YEAR_RANGE': os.environ.get('CVE_YEAR_RANGE', '2020-2025'),
        # 数据库配置
        'DB_URL': os.environ.get('DATABASE_URL', DB_URL),
        # GitHub配置
        'GITHUB_TOKEN': os.environ.get('GITHUB_TOKEN'),
        # 扩展搜索配置
        'ENABLE_EXTENDED': ENABLE_EXTENDED,
        # 仓库地址
        'GIT_URL': os.environ.get('GIT_URL', ''),
        # RSS配置
        'RSS_OUTPUT_PATH': os.environ.get('RSS_OUTPUT_PATH', './rss.xml'),
    }
    if key:
        return config.get(key)
    return config

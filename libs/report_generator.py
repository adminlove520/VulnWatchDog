import os
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from typing import List, Dict
import logging
import traceback

logger = logging.getLogger(__name__)

def get_template():
    with open('template/report.md', 'r', encoding='utf-8') as file:
        return file.read()

def write_to_markdown(data: Dict, filename: str):
    """
    将内容写入markdown文件
    """
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        # 记录写入前的数据
        logger.info(f"📝 准备写入markdown: {filename}")
        logger.debug(f"数据字段: {list(data.keys())}")
        
        template = get_template()
        content = template.format(**data)
        
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(content)
        
        logger.info(f"✅ Markdown文件已成功写入: {filename}")
        
    except KeyError as e:
        logger.error(f"❌ 模板字段缺失: {e}")
        logger.error(f"可用字段: {list(data.keys())}")
        logger.error(f"缺少的字段可能是模板中的: {e}")
        raise
    except Exception as e:
        logger.error(f"❌ 写入markdown失败: {e}")
        logger.debug(traceback.format_exc())
        raise

def generate_rss_feed(vulnerabilities: List[Dict], title: str, description: str) -> str:
    """
    生成RSS订阅源XML内容
    """
    # 创建根元素
    rss = ET.Element('rss', version='2.0')
    channel = ET.SubElement(rss, 'channel')
    
    # 添加频道信息
    ET.SubElement(channel, 'title').text = title
    ET.SubElement(channel, 'description').text = description
    ET.SubElement(channel, 'link').text = 'http://vulnwatchdog.local'
    ET.SubElement(channel, 'lastBuildDate').text = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0800')
    ET.SubElement(channel, 'generator').text = 'VulnWatchdog'
    
    # 添加每个漏洞作为一个条目
    for vuln in vulnerabilities:
        item = ET.SubElement(channel, 'item')
        
        # 基本信息
        ET.SubElement(item, 'title').text = f"{vuln.get('cve_id', 'Unknown')} - {vuln.get('title', 'Untitled')}"
        
        # 构建描述内容
        desc_parts = []
        desc_parts.append(f"<strong>严重程度:</strong> {vuln.get('severity', 'Unknown')}")
        desc_parts.append(f"<strong>发布日期:</strong> {vuln.get('published_date', 'Unknown')}")
        desc_parts.append(f"<strong>来源:</strong> {vuln.get('source', 'Unknown')}")
        desc_parts.append(f"<strong>描述:</strong> {vuln.get('description', 'No description available')}")
        
        # 添加PoC信息
        poc_info = vuln.get('poc_info', [])
        if poc_info:
            desc_parts.append("<strong>相关PoC:</strong>")
            for poc in poc_info:
                repo = poc.get('repo', {})
                if repo:
                    name = repo.get('name', 'Unknown')
                    url = repo.get('html_url', '#')
                    desc = repo.get('description', '')
                    desc_parts.append(f"<a href='{url}'>{name}</a>: {desc}")
        
        description_text = '<br>'.join(desc_parts)
        ET.SubElement(item, 'description').text = description_text
        
        # 链接和唯一ID
        link = vuln.get('reference_url', f"https://nvd.nist.gov/vuln/detail/{vuln.get('cve_id', 'unknown')}")
        ET.SubElement(item, 'link').text = link
        ET.SubElement(item, 'guid', isPermaLink='false').text = vuln.get('cve_id', f"unknown-{hash(link)}")
        
        # 发布日期
        pub_date = vuln.get('published_date', datetime.now().isoformat())
        ET.SubElement(item, 'pubDate').text = str(pub_date)
    
    # 将ElementTree转换为美观的XML字符串
    rough_string = ET.tostring(rss, encoding='utf-8', method='xml')
    reparsed = minidom.parseString(rough_string)
    
    return reparsed.toprettyxml(indent="  ")

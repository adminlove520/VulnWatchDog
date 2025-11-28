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

def fix_markdown_format(markdown_content: str) -> str:
    """
    修复markdown内容格式，确保标题、换行、缩进等格式正确
    
    Args:
        markdown_content: 原始markdown内容
        
    Returns:
        str: 格式化后的markdown内容
    """
    if not markdown_content:
        return ""
    
    import re
    
    # 1. 移除所有控制字符
    markdown_content = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', markdown_content)
    
    # 2. 修复标题格式：确保所有预期的标题都有正确的## 前缀
    expected_sections = ['漏洞概述', '有效性分析', '投毒风险分析', '利用方式', '代码分析']
    for section in expected_sections:
        # 匹配各种可能的标题格式，如"# 漏洞概述"、"漏洞概述"等
        markdown_content = re.sub(r'#*\s*' + re.escape(section), f'## {section}', markdown_content)
    
    # 3. 确保标题之间有正确的换行
    for section in expected_sections:
        # 在标题前添加两个换行符，确保标题之间有正确的分隔
        markdown_content = re.sub(r'(?<!\n\n)##\s*' + re.escape(section), f'\n\n## {section}', markdown_content)
    
    # 4. 确保标题后有正确的内容分隔
    for section in expected_sections:
        # 在标题后添加两个换行符，确保内容正确分隔
        markdown_content = re.sub(r'(##\s*' + re.escape(section) + r')([^\n])', r'\1\n\n\2', markdown_content)
    
    # 5. 修复列表格式：确保序号列表项之间有正确的换行
    # 匹配 1. 2. 3. 等序号列表项，确保它们之间有换行
    markdown_content = re.sub(r'(\d+\.\s+[^\d]+?)(?=\d+\.\s+)', r'\1\n', markdown_content)
    
    # 6. 修复无序列表格式：确保- 列表项之间有正确的换行
    # 匹配 - 开头的列表项，确保它们之间有换行
    markdown_content = re.sub(r'(-\s+[^-]+?)(?=-\s+)', r'\1\n', markdown_content)
    
    # 7. 修复"代码执行流程："等描述性文本后面的换行
    markdown_content = re.sub(r'(代码执行流程：|主要组件包括：|执行流程：)', r'\1\n', markdown_content)
    
    # 8. 确保列表项前有适当的换行
    markdown_content = re.sub(r'(?<!\n\n)(\d+\.\s+|-\s+)', r'\n\1', markdown_content)
    
    # 9. 移除行首和行尾的多余空格
    markdown_content = '\n'.join([line.strip() for line in markdown_content.split('\n')])
    
    # 10. 移除重复的换行，确保最多只有两个连续换行
    markdown_content = re.sub(r'\n{3,}', '\n\n', markdown_content)
    
    # 11. 特殊处理：确保概要部分不包含主标题
    # 移除可能存在的主标题（# 开头的行）
    markdown_content = re.sub(r'^#\s+[^\n]+\n', '', markdown_content, flags=re.MULTILINE)
    
    # 12. 确保内容开头没有空行
    markdown_content = markdown_content.lstrip('\n')
    
    # 13. 确保内容结尾没有空行
    markdown_content = markdown_content.rstrip('\n')
    
    return markdown_content

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
        
        # 确保所有模板需要的字段都存在，添加默认值
        data_with_defaults = data.copy()
        
        # 添加related_articles字段的默认值
        if 'related_articles' not in data_with_defaults:
            data_with_defaults['related_articles'] = '暂无相关文章'
        
        # 修复概要内容格式
        if 'markdown' in data_with_defaults:
            markdown_content = data_with_defaults['markdown']
            # 使用独立的格式化函数修复markdown格式
            markdown_content = fix_markdown_format(markdown_content)
            # 更新修复后的内容
            data_with_defaults['markdown'] = markdown_content
        
        template = get_template()
        content = template.format(**data_with_defaults)
        
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

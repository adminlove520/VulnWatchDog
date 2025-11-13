import os
import json
import logging
from datetime import datetime
from feedgen.feed import FeedGenerator
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import get_config

logger = logging.getLogger(__name__)

def generate_rss_feed(vulnerability_data, output_path='./rss.xml'):
    """
    生成漏洞订阅RSS feed
    
    Args:
        vulnerability_data: 漏洞数据列表，包含标题、描述、链接等信息
        output_path: RSS文件输出路径
        
    Returns:
        bool: 是否生成成功
    """
    try:
        # 创建FeedGenerator实例
        fg = FeedGenerator()
        
        # 设置feed元数据
        fg.title('VulnWatchdog 漏洞订阅')
        fg.link(href='https://github.com/adminlove520/VulnWatchDog.git', rel='alternate')
        fg.description('实时更新的漏洞情报订阅源')
        fg.language('zh-CN')
        fg.lastBuildDate(datetime.now())
        fg.pubDate(datetime.now())
        
        # 添加漏洞条目
        for vuln in vulnerability_data:
            entry = fg.add_entry()
            
            # 设置条目标题
            if 'title' in vuln:
                entry.title(vuln['title'])
            elif 'cve_id' in vuln:
                entry.title(f"{vuln['cve_id']} - 漏洞情报")
            else:
                entry.title("未知漏洞")
            
            # 设置条目链接
            if 'url' in vuln:
                entry.link(href=vuln['url'], rel='alternate')
            elif 'cve_id' in vuln:
                entry.link(href=f"https://nvd.nist.gov/vuln/detail/{vuln['cve_id']}", rel='alternate')
            else:
                entry.link(href='https://github.com/adminlove520/VulnWatchDog.git', rel='alternate')
            
            # 设置条目描述
            description = []
            if 'description' in vuln:
                description.append(f"**描述：**{vuln['description']}")
            if 'severity' in vuln:
                description.append(f"**严重程度：**{vuln['severity']}")
            if 'published_date' in vuln:
                description.append(f"**发布日期：**{vuln['published_date']}")
            if 'cve_id' in vuln:
                description.append(f"**CVE ID：**{vuln['cve_id']}")
            if 'affected_products' in vuln:
                description.append(f"**受影响产品：**{', '.join(vuln['affected_products'])}")
                
            entry.description('\n'.join(description))
            
            # 设置发布时间
            if 'published_date' in vuln:
                try:
                    pub_date = datetime.strptime(vuln['published_date'], '%Y-%m-%d')
                    entry.pubDate(pub_date)
                except:
                    entry.pubDate(datetime.now())
            else:
                entry.pubDate(datetime.now())
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # 生成RSS feed
        fg.rss_file(output_path, pretty=True)
        logger.info(f"RSS feed 已生成到: {output_path}")
        return True
    except Exception as e:
        logger.error(f"生成RSS feed失败: {str(e)}")
        return False

def generate_daily_rss():
    """
    生成当日漏洞的RSS feed
    """
    try:
        # 获取当前日期的目录路径
        today = datetime.now().strftime('%Y-%m-%d')
        year = today[:4]
        data_dir = f'./data/markdown/{year}'
        
        # 收集今日漏洞数据
        today_vulnerabilities = []
        
        # 检查目录是否存在
        if os.path.exists(data_dir):
            for filename in os.listdir(data_dir):
                if filename.startswith(today):
                    file_path = os.path.join(data_dir, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # 从Markdown文件中提取信息
                            cve_id = filename.split('.')[0].split('-')[-1]
                            title = f"CVE-{cve_id} - 漏洞情报"
                            
                            # 提取标题行
                            for line in content.split('\n'):
                                if line.startswith('#'):
                                    title = line.strip('# ')
                                    break
                            
                            today_vulnerabilities.append({
                                'title': title,
                                'cve_id': f"CVE-{cve_id}",
                                'description': content[:200] + '...' if len(content) > 200 else content,
                                'published_date': today,
                                'url': f"https://nvd.nist.gov/vuln/detail/CVE-{cve_id}"
                            })
                    except Exception as e:
                        logger.error(f"读取漏洞文件失败 {file_path}: {str(e)}")
        
        # 如果有今日漏洞，生成RSS
        if today_vulnerabilities:
            rss_output_path = get_config('RSS_OUTPUT_PATH', './rss.xml')
            return generate_rss_feed(today_vulnerabilities, rss_output_path)
        else:
            logger.info("今日无漏洞数据，跳过RSS生成")
            return False
    except Exception as e:
        logger.error(f"生成今日RSS失败: {str(e)}")
        return False
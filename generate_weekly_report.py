#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
每周漏洞报告生成器
用于生成和存储每周漏洞报告
"""
import os
import json
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("weekly_report.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 配置文件
CONFIG_PATH = "config.py"
def get_config(key: str) -> str:
    """获取配置项"""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("config", CONFIG_PATH)
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        return getattr(config, key, "")
    except Exception as e:
        logger.error(f"获取配置失败: {str(e)}")
        return ""

# 常量
DATA_DIR = Path("data/markdown")
WEEKLY_REPORT_DIR = Path("data/WeeklyReport")


def get_week_number(dt: datetime) -> int:
    """获取指定日期是当月的第几周"""
    # 计算当月第一周的开始日期（周一）
    first_day = dt.replace(day=1)
    first_weekday = first_day.weekday()
    first_week_start = first_day - timedelta(days=first_weekday)
    
    # 计算当前日期与第一周开始的天数差，除以7得到周数
    delta_days = (dt - first_week_start).days
    week_number = (delta_days // 7) + 1
    
    return week_number


def get_week_range(year: int, month: int, week_num: int) -> tuple:
    """获取指定年月周的开始和结束日期"""
    # 获取当月第一天
    first_day = datetime(year, month, 1)
    first_weekday = first_day.weekday()
    
    # 计算当月第一周的开始日期（周一）
    first_week_start = first_day - timedelta(days=first_weekday)
    
    # 计算指定周的开始和结束日期
    week_start = first_week_start + timedelta(days=(week_num - 1) * 7)
    week_end = week_start + timedelta(days=6)
    
    # 确保结束日期不超过当月最后一天
    if month == 12:
        next_month_first = datetime(year + 1, 1, 1)
    else:
        next_month_first = datetime(year, month + 1, 1)
    
    # 调整结束日期，不超过下个月第一天
    if week_end >= next_month_first:
        week_end = next_month_first - timedelta(days=1)
    
    return week_start, week_end


def collect_vulnerabilities_for_week(year: int, month: int, week_num: int) -> List[Dict]:
    """收集指定周的所有漏洞信息"""
    week_start, week_end = get_week_range(year, month, week_num)
    logger.info(f"收集 {year}-{month} 第 {week_num} 周 ({week_start.strftime('%Y-%m-%d')} 至 {week_end.strftime('%Y-%m-%d')}) 的漏洞信息")
    
    vulnerabilities = []
    
    # 遍历每年的目录
    for year_dir in DATA_DIR.iterdir():
        if not year_dir.is_dir():
            continue
        
        try:
            dir_year = int(year_dir.name)
        except ValueError:
            continue
        
        # 只处理指定年份或相关年份的漏洞
        if dir_year < year - 1 or dir_year > year + 1:
            continue
        
        # 遍历该年份下的所有markdown文件
        for md_file in year_dir.glob("*.md"):
            try:
                # 读取文件内容
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 提取CVE ID
                cve_id = md_file.stem.split('-')[0]
                
                # 尝试从文件名或内容中解析日期
                file_date = datetime.fromtimestamp(md_file.stat().st_mtime)
                
                # 检查是否在目标周范围内
                if week_start <= file_date <= week_end:
                    vulnerability = {
                        'cve_id': cve_id,
                        'file_path': str(md_file),
                        'file_date': file_date,
                        'content': content
                    }
                    vulnerabilities.append(vulnerability)
                    logger.debug(f"找到漏洞: {cve_id}")
                    
            except Exception as e:
                logger.error(f"处理文件 {md_file} 时出错: {str(e)}")
    
    # 按日期排序
    vulnerabilities.sort(key=lambda x: x['file_date'])
    logger.info(f"共收集到 {len(vulnerabilities)} 个漏洞")
    
    return vulnerabilities


def generate_weekly_report(year: int, month: int, week_num: int, vulnerabilities: List[Dict]) -> str:
    """生成每周漏洞报告内容"""
    week_start, week_end = get_week_range(year, month, week_num)
    
    # 按严重程度分类（这里简化处理，实际可能需要从内容中提取）
    critical_vulns = []
    high_vulns = []
    medium_vulns = []
    low_vulns = []
    
    for vuln in vulnerabilities:
        content = vuln['content'].lower()
        if 'critical' in content or '严重' in content:
            critical_vulns.append(vuln)
        elif 'high' in content or '高危' in content:
            high_vulns.append(vuln)
        elif 'medium' in content or '中危' in content:
            medium_vulns.append(vuln)
        else:
            low_vulns.append(vuln)
    
    # 构建报告内容
    report_date = datetime.now().strftime('%Y-%m-%d')
    report = f"""
# 每周漏洞报告

**报告生成日期:** {report_date}
**报告周期:** {week_start.strftime('%Y-%m-%d')} 至 {week_end.strftime('%Y-%m-%d')} （{year}-{month:02d} 第 {week_num} 周）
**漏洞总数:** {len(vulnerabilities)}

## 漏洞概览
- 严重级别: {len(critical_vulns)} 个
- 高危级别: {len(high_vulns)} 个
- 中危级别: {len(medium_vulns)} 个
- 低危级别: {len(low_vulns)} 个

## 详细漏洞列表

"""
    
    # 添加每个漏洞的简要信息
    for vuln in vulnerabilities:
        cve_id = vuln['cve_id']
        file_date = vuln['file_date'].strftime('%Y-%m-%d %H:%M:%S')
        
        # 提取漏洞标题和简短描述
        content_lines = vuln['content'].split('\n')
        title = next((line for line in content_lines if line.startswith('# ')), f"#{cve_id}")
        description = """
        """
        
        # 尝试提取漏洞类型和风险等级
        vuln_type = "未知"
        risk_level = "未知"
        
        for line in content_lines:
            if '类型:' in line:
                vuln_type = line.split('类型:')[1].strip()
            elif '风险:' in line:
                risk_level = line.split('风险:')[1].strip()
            elif line.strip() and not line.startswith('#') and not line.startswith('```'):
                if not description:
                    description = line.strip()
                if len(description) > 100:
                    break
        
        report += f"""
### {title.strip()}
- **CVE ID:** {cve_id}
- **发现日期:** {file_date}
- **漏洞类型:** {vuln_type}
- **风险等级:** {risk_level}
- **描述:** {description[:100]}...

"""
    
    # 添加总结部分
    report += f"""
## 总结

本周共发现 {len(vulnerabilities)} 个新漏洞，其中 {len(critical_vulns)} 个严重级别，{len(high_vulns)} 个高危级别。
建议优先关注严重和高危级别的漏洞，并及时更新相关系统和应用。

---
*本报告由 VulnWatchdog 自动生成*  
*项目地址: https://github.com/adminlove520/VulnWatchDog.git*
"""
    
    return report


def save_weekly_report(year: int, month: int, week_num: int, report_content: str) -> str:
    """保存每周漏洞报告到指定目录"""
    # 创建目录结构
    week_dir = WEEKLY_REPORT_DIR / f"{year}-{month:02d}-{week_num}"
    week_dir.mkdir(parents=True, exist_ok=True)
    
    # 生成文件名
    current_date = datetime.now().strftime('%Y%m%d')
    report_file = week_dir / f"Weekly_{current_date}.md"
    
    # 保存报告
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    logger.info(f"每周漏洞报告已保存至: {report_file}")
    return str(report_file)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='生成每周漏洞报告')
    parser.add_argument('--year', type=int, default=datetime.now().year, help='年份')
    parser.add_argument('--month', type=int, default=datetime.now().month, help='月份')
    parser.add_argument('--week', type=int, default=None, help='周数（不指定则自动计算）')
    
    args = parser.parse_args()
    
    # 如果未指定周数，计算当前是第几周
    if args.week is None:
        args.week = get_week_number(datetime.now())
    
    logger.info(f"开始生成 {args.year}-{args.month} 第 {args.week} 周的漏洞报告")
    
    # 创建必要的目录
    WEEKLY_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 收集漏洞信息
    vulnerabilities = collect_vulnerabilities_for_week(args.year, args.month, args.week)
    
    # 生成报告
    report_content = generate_weekly_report(args.year, args.month, args.week, vulnerabilities)
    
    # 保存报告
    report_path = save_weekly_report(args.year, args.month, args.week, report_content)
    
    logger.info(f"每周漏洞报告生成完成: {report_path}")


if __name__ == "__main__":
    main()
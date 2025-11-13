#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重构data/markdown目录结构，按年份创建子文件夹
"""

import os
import re
import shutil
from pathlib import Path

# 配置
MARKDOWN_DIR = Path("data/markdown")
# 支持的年份范围
SUPPORTED_YEARS = list(range(2020, 2026))  # 2020-2025

# CVE文件匹配模式
CVE_PATTERN = re.compile(r'CVE-(\d{4})-(\d+)')

def main():
    """
    主函数：重构目录结构
    """
    print(f"开始重构目录结构，目标目录: {MARKDOWN_DIR}")
    
    # 确保主目录存在
    if not MARKDOWN_DIR.exists():
        print(f"错误: 目录 {MARKDOWN_DIR} 不存在")
        return
    
    # 创建年份子文件夹
    for year in SUPPORTED_YEARS:
        year_dir = MARKDOWN_DIR / str(year)
        if not year_dir.exists():
            year_dir.mkdir(exist_ok=True)
            print(f"创建年份文件夹: {year_dir}")
    
    # 统计信息
    total_files = 0
    moved_files = 0
    skipped_files = 0
    
    # 遍历所有文件
    for file_path in MARKDOWN_DIR.iterdir():
        # 跳过目录
        if file_path.is_dir():
            continue
        
        # 只处理.md文件
        if not file_path.suffix.lower() == '.md':
            skipped_files += 1
            continue
        
        total_files += 1
        
        # 从文件名中提取年份
        match = CVE_PATTERN.search(file_path.name)
        if match:
            year = int(match.group(1))
            
            # 检查年份是否在支持范围内
            if year in SUPPORTED_YEARS:
                # 目标路径
                target_dir = MARKDOWN_DIR / str(year)
                target_path = target_dir / file_path.name
                
                # 移动文件
                shutil.move(str(file_path), str(target_path))
                moved_files += 1
                print(f"移动文件: {file_path.name} -> {year}/{file_path.name}")
            else:
                skipped_files += 1
                print(f"跳过文件 (年份不在范围内 {year}): {file_path.name}")
        else:
            skipped_files += 1
            print(f"跳过文件 (无法识别CVE格式): {file_path.name}")
    
    # 打印统计结果
    print(f"\n重构完成！")
    print(f"总文件数: {total_files}")
    print(f"移动文件数: {moved_files}")
    print(f"跳过文件数: {skipped_files}")
    
    # 显示目录结构
    print(f"\n当前目录结构:")
    for year in SUPPORTED_YEARS:
        year_dir = MARKDOWN_DIR / str(year)
        if year_dir.exists():
            file_count = len(list(year_dir.glob('*.md')))
            print(f"  {year}/: {file_count} 个文件")

if __name__ == "__main__":
    main()
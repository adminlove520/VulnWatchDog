import os
import re

# 定义要保留的年份范围
target_years = {'2020', '2021', '2022', '2023', '2024', '2025'}

# 设置markdown目录路径
markdown_dir = 'd:/safePro/VulnWatchdog/data/markdown'

# 获取目录中的所有文件
all_files = os.listdir(markdown_dir)

# 编译正则表达式以匹配CVE文件
cve_pattern = re.compile(r'CVE-(\d{4})-')

# 统计信息
total_files = len(all_files)
files_to_delete = []
files_to_keep = []

# 遍历所有文件
for file in all_files:
    match = cve_pattern.match(file)
    if match:
        year = match.group(1)
        if year not in target_years:
            files_to_delete.append(file)
        else:
            files_to_keep.append(file)
    else:
        # 非CVE格式的文件也删除
        files_to_delete.append(file)

# 删除不符合条件的文件
deleted_count = 0
for file in files_to_delete:
    try:
        file_path = os.path.join(markdown_dir, file)
        os.remove(file_path)
        deleted_count += 1
    except Exception as e:
        print(f"删除文件 {file} 时出错: {e}")

# 打印统计信息
print(f"总文件数: {total_files}")
print(f"保留的文件数: {len(files_to_keep)}")
print(f"删除的文件数: {deleted_count}")
print(f"清理完成!")
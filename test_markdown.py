#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
测试markdown生成功能
"""
from libs.report_generator import write_to_markdown
import logging

logging.basicConfig(level=logging.DEBUG)

# 模拟GPT结果
test_data = {
    'name': 'CVE-2024-TEST 测试漏洞',
    'cve_id': 'CVE-2024-99999',
    'type': 'RCE远程代码执行',
    'app': '测试应用系统',
    'risk': '高危',
    'version': '<= 1.0.0',
    'condition': '需要认证',
    'poc_available': '是',
    'poison': '10%',
    'markdown': '## 漏洞详情\n\n这是一个测试漏洞，用于验证markdown生成功能是否正常。',
    'repo_name': 'test/repo',
    'repo_url': 'https://github.com/test/repo',
    'cve_url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-99999',
    'reference_url': 'https://nvd.nist.gov',
    'action_log': '新增',
    'git_url': ''
}

print("\n" + "="*70)
print("开始测试markdown生成...")
print("="*70 + "\n")

try:
    filepath = 'data/markdown/2024/CVE-2024-99999-test_repo.md'
    write_to_markdown(test_data, filepath)
    print(f"\n✅ 测试成功！")
    print(f"文件位置: {filepath}")
    print("\n请检查该文件是否存在并包含正确内容。")
except Exception as e:
    print(f"\n❌ 测试失败！")
    print(f"错误: {e}")
    import traceback
    traceback.print_exc()

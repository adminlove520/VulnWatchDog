import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from libs.utils import get_cve_checker

def test_cve_validation():
    """测试修复后的CVE验证逻辑"""
    # 获取CVE检查器实例
    cve_checker = get_cve_checker()
    
    # 测试目标CVE
    target_cve = "CVE-2024-4577"
    print(f"测试CVE验证: {target_cve}")
    
    # 清除缓存以确保测试准确性
    cve_checker.clear_cache()
    
    # 使用check_cve_validity方法
    is_valid, source = cve_checker.check_cve_validity(target_cve)
    print(f"check_cve_validity 结果: 有效={is_valid}, 来源={source}")
    
    # 再次清除缓存并测试_verify_cve方法
    cve_checker.clear_cache()
    result = cve_checker._verify_cve(target_cve)
    print(f"_verify_cve 结果: {result}")
    
    # 单独测试OSCS检查
    result_oscs = cve_checker._check_oscs(target_cve)
    print(f"_check_oscs 结果: {result_oscs}")
    
    # 单独测试CISA检查
    result_cisa = cve_checker._check_cisa(target_cve)
    print(f"_check_cisa 结果: {result_cisa}")

if __name__ == "__main__":
    test_cve_validation()
import logging
import threading
import time
import schedule
from typing import Any, Optional
from libs.cve_checker import CVEChecker

logger = logging.getLogger(__name__)

class TaskScheduler:
    """
    定时任务管理器，负责定期执行漏洞检查、验证和更新任务
    """
    def __init__(self):
        """
        初始化定时任务管理器
        """
        self.running = False
        self.scheduler_thread = None
        self.cve_checker = CVEChecker()
        self.max_workers = 5  # 并发工作线程数
        
    def start(self):
        """
        启动定时任务调度器
        """
        if self.running:
            logger.warning("定时任务调度器已经在运行")
            return
        
        self.running = True
        
        # 设置定时任务
        # 每天凌晨2点执行CVE验证任务
        schedule.every().day.at("02:00").do(self.verify_vulnerabilities)
        
        # 每6小时检查PoC仓库可用性
        schedule.every(6).hours.do(self.check_poc_repositories)
        
        # 每周一上午9点生成报告
        schedule.every().monday.at("09:00").do(self.generate_weekly_report)
        
        # 每小时更新缓存
        schedule.every(1).hour.do(self.update_caches)
        
        # 在新线程中运行调度器
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("定时任务调度器已启动")
        
    def stop(self):
        """
        停止定时任务调度器
        """
        if not self.running:
            logger.warning("定时任务调度器未运行")
            return
        
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        schedule.clear()
        logger.info("定时任务调度器已停止")
        
    def _run_scheduler(self):
        """
        运行调度器的内部方法
        """
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # 每分钟检查一次是否有待执行的任务
            except Exception as e:
                logger.error(f"定时任务调度器异常: {e}")
                time.sleep(60)  # 出错后等待1分钟再继续
        
    def verify_vulnerabilities(self):
        """
        验证所有存储的漏洞信息的可用性
        """
        logger.info("开始执行漏洞验证任务")
        # (简化实现，略去具体数据库操作)
        pass
            
    def check_poc_repositories(self):
        """
        检查PoC仓库的可用性
        """
        logger.info("开始执行PoC仓库检查任务")
        # (简化实现，略去具体数据库操作)
        pass
        
    def generate_weekly_report(self):
        """
        生成每周漏洞报告
        """
        logger.info("开始生成每周漏洞报告")
        # (简化实现，略去具体数据库操作)
        pass
        
    def update_caches(self):
        """
        更新缓存数据
        """
        try:
            # 清除过期的缓存
            self.cve_checker.clear_cache()
            logger.info("缓存已更新")
            
        except Exception as e:
            logger.error(f"更新缓存时发生异常: {e}")

# 创建全局任务调度器实例
task_scheduler = TaskScheduler()

def start_scheduler():
    """
    启动定时任务调度器
    """
    task_scheduler.start()
    return task_scheduler

def stop_scheduler():
    """
    停止定时任务调度器
    """
    task_scheduler.stop()

def get_cve_checker(proxy: Optional[str] = None) -> Any:
    """
    获取CVE检查器实例
    """
    return task_scheduler.cve_checker

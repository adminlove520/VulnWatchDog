#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
手动处理GPT请求重试队列的脚本

这个脚本用于处理之前因各种原因失败的GPT分析请求，尝试重新分析并生成报告。

用法:
    python retry_gpt_requests.py [options]

选项:
    --config CONFIG_FILE  指定配置文件路径
    --persistence FILE    指定持久化文件路径
    --workers NUM         指定工作线程数量
    --no-wait             不等待队列处理完成，立即返回
    --timeout SECONDS     设置等待超时时间(秒)
    --import-legacy FILE  从旧格式文件导入请求
    --debug               启用调试日志
"""

import logging
import time
import argparse
from libs.gpt_queue import GPTQueueManager
from config import get_config

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("retry_log.txt"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='处理GPT请求重试队列')
    parser.add_argument('--config', help='指定配置文件路径')
    parser.add_argument('--persistence', help='指定持久化文件路径')
    parser.add_argument('--workers', type=int, help='指定工作线程数量')
    parser.add_argument('--no-wait', action='store_true', help='不等待队列处理完成，立即返回')
    parser.add_argument('--timeout', type=int, help='设置等待超时时间(秒)')
    parser.add_argument('--import-legacy', help='从旧格式文件导入请求')
    parser.add_argument('--debug', action='store_true', help='启用调试日志')
    return parser.parse_args()

def setup_logging(debug=False):
    """配置日志系统"""
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("retry_log.txt"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def main():
    """主函数，执行重试队列处理"""
    # 解析命令行参数
    args = parse_arguments()
    
    # 设置日志
    logger = setup_logging(args.debug)
    
    logger.info("=" * 60)
    logger.info("开始处理GPT请求重试队列")
    logger.info("=" * 60)
    
    manager = None
    try:
        # 创建队列管理器实例
        config = get_config(config_file=args.config)
        
        # 确定参数值，命令行参数优先于配置文件
        max_workers = args.workers if args.workers is not None else config.get('gpt_queue_max_workers', 2)
        persistence_file = args.persistence or config.get('gpt_queue_persistence_file', 'data/failed_gpt_requests.json')
        
        logger.info(f"初始化队列管理器，最大工作线程数: {max_workers}")
        logger.info(f"持久化文件路径: {persistence_file}")
        
        # 初始化队列管理器
        manager = GPTQueueManager(
            persistence_file=persistence_file,
            max_concurrent_tasks=max_workers
        )
        
        # 处理从旧格式文件导入请求
        if args.import_legacy:
            imported_count = manager.import_legacy_requests(args.import_legacy)
            logger.info(f"已从旧格式文件导入 {imported_count} 个请求")
        
        # 获取队列中的任务数量
        task_count = manager.get_queue_size()
        logger.info(f"队列中待处理任务数: {task_count}")
        
        if task_count == 0:
            logger.info("队列为空，无需处理")
            return
        
        # 开始处理任务
        logger.info("开始处理队列中的任务...")
        start_time = time.time()
        
        # 启动管理器
        manager.start()
        
        # 根据参数决定是否等待队列清空
        if not args.no_wait:
            timeout = args.timeout if args.timeout is not None else None
            logger.info(f"等待队列处理完成{'' if timeout is None else f'，超时时间: {timeout}秒'}")
            
            # 等待队列清空
            is_empty = manager.wait_until_empty(timeout=timeout)
            if not is_empty:
                logger.warning(f"等待超时，队列未完全清空")
        else:
            logger.info("不等待队列处理完成，任务将在后台继续处理")
        
        # 获取处理统计信息
        stats = manager.get_statistics()
        detailed_stats = manager.get_queue_stats()
        
        end_time = time.time()
        
        logger.info(f"处理操作完成")
        logger.info(f"处理耗时: {end_time - start_time:.2f} 秒")
        logger.info(f"成功任务数: {stats['tasks_completed']}")
        logger.info(f"失败任务数: {stats['tasks_failed']}")
        logger.info(f"当前队列剩余: {stats['tasks_remaining']}")
        logger.info(f"平均处理时间: {detailed_stats['avg_processing_time']} 秒/任务")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"处理重试队列时发生错误: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        raise
    finally:
        # 确保管理器被正确停止
        if manager is not None:
            try:
                logger.debug("正在停止队列管理器...")
                manager.stop()
                logger.info("队列管理器已安全停止")
            except Exception as e:
                logger.error(f"停止队列管理器时发生错误: {str(e)}")

if __name__ == "__main__":
    main()
import time
import logging
import threading
import json
import os
import random
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from .gpt_utils import ask_gpt
from .utils import write_to_markdown

logger = logging.getLogger(__name__)

class Priority(Enum):
    """任务优先级枚举"""
    CRITICAL = 0  # 关键任务（如高危漏洞）
    HIGH = 1      # 高优先级
    MEDIUM = 2    # 中优先级
    LOW = 3       # 低优先级

class RetryStatus(Enum):
    """重试状态枚举"""
    PENDING = "pending"      # 等待重试
    PROCESSING = "processing" # 正在处理
    SUCCESS = "success"      # 成功
    FAILED = "failed"        # 最终失败
    ERROR = "error"          # 处理出错

class ErrorType(Enum):
    """错误类型枚举"""
    RATE_LIMIT = "rate_limit"       # 速率限制
    SERVER_ERROR = "server_error"   # 服务器错误
    CLIENT_ERROR = "client_error"   # 客户端错误
    TIMEOUT = "timeout"             # 超时
    PARSE_ERROR = "parse_error"     # 解析错误
    UNKNOWN = "unknown"             # 未知错误

@dataclass
class RetryTask:
    """重试任务数据类"""
    cve_id: str
    prompt: str
    retry_count: int = 0
    max_retries: int = 5
    priority: Priority = Priority.MEDIUM
    status: RetryStatus = RetryStatus.PENDING
    error_type: Optional[ErrorType] = None
    last_error: Optional[str] = None
    created_at: float = 0
    last_attempt: float = 0
    next_attempt: float = 0
    metadata: Dict[str, Any] = None
    task_id: str = None
    # 确保结果中包含必要字段
    required_result_fields: List[str] = None
    
    def __post_init__(self):
        if self.created_at == 0:
            self.created_at = time.time()
        if self.task_id is None:
            self.task_id = f"task_{self.cve_id}_{int(self.created_at)}"
        if self.metadata is None:
            self.metadata = {}
        # 初始化必要结果字段列表
        if self.required_result_fields is None:
            self.required_result_fields = [
                "poc_available", "condition", "fix", "risk_level", 
                "summary", "attack_vector", "affected_component", 
                "poison", "markdown", "repo_name", "repo_url", "cve_url"
            ]
        # 初始计算下次尝试时间
        self.calculate_next_attempt()
    
    def calculate_next_attempt(self):
        """根据重试次数和错误类型计算下次尝试时间"""
        # 基础退避时间（秒）
        base_delay = 5
        
        # 根据错误类型调整退避策略
        if self.error_type == ErrorType.RATE_LIMIT:
            # 对速率限制使用更激进的退避
            base_delay = 10
        elif self.error_type == ErrorType.TIMEOUT:
            # 对超时使用稍长的退避
            base_delay = 7
        elif self.error_type == ErrorType.SERVER_ERROR:
            # 服务器错误可能需要更长时间恢复
            base_delay = 15
        
        # 指数退避 + 抖动
        backoff = base_delay * (2 ** min(self.retry_count, 5))  # 最大指数退避
        jitter = random.uniform(0.8, 1.2)  # 20%的随机性以避免雪崩
        
        # 为关键优先级任务减少延迟
        priority_factor = 0.5 if self.priority == Priority.CRITICAL else 1.0
        
        self.next_attempt = time.time() + (backoff * jitter * priority_factor)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = asdict(self)
        # 转换枚举为字符串
        result['priority'] = self.priority.value
        result['status'] = self.status.value
        if self.error_type:
            result['error_type'] = self.error_type.value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RetryTask':
        """从字典创建RetryTask"""
        data = data.copy()  # 创建副本以避免修改原始数据
        # 转换字符串回枚举
        data['priority'] = Priority(data['priority'])
        data['status'] = RetryStatus(data['status'])
        if 'error_type' in data and data['error_type']:
            data['error_type'] = ErrorType(data['error_type'])
        return cls(**data)

class GPTQueueManager:
    """GPT请求队列管理器"""
    
    def __init__(self, 
                 persistence_file: str = "data/failed_gpt_requests.json",
                 max_concurrent_tasks: int = 2,
                 auto_save_interval: int = 300,  # 5分钟自动保存
                 monitor_interval: int = 60):    # 1分钟监控检查
        """初始化队列管理器
        
        参数:
            persistence_file: 持久化文件路径
            max_concurrent_tasks: 最大并发任务数
            auto_save_interval: 自动保存间隔（秒）
            monitor_interval: 监控检查间隔（秒）
        """
        self.tasks: Dict[str, RetryTask] = {}  # 任务字典，使用task_id作为键
        self.priority_queue: List[RetryTask] = []  # 优先级队列
        self.lock = threading.RLock()  # 可重入锁保证线程安全
        self.persistence_file = persistence_file
        self.max_concurrent_tasks = max_concurrent_tasks
        self.active_tasks: Set[str] = set()  # 当前活动任务ID集合
        
        # 确保数据目录存在
        dir_name = os.path.dirname(self.persistence_file)
        if dir_name:  # 只有当目录名不为空时才创建
            os.makedirs(dir_name, exist_ok=True)
        
        # 异步处理线程
        self.worker_threads: List[threading.Thread] = []
        self.stop_event = threading.Event()
        self.task_available = threading.Condition(self.lock)
        
        # 统计信息
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'processing_time': 0,
            'last_processed': None
        }
        
        # 启动自动保存线程
        self.auto_save_thread = threading.Thread(target=self._auto_save_loop, 
                                               args=(auto_save_interval,), 
                                               daemon=True)
        self.auto_save_thread.start()
        
        # 启动监控线程
        self.monitor_thread = threading.Thread(target=self._monitor_loop, 
                                             args=(monitor_interval,), 
                                             daemon=True)
        self.monitor_thread.start()
        
        # 加载持久化数据
        self.load_tasks()
        
        # 启动工作线程
        self._start_workers()
    
    def _start_workers(self):
        """启动工作线程"""
        for i in range(self.max_concurrent_tasks):
            thread = threading.Thread(target=self._worker_loop, 
                                     args=(i,), 
                                     daemon=True)
            self.worker_threads.append(thread)
            thread.start()
    
    def _worker_loop(self, worker_id: int):
        """工作线程循环"""
        logger.info(f"工作线程 {worker_id} 已启动")
        
        while not self.stop_event.is_set():
            try:
                task = self._get_next_task()
                if task:
                    self._process_task(task, worker_id)
                else:
                    # 没有任务可处理，等待
                    with self.task_available:
                        self.task_available.wait(timeout=5)  # 5秒超时，以便检查stop_event
            except Exception as e:
                logger.error(f"工作线程 {worker_id} 异常: {str(e)}")
                time.sleep(1)  # 避免异常风暴
    
    def _get_next_task(self) -> Optional[RetryTask]:
        """获取下一个待处理的任务"""
        with self.lock:
            # 过滤出可处理的任务（状态为PENDING且已到执行时间）
            current_time = time.time()
            available_tasks = [
                task for task in self.tasks.values() 
                if task.status == RetryStatus.PENDING and 
                   task.task_id not in self.active_tasks and
                   task.next_attempt <= current_time
            ]
            
            if not available_tasks:
                return None
            
            # 按优先级和创建时间排序
            available_tasks.sort(key=lambda t: (t.priority.value, t.created_at))
            
            # 标记任务为处理中
            task = available_tasks[0]
            task.status = RetryStatus.PROCESSING
            self.active_tasks.add(task.task_id)
            
            logger.debug(f"工作线程获取任务: {task.cve_id}, 优先级: {task.priority.name}")
            return task
    
    def _process_task(self, task: RetryTask, worker_id: int):
        """处理单个任务"""
        start_time = time.time()
        logger.info(f"工作线程 {worker_id} 开始处理任务: {task.cve_id} (第{task.retry_count + 1}次尝试)")
        
        try:
            # 调用GPT API
            result = ask_gpt(task.prompt)
            
            # 验证结果格式
            if result:
                if not isinstance(result, dict):
                    logger.error(f"任务 {task.cve_id} 返回结果格式错误，不是预期的字典类型")
                    # 如果结果不是字典，尝试解析或创建默认字典
                    try:
                        if isinstance(result, str):
                            import json
                            result = json.loads(result)
                        else:
                            result = {}
                    except:
                        result = {}
                # 处理成功
                self._handle_success(task, result, start_time)
            else:
                # 处理失败
                self._handle_failure(task, "API返回空结果", ErrorType.CLIENT_ERROR, start_time)
                
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if hasattr(e, 'response') and e.response else None
            
            if status_code == 429:
                error_type = ErrorType.RATE_LIMIT
                error_msg = f"速率限制错误 (429): {str(e)}"
            elif status_code >= 500:
                error_type = ErrorType.SERVER_ERROR
                error_msg = f"服务器错误 ({status_code}): {str(e)}"
            elif status_code >= 400:
                error_type = ErrorType.CLIENT_ERROR
                error_msg = f"客户端错误 ({status_code}): {str(e)}"
            else:
                error_type = ErrorType.UNKNOWN
                error_msg = f"HTTP错误: {str(e)}"
            
            self._handle_failure(task, error_msg, error_type, start_time)
            
        except requests.exceptions.Timeout:
            self._handle_failure(task, "请求超时", ErrorType.TIMEOUT, start_time)
            
        except json.JSONDecodeError:
            self._handle_failure(task, "JSON解析错误", ErrorType.PARSE_ERROR, start_time)
            
        except Exception as e:
            self._handle_failure(task, f"处理异常: {str(e)}", ErrorType.UNKNOWN, start_time)
            
        finally:
            # 从活动任务中移除
            with self.lock:
                self.active_tasks.discard(task.task_id)
    
    def _handle_success(self, task: RetryTask, result: Dict[str, Any], start_time: float):
        """处理成功结果"""
        processing_time = time.time() - start_time
        
        with self.lock:
            # 确保结果包含所有必要字段
            if isinstance(result, dict) and hasattr(task, 'required_result_fields'):
                # 设置默认值确保必要字段存在
                for field in task.required_result_fields:
                    if field not in result:
                        if field == "poison":
                            result[field] = "未知"
                        elif field == "markdown":
                            result[field] = f"# CVE-{task.cve_id}\n\n## 漏洞描述\n暂无详细信息\n\n## 漏洞影响\n未知\n\n## 建议修复\n请参考官方安全公告"
                        elif field == "repo_name":
                            result[field] = "VulnWatchdog"
                        elif field == "repo_url":
                            result[field] = "https://github.com/VulnWatchdog/VulnWatchdog"
                        elif field == "cve_url":
                            result[field] = f"https://nvd.nist.gov/vuln/detail/{task.cve_id}"
                        else:
                            result[field] = "未知"
                            logger.warning(f"任务 {task.cve_id} 结果中缺少字段: {field}，已设置为默认值")
            
            task.status = RetryStatus.SUCCESS
            task.last_attempt = time.time()
            
            # 更新统计信息
            self.stats['completed_tasks'] += 1
            self.stats['processing_time'] += processing_time
            self.stats['last_processed'] = time.time()
            
            # 尝试生成报告
            try:
                # 确保结果包含必要的字段
                if 'cve_id' not in result:
                    result['cve_id'] = task.cve_id
                
                # 生成markdown文件路径（按年份分类）
                year = task.cve_id.split('-')[1]
                filepath = f"data/markdown/{year}/{task.cve_id}.md"
                write_to_markdown(result, filepath)
                logger.info(f"任务 {task.cve_id} 处理成功，已生成报告: {filepath}")
            except Exception as e:
                logger.error(f"任务 {task.cve_id} 虽然API调用成功，但生成报告失败: {str(e)}")
            
            # 从任务列表中移除
            if task.task_id in self.tasks:
                del self.tasks[task.task_id]
            
        # 保存状态
        self.save_tasks()
    
    def _handle_failure(self, task: RetryTask, error_msg: str, error_type: ErrorType, start_time: float):
        """处理失败结果"""
        with self.lock:
            task.retry_count += 1
            task.last_attempt = time.time()
            task.last_error = error_msg
            task.error_type = error_type
            
            # 更新统计信息
            self.stats['processing_time'] += time.time() - start_time
            
            if task.retry_count >= task.max_retries:
                # 达到最大重试次数
                task.status = RetryStatus.FAILED
                self.stats['failed_tasks'] += 1
                logger.error(f"任务 {task.cve_id} 已达到最大重试次数 {task.max_retries}，最终失败: {error_msg}")
                
                # 可选：将最终失败的任务移动到失败列表或标记为特殊状态
            else:
                # 计算下次尝试时间
                task.status = RetryStatus.PENDING
                task.calculate_next_attempt()
                logger.warning(f"任务 {task.cve_id} 第 {task.retry_count} 次尝试失败，下次尝试时间: {datetime.fromtimestamp(task.next_attempt).strftime('%Y-%m-%d %H:%M:%S')}，错误: {error_msg}")
        
        # 保存状态
        self.save_tasks()
        
        # 通知等待的工作线程
        with self.task_available:
            self.task_available.notify_all()
    
    def add_task(self, 
                cve_id: str, 
                prompt: str, 
                priority: Priority = Priority.MEDIUM,
                max_retries: int = 5,
                metadata: Optional[Dict[str, Any]] = None) -> str:
        """添加新任务到队列
        
        参数:
            cve_id: CVE编号
            prompt: 提示词
            priority: 任务优先级
            max_retries: 最大重试次数
            metadata: 附加元数据
        
        返回:
            任务ID
        """
        with self.lock:
            # 检查是否已存在相同的CVE任务
            for existing_task in self.tasks.values():
                if (existing_task.cve_id == cve_id and 
                    existing_task.status != RetryStatus.SUCCESS and 
                    existing_task.status != RetryStatus.FAILED):
                    logger.warning(f"任务 {cve_id} 已在队列中，不重复添加")
                    return existing_task.task_id
            
            # 创建新任务
            task = RetryTask(
                cve_id=cve_id,
                prompt=prompt,
                priority=priority,
                max_retries=max_retries,
                metadata=metadata
            )
            
            # 添加到任务字典
            self.tasks[task.task_id] = task
            
            # 更新统计信息
            self.stats['total_tasks'] += 1
            
            logger.info(f"已将任务 {cve_id} 加入队列，优先级: {priority.name}，任务ID: {task.task_id}")
            
            # 保存状态
            self.save_tasks()
            
            # 通知等待的工作线程
            with self.task_available:
                self.task_available.notify_all()
            
            return task.task_id
    
    def save_tasks(self):
        """持久化任务到文件"""
        try:
            with self.lock:
                # 只保存非成功状态的任务
                tasks_to_save = [
                    task.to_dict() for task in self.tasks.values()
                    if task.status != RetryStatus.SUCCESS
                ]
                
            with open(self.persistence_file, 'w', encoding='utf-8') as f:
                json.dump(tasks_to_save, f, ensure_ascii=False, indent=2)
                
            logger.debug(f"已持久化 {len(tasks_to_save)} 个任务到 {self.persistence_file}")
        except Exception as e:
            logger.error(f"持久化任务失败: {str(e)}")
    
    def load_tasks(self):
        """从文件加载任务"""
        try:
            if not os.path.exists(self.persistence_file):
                logger.warning(f"持久化文件不存在: {self.persistence_file}")
                return
            
            with open(self.persistence_file, 'r', encoding='utf-8') as f:
                tasks_data = json.load(f)
            
            with self.lock:
                loaded_count = 0
                for task_data in tasks_data:
                    task = RetryTask.from_dict(task_data)
                    # 重置正在处理的任务为等待状态
                    if task.status == RetryStatus.PROCESSING:
                        task.status = RetryStatus.PENDING
                        task.calculate_next_attempt()
                    
                    self.tasks[task.task_id] = task
                    loaded_count += 1
                
                # 更新统计信息
                self.stats['total_tasks'] += loaded_count
            
            logger.info(f"从 {self.persistence_file} 加载了 {loaded_count} 个任务")
        except Exception as e:
            logger.error(f"加载任务失败: {str(e)}")
    
    def _auto_save_loop(self, interval: int):
        """自动保存循环"""
        while not self.stop_event.is_set():
            time.sleep(interval)
            try:
                self.save_tasks()
                logger.debug("自动保存任务完成")
            except Exception as e:
                logger.error(f"自动保存失败: {str(e)}")
    
    def _monitor_loop(self, interval: int):
        """监控循环"""
        while not self.stop_event.is_set():
            time.sleep(interval)
            try:
                self._log_monitoring_stats()
                self._check_stuck_tasks()
            except Exception as e:
                logger.error(f"监控循环异常: {str(e)}")
    
    def _log_monitoring_stats(self):
        """记录监控统计信息"""
        with self.lock:
            pending = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PENDING)
            processing = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PROCESSING)
            failed = sum(1 for t in self.tasks.values() if t.status == RetryStatus.FAILED)
            success = self.stats['completed_tasks']
            
            logger.info(f"监控统计 - 待处理: {pending}, 处理中: {processing}, 成功: {success}, 失败: {failed}, 总任务: {self.stats['total_tasks']}")
    
    def _check_stuck_tasks(self):
        """检查卡住的任务"""
        current_time = time.time()
        stuck_threshold = 300  # 5分钟视为卡住
        
        with self.lock:
            for task in self.tasks.values():
                if (task.status == RetryStatus.PROCESSING and 
                    current_time - task.last_attempt > stuck_threshold):
                    logger.warning(f"任务 {task.cve_id} 疑似卡住，重置状态")
                    task.status = RetryStatus.PENDING
                    task.calculate_next_attempt()
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """获取队列统计信息
        
        返回:
            统计信息字典
        """
        with self.lock:
            pending = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PENDING)
            processing = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PROCESSING)
            failed = sum(1 for t in self.tasks.values() if t.status == RetryStatus.FAILED)
            
            avg_processing_time = (
                self.stats['processing_time'] / self.stats['completed_tasks'] 
                if self.stats['completed_tasks'] > 0 else 0
            )
            
            return {
                'total_tasks': self.stats['total_tasks'],
                'pending_tasks': pending,
                'processing_tasks': processing,
                'completed_tasks': self.stats['completed_tasks'],
                'failed_tasks': failed,
                'active_workers': len(self.active_tasks),
                'avg_processing_time': round(avg_processing_time, 2),
                'last_processed': (
                    datetime.fromtimestamp(self.stats['last_processed']).strftime('%Y-%m-%d %H:%M:%S')
                    if self.stats['last_processed'] else None
                )
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息，为retry_gpt_requests.py提供兼容接口
        
        返回:
            统计信息字典
        """
        stats = self.get_queue_stats()
        return {
            'tasks_completed': stats['completed_tasks'],
            'tasks_failed': stats['failed_tasks'],
            'tasks_remaining': stats['pending_tasks'] + stats['processing_tasks']
        }
    
    def wait_until_empty(self, timeout: Optional[float] = None) -> bool:
        """等待队列处理完成
        
        参数:
            timeout: 超时时间（秒），None表示无限等待
        
        返回:
            队列是否已清空
        """
        start_time = time.time()
        
        while True:
            # 检查是否超时
            if timeout is not None and time.time() - start_time > timeout:
                return False
            
            with self.lock:
                pending = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PENDING)
                processing = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PROCESSING)
                
                # 如果没有待处理和处理中的任务，则队列为空
                if pending == 0 and processing == 0:
                    return True
            
            # 短暂休眠后再次检查
            time.sleep(1)
    
    def get_queue_size(self) -> int:
        """获取当前队列中的任务总数
        
        返回:
            队列中的任务数
        """
        with self.lock:
            return len(self.tasks)
    
    def import_legacy_requests(self, legacy_file: str = "failed_gpt_requests.json") -> int:
        """从旧格式文件导入失败请求
        
        参数:
            legacy_file: 旧格式文件路径
            
        返回:
            成功导入的任务数
        """
        imported_count = 0
        try:
            if not os.path.exists(legacy_file):
                logger.debug(f"旧格式文件不存在: {legacy_file}")
                return 0
            
            with open(legacy_file, 'r', encoding='utf-8') as f:
                old_requests = json.load(f)
                
            # 导入旧格式的请求
            for req in old_requests:
                if 'cve_id' in req and 'prompt' in req:
                    self.add_task(
                        cve_id=req['cve_id'],
                        prompt=req['prompt'],
                        metadata={"legacy": True, "original_retry_count": req.get('retry_count', 0)}
                    )
                    imported_count += 1
            
            logger.info(f"从旧格式文件 {legacy_file} 导入了 {imported_count} 个失败请求")
        except Exception as e:
            logger.error(f"导入旧格式失败请求时出错: {str(e)}")
        
        return imported_count
    
    def start(self):
        """启动队列管理器
        
        注意：GPTQueueManager在初始化时已经自动启动了工作线程，
        此方法是为了API兼容性而提供的，调用时不会执行任何操作。
        
        返回:
            bool: 始终返回True
        """
        logger.debug("队列管理器启动请求已接收（实际上在初始化时已启动）")
        # 由于管理器在初始化时已经启动，这里不需要额外操作
        # 只是为了API兼容性而提供这个方法
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息，为retry_gpt_requests.py提供兼容接口
        
        返回:
            统计信息字典
        """
        stats = self.get_queue_stats()
        return {
            'tasks_completed': stats['completed_tasks'],
            'tasks_failed': stats['failed_tasks'],
            'tasks_remaining': stats['pending_tasks'] + stats['processing_tasks']
        }
    
    def wait_until_empty(self, timeout: Optional[float] = None) -> bool:
        """等待队列处理完成
        
        参数:
            timeout: 超时时间（秒），None表示无限等待
        
        返回:
            队列是否已清空
        """
        start_time = time.time()
        
        while True:
            # 检查是否超时
            if timeout is not None and time.time() - start_time > timeout:
                return False
            
            with self.lock:
                pending = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PENDING)
                processing = sum(1 for t in self.tasks.values() if t.status == RetryStatus.PROCESSING)
                
                # 如果没有待处理和处理中的任务，则队列为空
                if pending == 0 and processing == 0:
                    return True
            
            # 短暂休眠后再次检查
            time.sleep(1)
    
    def get_queue_size(self) -> int:
        """获取当前队列中的任务总数
        
        返回:
            队列中的任务数
        """
        with self.lock:
            return len(self.tasks)
    
    def import_legacy_requests(self, legacy_file: str = "failed_gpt_requests.json") -> int:
        """从旧格式文件导入失败请求
        
        参数:
            legacy_file: 旧格式文件路径
            
        返回:
            成功导入的任务数
        """
        imported_count = 0
        try:
            if not os.path.exists(legacy_file):
                logger.debug(f"旧格式文件不存在: {legacy_file}")
                return 0
            
            with open(legacy_file, 'r', encoding='utf-8') as f:
                old_requests = json.load(f)
                
            # 导入旧格式的请求
            for req in old_requests:
                if 'cve_id' in req and 'prompt' in req:
                    self.add_task(
                        cve_id=req['cve_id'],
                        prompt=req['prompt'],
                        metadata={"legacy": True, "original_retry_count": req.get('retry_count', 0)}
                    )
                    imported_count += 1
            
            logger.info(f"从旧格式文件 {legacy_file} 导入了 {imported_count} 个失败请求")
        except Exception as e:
            logger.error(f"导入旧格式失败请求时出错: {str(e)}")
        
        return imported_count
    
    def stop(self):
        """停止队列管理器"""
        logger.info("正在停止队列管理器...")
        
        # 设置停止事件
        self.stop_event.set()
        
        # 通知所有等待的线程
        with self.task_available:
            self.task_available.notify_all()
        
        # 等待所有线程结束
        for thread in self.worker_threads + [self.auto_save_thread, self.monitor_thread]:
            if thread.is_alive():
                thread.join(timeout=5)  # 最多等待5秒
        
        # 最终保存
        self.save_tasks()
        
        logger.info("队列管理器已停止")

# 创建全局队列管理器实例
gpt_queue_manager = GPTQueueManager()

# 尝试导入旧格式的失败请求
gpt_queue_manager.import_legacy_requests("failed_gpt_requests.json")

def queue_gpt_retry(cve_id: str, prompt: str, priority: int = 2):
    """向后兼容的队列GPT请求函数
    
    这是为了保持与旧版代码的兼容性而提供的包装函数。
    
    参数:
        cve_id: CVE编号
        prompt: 提示词
        priority: 优先级（0-3，0为最高）
    
    返回:
        任务ID
    """
    # 将整数优先级转换为Priority枚举
    try:
        priority_enum = Priority(priority)
    except ValueError:
        logger.warning(f"无效的优先级值: {priority}，使用默认值 MEDIUM")
        priority_enum = Priority.MEDIUM
    
    return gpt_queue_manager.add_task(cve_id, prompt, priority=priority_enum)

# 示例用法
"""
# 添加一个高优先级任务
task_id = gpt_queue_manager.add_task(
    cve_id="CVE-2023-1234",
    prompt="分析这个漏洞的严重性和影响",
    priority=Priority.HIGH
)

# 获取队列统计
stats = gpt_queue_manager.get_queue_stats()
print(f"当前队列中有 {stats['pending_tasks']} 个待处理任务")

# 等待队列处理完成
gpt_queue_manager.wait_until_empty()
print("所有任务处理完成")

# 停止队列管理器
gpt_queue_manager.stop()
"""
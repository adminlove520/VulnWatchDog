import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text, inspect, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session
from contextlib import contextmanager
from config import get_config
import logging


logger = logging.getLogger(__name__)
# 创建数据库连接，配置连接池
db_url = get_config('DB_URL')

# 配置SQLAlchemy引擎，优化连接池设置
engine = create_engine(
    db_url,
    pool_size=10,  # 连接池大小
    max_overflow=20,  # 最大溢出连接数
    pool_pre_ping=True,  # 连接池预检查，确保连接有效
    pool_recycle=3600,  # 连接回收时间（秒）
    echo=False  # 是否打印SQL语句
)

# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):  # 改这里
    pass

class CVE(Base):
    __tablename__ = 'cves'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), unique=True, nullable=False)
    title = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    cve_data = Column(JSON, nullable=False)
    is_valid = Column(Boolean, default=None, nullable=True)  # None表示未验证，True表示有效，False表示无效
    validation_source = Column(String, nullable=True)  # 验证来源：CISA、OSCS、GitHub PoC等
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Repository(Base):
    __tablename__ = 'repositories'
    
    id = Column(Integer, primary_key=True)
    github_id = Column(Integer, nullable=False)
    cve_id = Column(String(20), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(255), nullable=False)
    repo_data = Column(JSON, nullable=False)
    repo_pushed_at = Column(String(20), nullable=False)
    action_log = Column(String(10), nullable=False)  # new/update
    gpt_analysis = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


def init_db():
    """初始化数据库，创建所有表"""
    Base.metadata.create_all(bind=engine)
    logger.info(f"数据库表初始化完成: {db_url}")

@contextmanager
def get_db_session():
    """数据库会话上下文管理器，自动处理会话的创建和关闭"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def get_db():
    """获取数据库会话，兼容现有代码"""
    # 确保表存在
    inspector = inspect(engine)
    if not inspector.has_table("cves") or not inspector.has_table("repositories"):
        logger.info(f"数据库表不存在，正在创建: {db_url}")
        init_db()
    
    # 返回会话
    return SessionLocal()
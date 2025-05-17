from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# 创建数据库引擎
engine = create_engine('sqlite:///users.db')
Base = declarative_base()

# 用户表
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    role = Column(String, default='user')

# 登录日志表
class LoginLog(Base):
    __tablename__ = 'login_logs'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    ip = Column(String)
    success = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.utcnow)

# 创建所有表
Base.metadata.create_all(engine)

# 创建数据库会话
Session = sessionmaker(bind=engine)

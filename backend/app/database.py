"""
database.py
------------
SQLite database setup (swap DATABASE_URL for PostgreSQL in production
without changing any other code -- SQLAlchemy handles both).
"""

import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./security_copilot.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    protocol_type = Column(String)
    duration = Column(Float)
    src_bytes = Column(Float)
    dst_bytes = Column(Float)
    count = Column(Integer)
    srv_count = Column(Integer)
    same_srv_rate = Column(Float)
    diff_srv_rate = Column(Float)
    serror_rate = Column(Float)
    rerror_rate = Column(Float)
    num_failed_logins = Column(Integer)
    logged_in = Column(Integer)
    wrong_fragment = Column(Integer)
    urgent = Column(Integer)
    hot = Column(Integer)

    predicted_label = Column(String, index=True)   # model's classification
    severity = Column(String, index=True)           # normal / suspicious / critical
    confidence = Column(Float)
    anomaly_score = Column(Float)
    is_anomaly = Column(Boolean, default=False)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

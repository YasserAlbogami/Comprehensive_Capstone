# db.py
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, JSON
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql+psycopg2://postgres:123456@localhost:5432/projects")
Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Packet(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)

    iface = Column(String(64), index=True, nullable=True)
    src_mac = Column(String(32), nullable=True)
    dst_mac = Column(String(32), nullable=True)
    bssid = Column(String(32), nullable=True)

    frame_len = Column(Integer, nullable=True)
    channel_freq = Column(Integer, nullable=True)
    datarate = Column(Float, nullable=True)
    signal_dbm = Column(Float, nullable=True)
    wlan_ds = Column(Integer, nullable=True)
    wlan_retry = Column(Integer, nullable=True)
    wlan_type = Column(Integer, nullable=True)
    wlan_subtype = Column(Integer, nullable=True)
    wlan_duration = Column(Integer, nullable=True)

    proba_anomaly = Column(Float, nullable=True)
    proba_attack = Column(Float, nullable=True)
    predicted_label = Column(String(64), nullable=True)

    raw = Column(JSON, nullable=True)


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    title = Column(String(256), nullable=True)
    text = Column(Text, nullable=False)
    tags = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


# 👇 Add this dependency
from sqlalchemy.orm import Session
from contextlib import contextmanager

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Packet(Base):
    __tablename__ = "packet"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float)
    frame_time_delta = Column(Float)
    frame_time_epoch = Column(Float)
    frame_number = Column(Integer)
    frame_len = Column(Float)
    radiotap_datarate = Column(Float)
    radiotap_dbm_antsignal = Column(Float)
    radiotap_channel_freq = Column(Float)
    radiotap_mactime = Column(Float)
    wlan_duration = Column(Float)
    wlan_fc_type = Column(Integer)
    wlan_fc_subtype = Column(Integer)
    wlan_bssid = Column(String)
    wlan_sa = Column(String)
    wlan_da = Column(String)
    label = Column(Integer, nullable=False)
    proba_attack = Column(Float, nullable=False)
    attack_type = Column(String)

# models.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from database import Base


class User(Base):
    """Représente un compte utilisateur (un technicien)."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)

    # Relation 1-N : un user possède plusieurs scans
    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")


class Scan(Base):
    """Représente un fichier XML uploadé et analysé (un scan complet)."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    date_creation = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # --- Nouveau : chaque scan appartient à un utilisateur ---
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="scans")

    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")


class Host(Base):
    """Représente une machine détectée au sein d'un scan."""
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    ip = Column(String, nullable=False)
    status = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    os = Column(String, nullable=True)
    open_ports = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="hosts")
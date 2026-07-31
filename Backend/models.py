# models.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from database import Base


class Scan(Base):
    """Représente un fichier XML uploadé et analysé (un scan complet)."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    date_creation = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relation 1-N : un scan a plusieurs hosts.
    # cascade="all, delete-orphan" : si on supprime un Scan, ses Hosts associés
    # sont supprimés automatiquement (évite les lignes orphelines en base).
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

    # Stocké en JSON texte car SQLite n'a pas de type "liste" natif.
    # On sérialise/désérialise manuellement dans main.py.
    open_ports = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="hosts")
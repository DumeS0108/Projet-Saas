# database.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# --- Connexion SQLite ---
# Le fichier sera créé automatiquement au premier lancement, dans le dossier backend/
DATABASE_URL = "sqlite:///./scans.db"

# check_same_thread=False est requis pour SQLite avec FastAPI :
# FastAPI peut gérer chaque requête sur un thread différent, ce que SQLite
# interdit par défaut pour une même connexion.
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

# Fabrique de sessions : chaque requête API en ouvrira une nouvelle
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Classe de base dont hériteront tous nos modèles (Scan, Host)
Base = declarative_base()


def get_db():
    """
    Dependency FastAPI : fournit une session DB à chaque route qui en a besoin,
    et la ferme automatiquement une fois la requête terminée (via yield/finally).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
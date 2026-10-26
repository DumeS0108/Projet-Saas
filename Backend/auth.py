# auth.py

import os
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database import get_db
import models


# --- Configuration JWT ---
# En production, cette clé DOIT venir d'une variable d'environnement,
# jamais codée en dur dans le code source versionné.
SECRET_KEY = os.getenv("SECRET_KEY", "change-moi-en-variable-environnement-avant-la-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h, confortable pour du dev/MVP

# --- Configuration du hachage de mot de passe ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Indique à FastAPI où se trouve la route de login, pour générer
# automatiquement le petit formulaire d'auth dans Swagger (/docs)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")


def hash_password(password: str) -> str:
    """Transforme un mot de passe en clair en hash bcrypt (jamais l'inverse)."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compare un mot de passe en clair à son hash stocké en base."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    """Génère un JWT signé, contenant les données fournies + une date d'expiration."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    Dependency FastAPI : décode le token JWT reçu dans le header Authorization,
    vérifie sa validité, et retourne l'utilisateur correspondant en base.
    Toute route qui déclare `Depends(get_current_user)` est automatiquement protégée.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Impossible de valider les identifiants.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        # Token expiré, signature invalide, malformé, etc.
        raise credentials_exception

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception

    return user
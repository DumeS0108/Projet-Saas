import os
import json
import uuid
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from nmap_parser import parse_nmap_xml
from cve_engine import search_cve
from remediation_engine import get_remediations
from database import engine, get_db, Base
import models
import auth

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Network Report SaaS API")

# --- CONFIGURATION CORS UNIQUE ET PROPRE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "http://127.0.0.1:5173",
        "http://192.168.1.174:5173" # Ajout de ton IP réseau
    ], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)


TEMP_DIR = "temp_uploads"
os.makedirs(TEMP_DIR, exist_ok=True)


# ============================================================
# --- Schémas Pydantic ---
# ============================================================

class UserCreate(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# ============================================================
# --- Routes d'authentification ---
# ============================================================

@app.post("/api/register", response_model=Token)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(
        models.User.username == user_data.username
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Ce nom d'utilisateur est déjà pris.")

    new_user = models.User(
        username=user_data.username,
        hashed_password=auth.hash_password(user_data.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token = auth.create_access_token(data={"sub": new_user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(
        models.User.username == form_data.username
    ).first()

    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# ============================================================
# --- Routes métier (protégées) ---
# ============================================================

@app.post("/api/upload-scan")
async def upload_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Parse le XML, enrichit chaque port avec les CVE connues, calcule les
    remédiations par host, sauvegarde le tout en base, et retourne le JSON complet.
    """

    if not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="Le fichier doit être un .xml")

    temp_filename = f"{uuid.uuid4()}.xml"
    temp_filepath = os.path.join(TEMP_DIR, temp_filename)

    try:
        contents = await file.read()
        with open(temp_filepath, "wb") as f:
            f.write(contents)

        parsed_data = parse_nmap_xml(temp_filepath)

        if not parsed_data:
            raise HTTPException(
                status_code=422,
                detail="Aucun host valide trouvé dans le fichier XML fourni."
            )

        new_scan = models.Scan(filename=file.filename, user_id=current_user.id)
        db.add(new_scan)
        db.flush()

        enriched_hosts = []

        for host_data in parsed_data:
            enriched_ports = []
            for port in host_data["open_ports"]:
                product = port.get("product")
                version = port.get("version")
                cves = search_cve(product, version) if product and version else []
                enriched_ports.append({**port, "cves": cves})

            # --- Remédiations calculées à partir des ports enrichis ---
            remediations = get_remediations(enriched_ports)

            new_host = models.Host(
                scan_id=new_scan.id,
                ip=host_data["ip"],
                status=host_data["status"],
                mac_address=host_data["mac_address"],
                vendor=host_data["vendor"],
                hostname=host_data["hostname"],
                os=host_data["os"],
                open_ports=json.dumps(enriched_ports),
            )
            db.add(new_host)

            enriched_hosts.append({
                **host_data,
                "open_ports": enriched_ports,
                "remediations": remediations,
            })

        db.commit()
        db.refresh(new_scan)

        return {
            "scan_id": new_scan.id,
            "filename": file.filename,
            "hosts_count": len(enriched_hosts),
            "hosts": enriched_hosts,
        }

    except HTTPException:
        raise

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=422, detail=f"Erreur lors du parsing : {str(e)}")

    finally:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)


@app.get("/api/scans")
def list_scans(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == current_user.id)
        .order_by(models.Scan.date_creation.desc())
        .all()
    )

    return [
        {
            "id": scan.id,
            "filename": scan.filename,
            "date_creation": scan.date_creation,
            "hosts_count": len(scan.hosts),
        }
        for scan in scans
    ]


@app.get("/api/scans/{scan_id}")
def get_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    """
    Retourne le détail complet d'un scan, avec CVE (stockées en base) et
    remédiations (recalculées à la volée à partir des ports, pour toujours
    refléter la version la plus à jour des règles de sécurité).
    """
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id, models.Scan.user_id == current_user.id)
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail=f"Aucun scan trouvé avec l'ID {scan_id}."
        )

    hosts = []
    for host in scan.hosts:
        open_ports = json.loads(host.open_ports) if host.open_ports else []
        hosts.append({
            "ip": host.ip,
            "status": host.status,
            "mac_address": host.mac_address,
            "vendor": host.vendor,
            "hostname": host.hostname,
            "os": host.os,
            "open_ports": open_ports,
            "remediations": get_remediations(open_ports),
        })

    return {
        "scan_id": scan.id,
        "filename": scan.filename,
        "date_creation": scan.date_creation,
        "hosts_count": len(hosts),
        "hosts": hosts,
    }


@app.get("/")
def root():
    return {"status": "API is running"}
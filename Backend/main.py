# main.py

import os
import json
import uuid
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from nmap_parser import parse_nmap_xml
from database import engine, get_db, Base
import models


# --- Création des tables au démarrage ---
# Base.metadata.create_all vérifie quelles tables existent déjà et ne crée
# que celles qui manquent. Sans effet si scans.db et ses tables existent déjà.
Base.metadata.create_all(bind=engine)


app = FastAPI(title="Network Report SaaS API")


origins = [
    "http://localhost:3000",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


TEMP_DIR = "temp_uploads"
os.makedirs(TEMP_DIR, exist_ok=True)


@app.post("/api/upload-scan")
async def upload_scan(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Reçoit un fichier XML Nmap, le parse, sauvegarde le résultat en base,
    et retourne le JSON enrichi avec l'ID du scan enregistré.
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

        # --- Sauvegarde en base ---

        # 1. Création de la ligne "Scan" parente
        new_scan = models.Scan(filename=file.filename)
        db.add(new_scan)
        db.flush()  # flush (sans commit) pour obtenir new_scan.id avant l'insertion des hosts

        # 2. Création d'une ligne "Host" par machine détectée
        for host_data in parsed_data:
            new_host = models.Host(
                scan_id=new_scan.id,
                ip=host_data["ip"],
                status=host_data["status"],
                mac_address=host_data["mac_address"],
                vendor=host_data["vendor"],
                hostname=host_data["hostname"],
                os=host_data["os"],
                open_ports=json.dumps(host_data["open_ports"]),  # liste -> texte JSON
            )
            db.add(new_host)

        db.commit()  # valide la transaction (Scan + tous les Hosts, tout ou rien)
        db.refresh(new_scan)

        return {
            "scan_id": new_scan.id,
            "filename": file.filename,
            "hosts_count": len(parsed_data),
            "hosts": parsed_data,
        }

    except HTTPException:
        # On relance telle quelle une HTTPException déjà levée volontairement
        # (évite qu'elle soit re-catchée par le except Exception ci-dessous)
        raise

    except Exception as e:
        db.rollback()  # annule toute insertion partielle en cas d'erreur en cours de route
        raise HTTPException(status_code=422, detail=f"Erreur lors du parsing : {str(e)}")

    finally:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    """
    Retourne l'historique de tous les scans effectués,
    avec le nombre d'hosts associés à chacun.
    """
    scans = db.query(models.Scan).order_by(models.Scan.date_creation.desc()).all()

    return [
        {
            "id": scan.id,
            "filename": scan.filename,
            "date_creation": scan.date_creation,
            "hosts_count": len(scan.hosts),  # utilise la relation SQLAlchemy directement
        }
        for scan in scans
    ]

@app.get("/api/scans/{scan_id}")
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    """
    Retourne le détail complet d'un scan passé : infos générales
    + liste de tous ses hosts avec leurs ports (désérialisés en JSON).
    """
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail=f"Aucun scan trouvé avec l'ID {scan_id}."
        )

    hosts = [
        {
            "ip": host.ip,
            "status": host.status,
            "mac_address": host.mac_address,
            "vendor": host.vendor,
            "hostname": host.hostname,
            "os": host.os,
            # open_ports est stocké en Text (JSON sérialisé) en base,
            # on le désérialise pour renvoyer un vrai tableau au frontend
            "open_ports": json.loads(host.open_ports) if host.open_ports else [],
        }
        for host in scan.hosts
    ]

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
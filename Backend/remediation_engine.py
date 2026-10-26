# remediation_engine.py

# --- Base de règles : port -> conseil de sécurité ---
# Clé = numéro de port (en string, car nmap le retourne en string dans notre parser)
PORT_RECOMMENDATIONS = {
    "21": "Le FTP (port 21) fait transiter les identifiants et données en clair. Migrez vers SFTP (port 22) ou FTPS.",
    "23": "Telnet (port 23) est non chiffré et obsolète. Désactivez-le et utilisez SSH (port 22) à la place.",
    "25": "Le port SMTP (25) ouvert publiquement peut être exploité comme relais de spam (open relay). Vérifiez la configuration d'authentification.",
    "53": "Un serveur DNS exposé (port 53) peut être utilisé pour des attaques d'amplification DDoS s'il autorise les requêtes récursives depuis l'extérieur.",
    "69": "TFTP (port 69) ne propose aucune authentification. À réserver strictement à un réseau interne isolé.",
    "135": "Le port 135 (RPC Windows) est une cible fréquente d'exploitation. Filtrez-le au niveau du pare-feu si non nécessaire en externe.",
    "139": "Le port 139 (NetBIOS) est associé à d'anciennes vulnérabilités SMB. Désactivez-le si le partage de fichiers Windows n'est pas requis.",
    "445": "Le port 445 (SMB) a été historiquement exploité (ex: WannaCry). Assurez-vous que SMBv1 est désactivé et que le port n'est pas exposé à Internet.",
    "512": "Les services rexec (port 512) transmettent les identifiants en clair. À désactiver.",
    "513": "Les services rlogin (port 513) sont obsolètes et non chiffrés. Remplacez par SSH.",
    "514": "Le port 514 (rsh/syslog) peut transmettre des données non chiffrées. Vérifiez qu'il n'est pas exposé publiquement.",
    "1433": "SQL Server (port 1433) ne devrait jamais être exposé directement à Internet. Restreignez l'accès via VPN ou pare-feu applicatif.",
    "1900": "Le port 1900 (UPnP/SSDP) permet l'ouverture automatique de ports et est régulièrement exploité pour des attaques DDoS par réflexion. Désactivez l'UPnP si non indispensable.",
    "3306": "MySQL (port 3306) exposé publiquement est une cible fréquente de bruteforce. Limitez l'accès aux IP de confiance uniquement.",
    "3389": "Le RDP (port 3389) exposé à Internet est une cible majeure de ransomwares. Passez par un VPN ou activez l'authentification à plusieurs facteurs.",
    "5900": "VNC (port 5900) transmet souvent les identifiants faiblement chiffrés. Préférez un tunnel SSH pour y accéder.",
    "6379": "Redis (port 6379) est souvent déployé sans authentification par défaut. Vérifiez qu'un mot de passe est configuré et que le port n'est pas exposé publiquement.",
    "8080": "Un service web exposé sur le port 8080 (souvent une interface d'admin) mérite une vérification d'accès et d'authentification renforcée.",
    "9200": "Elasticsearch (port 9200) est fréquemment laissé sans authentification, exposant toutes les données indexées. Vérifiez la configuration d'accès.",
    "27017": "MongoDB (port 27017) sans authentification est une source récurrente de fuites de données massives. Activez l'authentification et restreignez l'accès réseau.",
}

# --- Règles de secours basées sur le nom du service (si le port n'est pas dans la table ci-dessus) ---
SERVICE_RECOMMENDATIONS = {
    "ftp": "Un service FTP a été détecté. Préférez SFTP pour chiffrer les transferts de fichiers.",
    "telnet": "Telnet a été détecté. Ce protocole est non chiffré, remplacez-le par SSH.",
    "http": "Un service HTTP non chiffré a été détecté. Envisagez une migration vers HTTPS (TLS).",
}


def get_remediations(open_ports: list[dict]) -> list[str]:
    """
    Analyse la liste des ports ouverts d'un host et retourne une liste
    de conseils de sécurité textuels, dédupliqués.
    """
    if not open_ports:
        return []

    recommendations = []

    for port in open_ports:
        port_id = port.get("port")
        service = (port.get("service") or "").lower()

        # 1. On regarde d'abord si une règle existe pour ce numéro de port précis
        if port_id in PORT_RECOMMENDATIONS:
            advice = PORT_RECOMMENDATIONS[port_id]
            if advice not in recommendations:
                recommendations.append(advice)
            continue  # on ne double-check pas le service si le port a déjà matché

        # 2. Sinon, on regarde si le nom du service correspond à une règle générique
        if service in SERVICE_RECOMMENDATIONS:
            advice = SERVICE_RECOMMENDATIONS[service]
            if advice not in recommendations:
                recommendations.append(advice)

    return recommendations
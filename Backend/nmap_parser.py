# nmap_parser.py

import xml.etree.ElementTree as ET
import json
import sys


def _extract_mac_info(host):
    """Extrait l'adresse MAC et le vendor associé, si disponibles."""
    mac_elem = host.find("address[@addrtype='mac']")
    if mac_elem is not None:
        return mac_elem.get("addr"), mac_elem.get("vendor")  # vendor peut être None
    return None, None


def _extract_hostname(host):
    """Extrait le premier hostname trouvé, s'il existe."""
    hostname_elem = host.find("hostnames/hostname")
    if hostname_elem is not None:
        return hostname_elem.get("name")
    return None


def _extract_os(host):
    """
    Extrait le nom de l'OS le plus probable (accuracy la plus élevée).
    Retourne None si aucune détection OS n'est présente (scan sans -O,
    ou host ayant bloqué la détection).
    """
    os_elem = host.find("os")
    if os_elem is None:
        return None

    osmatches = os_elem.findall("osmatch")
    if not osmatches:
        return None

    # On trie par accuracy décroissante pour être sûr de prendre le meilleur match,
    # sans dépendre de l'ordre d'apparition dans le XML
    best_match = max(osmatches, key=lambda m: int(m.get("accuracy", 0)))
    return best_match.get("name")


def parse_nmap_xml(filepath: str) -> list[dict]:
    """
    Parse un fichier XML généré par `nmap -oX output.xml`
    et retourne une liste de dictionnaires, un par host scanné.
    """
    tree = ET.parse(filepath)
    root = tree.getroot()

    results = []

    for host in root.findall("host"):

        # --- Statut du host ---
        status_elem = host.find("status")
        status = status_elem.get("state") if status_elem is not None else "unknown"

        # --- Adresse IPv4 ---
        address_elem = host.find("address[@addrtype='ipv4']")
        ip_address = address_elem.get("addr") if address_elem is not None else None

        # --- Adresse MAC + vendor ---
        mac_address, vendor = _extract_mac_info(host)

        # --- Hostname ---
        hostname = _extract_hostname(host)

        # --- OS détecté ---
        os_name = _extract_os(host)

        # --- Ports ouverts (inchangé) ---
        open_ports = []
        ports_container = host.find("ports")

        if ports_container is not None:
            for port in ports_container.findall("port"):
                state_elem = port.find("state")

                if state_elem is not None and state_elem.get("state") == "open":
                    service_elem = port.find("service")

                    port_info = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service": service_elem.get("name") if service_elem is not None else "unknown",
                        "product": service_elem.get("product") if service_elem is not None else "",
                        "version": service_elem.get("version") if service_elem is not None else "",
                    }
                    open_ports.append(port_info)

        if ip_address:
            results.append({
                "ip": ip_address,
                "status": status,
                "mac_address": mac_address,   # None si absent (scan distant sans sudo)
                "vendor": vendor,              # None si MAC inconnue de la base OUI
                "hostname": hostname,          # None si pas de résolution
                "os": os_name,                 # None si pas de scan -O ou détection échouée
                "open_ports": open_ports,
                "open_ports_count": len(open_ports),
            })

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python nmap_parser.py <fichier.xml>")
        sys.exit(1)

    filepath = sys.argv[1]
    data = parse_nmap_xml(filepath)
    print(json.dumps(data, indent=2))
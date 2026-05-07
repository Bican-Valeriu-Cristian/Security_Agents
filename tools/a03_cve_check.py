import re
import requests
from bs4 import BeautifulSoup

def verifica_versiuni_si_cve(url: str) -> str:
    """
    Identifică tehnologiile și versiunile folosite de serverul țintă
    și caută vulnerabilități cunoscute (CVE-uri) pe NIST NVD.
    Dacă versiunea nu poate fi detectată, CVE-urile sunt sărite.
    """
    print(f"\n[🔍 Tool Executat] Amprentez serverul și caut CVE-uri LIVE pentru {url}...")

    try:
        raspuns = requests.get(url, timeout=5)
        headere = raspuns.headers

        traduceri_tehnologii = {
            "apache-coyote": "tomcat",
            "coyote": "tomcat",
            "apache": "apache_http_server",
            "iis": "iis",
            "nginx": "nginx",
            "express": "express",
            "openresty": "nginx",
            "lighttpd": "lighttpd",
            "caddy": "caddy",
            "gunicorn": "gunicorn",
            "uvicorn": "uvicorn",
            "litespeed": "litespeed",
            "wordpress": "wordpress",
            "joomla": "joomla",
            "drupal": "drupal",
            "php": "php",
            "tomcat": "tomcat"
        }

        def extrage_tech_si_versiune(valoare: str):
            """Extrage numele tehnologiei și versiunea dintr-un string de forma 'nginx/1.18.0'."""
            parts = valoare.split('/')
            nume_brut = parts[0].lower().strip()
            versiune = parts[1].strip() if len(parts) > 1 else None
            if versiune:
                match = re.match(r'[\d.]+', versiune)
                versiune = match.group(0) if match else None
            nume_curat = traduceri_tehnologii.get(nume_brut, nume_brut)
            return nume_curat, versiune

        # --- DETECTARE TEHNOLOGIE ---
        tehnologii_gasite = {}

        if 'Server' in headere:
            nume, versiune = extrage_tech_si_versiune(headere['Server'])
            tehnologii_gasite[nume] = versiune

        if 'X-Powered-By' in headere:
            nume, versiune = extrage_tech_si_versiune(headere['X-Powered-By'])
            tehnologii_gasite[nume] = versiune

        rezultat = f"--- Rezultate Scanare A03 (Versiuni & CVE LIVE) pentru {url} ---\n\n"

        if not tehnologii_gasite:
            rezultat += "🛡️ AMPRENTARE: Site-ul nu expune informații despre tehnologiile folosite.\n"
            return rezultat

        rezultat += "🛠️ TEHNOLOGII IDENTIFICATE:\n"
        for tech, ver in tehnologii_gasite.items():
            ver_str = ver if ver else "versiune necunoscută"
            rezultat += f"- {tech}: {ver_str}\n"

        # --- CĂUTARE CVE-uri pe NIST ---
        rezultat += "\n🚨 CĂUTARE VULNERABILITĂȚI (CVE):\n"
        headers_api = {'User-Agent': 'SecurityAuditorAgent/1.0'}

        for tech_nume, tech_versiune in tehnologii_gasite.items():

            # Fără versiune → sărim CVE-urile
            if not tech_versiune:
                rezultat += (
                    f"\n⚠️ [{tech_nume}] Versiunea nu a putut fi detectată automat — "
                    f"CVE-urile nu pot fi verificate.\n"
                    f"   Verificați manual pe: https://nvd.nist.gov/vuln/search\n"
                )
                continue

            rezultat += f"\nInteroghez NIST pentru '{tech_nume}' versiunea {tech_versiune}...\n"

            try:
                api_url = (
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?keywordSearch={tech_nume}+{tech_versiune}&resultsPerPage=5"
                )
                cve_resp = requests.get(api_url, headers=headers_api, timeout=7)

                if cve_resp.status_code == 200:
                    vulnerabilitati = cve_resp.json().get("vulnerabilities", [])
                    if vulnerabilitati:
                        rezultat += f"  {len(vulnerabilitati)} CVE-uri găsite:\n"
                        for vuln in vulnerabilitati:
                            cve = vuln.get("cve", {})
                            cve_id = cve.get("id", "Fără ID")
                            descriere = next(
                                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                                "Fără descriere disponibilă."
                            )
                            severitate = "NECUNOSCUTĂ"
                            metrics = cve.get("metrics", {})
                            if "cvssMetricV31" in metrics:
                                severitate = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                            elif "cvssMetricV3" in metrics:
                                severitate = metrics["cvssMetricV3"][0]["cvssData"]["baseSeverity"]
                            elif "cvssMetricV2" in metrics:
                                scor = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                                severitate = "CRITICĂ" if scor >= 9.0 else "ÎNALTĂ" if scor >= 7.0 else "MEDIE" if scor >= 4.0 else "SCĂZUTĂ"
                            rezultat += f"  * {cve_id} | Severitate: {severitate}\n"
                            rezultat += f"    Detalii: {descriere[:120]}...\n\n"
                    else:
                        rezultat += f"  Nu au fost găsite CVE-uri cunoscute pentru {tech_nume} {tech_versiune}.\n"

                else:
                    rezultat += f"  NIST indisponibil (Cod: {cve_resp.status_code}) — verificați manual pe https://nvd.nist.gov\n"

            except requests.exceptions.Timeout:
                rezultat += f"  NIST nu a răspuns în timp util — verificați manual pe https://nvd.nist.gov\n"
            except Exception as e:
                rezultat += f"  Eroare la interogarea NIST: {str(e)}\n"

        return rezultat

    except requests.exceptions.RequestException as e:
        return f"Eroare la conectare: Nu am putut accesa {url}. Detalii: {str(e)}"


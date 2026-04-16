import requests

def verifica_versiuni_si_cve(url: str) -> str:
    """
    Identifică tehnologiile și versiunile folosite de serverul țintă (ex: Express, Apache, Nginx) 
    și caută vulnerabilități cunoscute (CVE-uri) LIVE. Folosește NIST NVD ca sursă principală,
    și CIRCL ca soluție de rezervă (Fallback) în caz de Timeout.
    """
    print(f"\n[🔍 Tool Executat] Amprentez serverul și caut CVE-uri LIVE pentru {url}...")
    
    try:
        raspuns = requests.get(url, timeout=5)
        headere = raspuns.headers
        
        # 1. AMPRENTAREA
        tehnologii_gasite = {}
        
        if 'Server' in headere:
            tehnologii_gasite['Server'] = headere['Server']
        if 'X-Powered-By' in headere:
            tehnologii_gasite['X-Powered-By'] = headere['X-Powered-By']
            
        rezultat = f"--- Rezultate Scanare A03 (Versiuni & CVE LIVE) pentru {url} ---\n\n"
        
        if not tehnologii_gasite:
            rezultat += "🛡️ AMPRENTARE: Site-ul este bine configurat și își ascunde tehnologiile.\n"
            return rezultat
            
        rezultat += "🛠️ TEHNOLOGII IDENTIFICATE pe acest port:\n"
        for cheie, valoare in tehnologii_gasite.items():
            rezultat += f"- {cheie}: {valoare}\n"
            
        
        # 2. CĂUTAREA DE CVE-uri LIVE (Cu Fallback)
        
        rezultat += "\n🚨 VULNERABILITĂȚI GĂSITE ÎN BAZELE DE DATE OFICIALE:\n"
        headers_api = {'User-Agent': 'SecurityAuditorAgent/1.0'}

        traduceri_tehnologii = {
            "apache-coyote": "tomcat",
            "coyote": "tomcat",
            "apache": "apache_http_server",
            "iis": "iis",
            "nginx": "nginx",
            "express": "express"
        }

        for tehnologie in tehnologii_gasite.values():
            tech_brut = tehnologie.split('/')[0].lower().strip()
            tech_nume_curat = traduceri_tehnologii.get(tech_brut, tech_brut)
            
            rezultat += f"\nInteroghez baza de date pentru '{tech_nume_curat}' (pe baza '{tehnologie}')...\n"
            
            # --- ÎNCERCAREA 1: NIST NVD ---
            try:
                api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech_nume_curat}&resultsPerPage=3"
                cve_resp = requests.get(api_url, headers=headers_api, timeout=7) # Am redus la 7 secunde
                
                if cve_resp.status_code == 200:
                    date_json = cve_resp.json()
                    vulnerabilitati = date_json.get("vulnerabilities", [])
                    
                    if vulnerabilitati:
                        for vuln in vulnerabilitati:
                            cve = vuln.get("cve", {})
                            cve_id = cve.get("id", "Fără ID")
                            
                            descriere = "Fără descriere disponibilă."
                            for desc in cve.get("descriptions", []):
                                if desc.get("lang") == "en":
                                    descriere = desc.get("value")
                                    break
                                    
                            severitate = "NECUNOSCUTĂ"
                            metrics = cve.get("metrics", {})
                            if "cvssMetricV31" in metrics:
                                severitate = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                            elif "cvssMetricV3" in metrics:
                                severitate = metrics["cvssMetricV3"][0]["cvssData"]["baseSeverity"]
                            elif "cvssMetricV2" in metrics:
                                scor_v2 = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                                severitate = "CRITICĂ" if scor_v2 >= 9.0 else "ÎNALTĂ" if scor_v2 >= 7.0 else "MEDIE" if scor_v2 >= 4.0 else "SCĂZUTĂ"
                                
                            rezultat += f"  * {cve_id} | Severitate (NIST): {severitate}\n"
                            rezultat += f"    Detalii: {descriere[:120]}...\n\n"
                        continue # Dacă am găsit CVE-uri în NIST, nu mai încercăm Fallback-ul
                    else:
                        rezultat += f"  -> Nu am găsit CVE-uri majore pe NIST.\n"
                        continue
                else:
                    rezultat += f"  -> Eroare la NIST API (Cod: {cve_resp.status_code}). Trec la Fallback...\n"
                    # Dacă NIST dă eroare, lăsăm codul să curgă mai jos, către CIRCL
                    
            except requests.exceptions.Timeout:
                rezultat += f"  -> [TIMEOUT] NIST a răspuns prea greu. Încerc baza de date alternativă (CIRCL)...\n"

            # --- ÎNCERCAREA 2: FALLBACK LA CIRCL (Doar dacă NIST a eșuat) ---
            try:
                # CIRCL este mai simplu și mai rapid, dar returnează o listă masivă.
                circl_url = f"https://cve.circl.lu/api/search/{tech_nume_curat}"
                circl_resp = requests.get(circl_url, headers=headers_api, timeout=5)
                
                if circl_resp.status_code == 200:
                    date_circl = circl_resp.json()
                    
                    # Luăm doar primele 3 rezultate ca să nu umplem ecranul
                    if date_circl and isinstance(date_circl, list):
                        for vuln in date_circl[:3]:
                            cve_id = vuln.get("id", "Fără ID")
                            descriere = vuln.get("summary", "Fără descriere")
                            # CIRCL folosește CVSS V2, așa că mapăm noi severitatea aproximativ
                            cvss_score = float(vuln.get("cvss", 0.0) or 0.0)
                            severitate = "CRITICĂ" if cvss_score >= 9.0 else "ÎNALTĂ" if cvss_score >= 7.0 else "MEDIE" if cvss_score >= 4.0 else "SCĂZUTĂ"
                            
                            rezultat += f"  * {cve_id} | Severitate estimată (CIRCL): {severitate}\n"
                            rezultat += f"    Detalii: {descriere[:120]}...\n\n"
                    else:
                        rezultat += f"  -> Nici CIRCL nu a găsit CVE-uri pentru '{tech_nume_curat}'.\n"
                else:
                    rezultat += f"  -> Eroare și la CIRCL. Scanare abandonată pentru această tehnologie.\n"

            except Exception as e:
                rezultat += f"  -> Eroare la interogarea de Fallback: {str(e)}\n"

        return rezultat

    except requests.exceptions.RequestException as e:
        return f"Eroare la conectare: Nu am putut accesa {url}. Detalii: {str(e)}"

if __name__ == "__main__":
    print(verifica_versiuni_si_cve("http://demo.testfire.net"))
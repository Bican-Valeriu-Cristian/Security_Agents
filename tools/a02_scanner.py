import requests

def scaneaza_headere_http(url: str) -> str:
    """
    Scanează headerele HTTP ale unui URL pentru a identifica configurări de securitate 
    lipsă sau expunerea versiunilor de server (OWASP A02).
    Input: un URL complet (ex: http://localhost:3000).
    Returnează: un string cu headerele găsite și cele care lipsesc.
    """
    print(f"\n[🔧 Tool Executat] Verific configurările HTTP pentru {url}...")
    
    try:
        # Facem request-ul către site-ul țintă
        raspuns = requests.get(url, timeout=5)
        headere = raspuns.headers
        
        # Formatăm rezultatul sub formă de text pentru AI
        rezultat = f"--- Rezultate Scanare HTTP pentru {url} ---\n"
        rezultat += f"Cod de răspuns: {raspuns.status_code}\n\n"
        
        rezultat += "Headere returnate de server:\n"
        for cheie, valoare in headere.items():
            rezultat += f"- {cheie}: {valoare}\n"
            
        
        headere_securitate_asteptate = [
            'Strict-Transport-Security', 
            'X-Frame-Options', 
            'X-Content-Type-Options', 
            'Content-Security-Policy'
        ]
        
        lipsesc = [h for h in headere_securitate_asteptate if h not in headere]
        
        if lipsesc:
            rezultat += "\n[ATENȚIE - A02] Următoarele headere de securitate esențiale LIPSESC:\n"
            for h in lipsesc:
                rezultat += f"- {h}\n"

        # Acestea sunt endpoint-uri specifice Juice Shop care nu ar trebui să fie publice
        directoare_test = [
            "/admin", 
            "/ftp", 
            "/.env", 
            "/architecture",
            "/promotion"
        ]   

        rezultat += "\nVerificare directoare sensibile:\n"
        url_baza = url.rstrip('/')
        for cale in directoare_test:
            tinta_completa = f"{url_baza}{cale}"
            try:
                r_test = requests.get(tinta_completa, timeout=3)
                # Daca primim 200 (OK) sau 403 (Forbidden), înseamna ca directorul exista
                if r_test.status_code == 200:
                    rezultat += f"- GĂSIT: {cale} (Accesibil!)\n"
                elif r_test.status_code == 403:
                    rezultat += f"- RESTRICȚIONAT: {cale} (Existent, dar protejat)\n"
            except:
                continue
        return rezultat

    except requests.exceptions.RequestException as e:
        return f"Eroare la conectare: Nu am putut accesa {url}. Detalii: {str(e)}"

# --- ZONĂ DE TESTARE MANUALĂ ---
if __name__ == "__main__":
    tinta_test = "http://localhost:3000"
    print(scaneaza_headere_http(tinta_test))
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
        raspuns = requests.get(url, timeout=5)
        headere = raspuns.headers
        
        rezultat = f"--- Rezultate Scanare HTTP pentru {url} ---\n"
        rezultat += f"Cod de răspuns: {raspuns.status_code}\n\n"
        
        rezultat += "Headere returnate de server:\n"
        for cheie, valoare in headere.items():
            rezultat += f"- {cheie}: {valoare}\n"
            
        headere_securitate_asteptate = [
            'Strict-Transport-Security', 
            'X-Frame-Options', 
            'X-Content-Type-Options', 
            'Content-Security-Policy',
            'Referrer-Policy',       
            'Permissions-Policy'     
        ]
        
        lipsesc = [h for h in headere_securitate_asteptate if h not in headere]
        
        severitate_headere = {
            'Strict-Transport-Security': ('ÎNALTĂ', 'Permite atacuri MITM prin HTTP'),
            'X-Frame-Options': ('MEDIE', 'Vulnerabil la clickjacking'),
            'X-Content-Type-Options': ('MEDIE', 'Permite MIME sniffing'),
            'Content-Security-Policy': ('ÎNALTĂ', 'Permite injectare de scripturi XSS'),
            'Referrer-Policy': ('MEDIE', 'Scurgere de informații de navigare către terți'),
            'Permissions-Policy': ('SCĂZUTĂ', 'Permite abuzul funcțiilor hardware (cameră/microfon)')
        } 
        
        if lipsesc:
            rezultat += "\n[ATENȚIE - A02] Următoarele headere de securitate esențiale LIPSESC:\n"
            for h in lipsesc:
                 sev, motiv = severitate_headere.get(h, ('MEDIE', 'Risc de securitate'))
                 rezultat += f"- {h} | Severitate: {sev} | Risc: {motiv}\n"

        # === DIRECȚIA UNIVERSALĂ ===
        # Un dicționar cu cele mai comune fișiere uitate pe servere la nivel global
        directoare_universale = {
            # --- 1. Credențiale și Chei (Cele mai grave) ---
            '/.env': 'CRITICĂ',                # Parole și chei API
            '/.git/config': 'CRITICĂ',         # Expune tot codul sursă
            '/.aws/credentials': 'CRITICĂ',    # Chei pentru cloud Amazon
            '/.ssh/id_rsa': 'CRITICĂ',         # Chei private de acces la server
            
            # --- 2. Baze de date și Backup-uri ---
            '/backup.zip': 'ÎNALTĂ',           # Arhive cu site-ul vechi
            '/config.php.bak': 'ÎNALTĂ',       # Fișier de configurare salvat greșit
            '/database.sqlite': 'CRITICĂ',     # Baza de date descărcabilă direct!
            '/db.sqlite3': 'CRITICĂ',          # Alt format comun de bază de date
            
            # --- 3. Panouri de administrare ---
            '/admin/': 'ÎNALTĂ',               # Panou de administrare generic
            '/wp-admin/': 'ÎNALTĂ',            # Panou WordPress
            '/phpinfo.php': 'ÎNALTĂ',          # Scurgeri masive de date despre server
            
            # --- 4. Configurații de Infrastructură ---
            '/docker-compose.yml': 'ÎNALTĂ',   # Structura serverelor și parole
            '/web.config': 'ÎNALTĂ',           # Configurații server IIS (Windows)
            '/package.json': 'MEDIE',          # Arată ce librării Node.js rulează în spate
            
            # --- 5. Hărți și API-uri expuse ---
            '/swagger/v1/swagger.json': 'MEDIE', # Documentație API neprotejată
            '/api/docs': 'MEDIE',              # Altă rută comună pentru API
            '/server-status': 'MEDIE',         # Statusul serverului Apache
            '/robots.txt': 'INFO',             # Spune hackerilor unde să NU se uite (foarte util)
            '/sitemap.xml': 'INFO'             # Harta completă a site-ului
        }   

        url_baza = url.rstrip('/')
        
        try:
            raspuns_homepage = requests.get(url_baza, timeout=3)
            homepage_text = raspuns_homepage.text
        except:
            homepage_text = ""

        rezultat += "\nVerificare directoare sensibile globale:\n"
        
        for cale, sev in directoare_universale.items():
            tinta_completa = f"{url_baza}{cale}"
            try:
                r_test = requests.get(tinta_completa, timeout=3)
                
                # Verificăm dacă există și dacă nu e doar un redirect către homepage
                if r_test.status_code == 200:
                    if r_test.text == homepage_text:
                        continue # E doar un fals pozitiv
                    else:
                        rezultat += f"- GĂSIT: {cale} | Severitate: {sev} | STATUS: Accesibil public!\n"
                        
                elif r_test.status_code == 403:
                    rezultat += f"- RESTRICȚIONAT: {cale} | Severitate: SCĂZUTĂ | STATUS: Existent, dar blocat (403)\n"
            except:
                continue
                
        return rezultat

    except requests.exceptions.RequestException as e:
        return f"Eroare la conectare: Nu am putut accesa {url}. Detalii: {str(e)}"

# --- ZONĂ DE TESTARE MANUALĂ ---
if __name__ == "__main__":
    tinta_test = "http://localhost:3000"
    print(scaneaza_headere_http(tinta_test))
import requests
import re
from bs4 import BeautifulSoup
from bs4 import Comment
from urllib.parse import urljoin 

def scaneaza_cod_sursa(url: str) -> str:
    """
    Descarcă și analizează codul sursă HTML și TOATE scripturile .js externe.
    Caută comentarii, input-uri ascunse și folosește RegEx pentru a detecta
    chei API, token-uri sau parole lăsate în clar (OWASP A01/A05).
    """
    print(f"\n[👀 Tool Executat] Scanez în profunzime sursa și fișierele JS pentru {url}...")
    
    try:
        raspuns = requests.get(url, timeout=5)
        text_brut = raspuns.text
        soup = BeautifulSoup(text_brut, 'html.parser')
        
        rezultat = f"--- Rezultate Scraping Avansat pentru {url} ---\n\n"
        
        # 1. COMENTARII HTML
        comentarii = soup.find_all(string=lambda text: isinstance(text, Comment))
        rezultat += "🕵️ COMENTARII ASCUNSE:\n"
        if comentarii:
            for c in comentarii:
                rezultat += f"- \n"
        else:
            rezultat += "- Nu am găsit comentarii HTML.\n"
            
        # 2. INPUT-URI ASCUNSE
        inputuri_ascunse = soup.find_all('input', type='hidden')
        rezultat += "\n🕳️ CÂMPURI ASCUNSE (Hidden Inputs):\n"
        if inputuri_ascunse:
            for inp in inputuri_ascunse:
                nume = inp.get('name', 'fără-nume')
                val = inp.get('value', 'fără-valoare')
                if 'csrf' not in nume.lower(): 
                    rezultat += f"- Nume: '{nume}' | Valoare: '{val}'\n"
        else:
            rezultat += "- Nu am găsit input-uri ascunse relevante.\n"

        
        # 3. DESCĂRCAREA FIȘIERELOR JAVASCRIPT
        
        text_de_analizat = text_brut # Începem prin a analiza HTML-ul
        
        scripturi = soup.find_all('script', src=True)
        if scripturi:
            rezultat += f"\n📥 EXTRAGERE FIȘIERE JAVASCRIPT ({len(scripturi)} găsite):\n"
            for script in scripturi:
                # urljoin transformă "/static/js/main.js" în "http://localhost:3000/static/js/main.js"
                js_url = urljoin(url, script['src']) 
                try:
                    js_raspuns = requests.get(js_url, timeout=5)
                    if js_raspuns.status_code == 200:
                        # Adăugăm codul JS uriaș la "grămada" noastră de text pe care o va citi RegEx-ul
                        text_de_analizat += "\n" + js_raspuns.text 
                        rezultat += f"- Succes: Am descărcat și inclus în analiză {js_url}\n"
                except:
                    rezultat += f"- Eroare: Nu am putut descărca {js_url}\n"
        else:
            rezultat += "\n📥 Nu am găsit fișiere .js externe de descărcat.\n"


        # 4. REGEX PENTRU SECRETE ÎN COD
        rezultat += "\n🔑 SECRETE SAU TOKEN-URI (Extrase via RegEx din HTML și JS):\n"
        secrete_gasite = False
        
        modele_regex = {
            "Posibil Token JWT (Autentificare)": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "Posibilă Cheie API / Parolă Hardcodată": r"(?i)(api_key|apikey|secret|password|token)\s*[:=]\s*['\"]([^'\"]+)['\"]",
            "Posibilă adresă de Email internă": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        }

        for nume_vulnerabilitate, sablon in modele_regex.items():
            # Aplicăm RegEx-ul pe tot textul combinat (HTML + JS) pentru a găsi posibile secrete
            potriviri = set(re.findall(sablon, text_de_analizat)) 
            
            if potriviri:
                secrete_gasite = True
                rezultat += f"\n  [{nume_vulnerabilitate}]:\n"
                for potrivire in potriviri:
                    valoare_gasita = potrivire if isinstance(potrivire, str) else str(potrivire)
                    rezultat += f"  -> {valoare_gasita[:15]}...[TRUNCHIAT]\n"

        if not secrete_gasite:
            rezultat += "- Nu am detectat semnături de token-uri sau parole în codul sursă.\n"

        return rezultat

    except Exception as e:
        return f"Eroare la parsarea HTML pentru {url}. Detalii: {str(e)}"

if __name__ == "__main__":
    print(scaneaza_cod_sursa("http://localhost:3000"))
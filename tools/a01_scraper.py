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
                continut = c.strip()
                if continut:  # ignorăm comentariile goale sau doar cu spații
                    rezultat += f"- {continut}\n"
        else:
            rezultat += "- Nu am găsit comentarii HTML.\n"
            
        # 2. INPUT-URI ASCUNSE
        inputuri_ascunse = soup.find_all('input', type='hidden')
        rezultat += "\n🕳️ CÂMPURI ASCUNSE (Hidden Inputs):\n"
        if inputuri_ascunse:
            for inp in inputuri_ascunse:
                nume = inp.get('name', 'fără-nume')
                val = inp.get('value', 'fără-valoare')
                
                # Ignorăm token-urile CSRF (nu sunt vulnerabilități, sunt protecții)
                termeni_ignorati = ['csrf', 'xsrf', '_token', 'authenticity_token']
                if not any(termen in nume.lower() for termen in termeni_ignorati):
                    
                    # ─── LOGICA DE TRUNCHIERE ───
                    if len(val) > 60:
                        val = val[:60] + "... [TRUNCHIAT PENTRU CITIBILITATE]"
                        
                    rezultat += f"- Nume: '{nume}' | Valoare: '{val}'\n"
        else:
            rezultat += "- Nu am găsit input-uri ascunse relevante.\n"

        
        # 3. DESCĂRCAREA FIȘIERELOR JAVASCRIPT
        
        text_de_analizat = text_brut  # Începem prin a analiza HTML-ul
        js_text_total = ""             # Vom acumula separat tot codul JS pentru analiza comentariilor
        
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
                        js_text_total += "\n" + js_raspuns.text  # separat doar JS-ul
                        rezultat += f"- Succes: Am descărcat și inclus în analiză {js_url}\n"
                except:
                    rezultat += f"- Eroare: Nu am putut descărca {js_url}\n"
        else:
            rezultat += "\n📥 Nu am găsit fișiere .js externe de descărcat.\n"

        # Includem și scripturile inline din HTML pentru analiza comentariilor JS
        scripturi_inline = soup.find_all('script', src=False)
        for script_inline in scripturi_inline:
            if script_inline.string:
                js_text_total += "\n" + script_inline.string


        # 4. REGEX PENTRU SECRETE ÎN COD
        rezultat += "\n🔑 SECRETE SAU TOKEN-URI (Extrase din HTML și JS):\n"
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
                    # re.findall cu grupuri de captură returnează tuple-uri.
                    # Ex: ('api_key', 'valoarea_secretă') → vrem elementul [1]
                    # Fără grupuri (ex: JWT), returnează direct un string.
                    if isinstance(potrivire, tuple):
                        valoare_gasita = potrivire[1]  # luăm valoarea secretă, nu numele variabilei
                    else:
                        valoare_gasita = potrivire
                    rezultat += f"  -> {valoare_gasita[:15]}...[TRUNCHIAT]\n"

        if not secrete_gasite:
            rezultat += "- Nu am detectat semnături de token-uri sau parole în codul sursă.\n"


        # 5. COMENTARII ÎN COD JAVASCRIPT (suspecte / interesante pentru audit)
        rezultat += "\n💬 COMENTARII SUSPECTE ÎN COD JAVASCRIPT:\n"

        if js_text_total.strip():
            # Pattern pentru comentarii single-line // ... (până la sfârșit de linie)
            # Exclud URL-urile (http:// https://) cu negative lookbehind
            comentarii_js_single = re.findall(r'(?<!:)//\s*(.+?)$', js_text_total, re.MULTILINE)

            # Pattern pentru comentarii multi-line /* ... */
            comentarii_js_multi = re.findall(r'/\*([\s\S]*?)\*/', js_text_total)

            # Cuvinte cheie suspecte - relevante pentru audit de securitate
            cuvinte_suspecte = [
                'TODO', 'FIXME', 'HACK', 'XXX', 'BUG', 'WARNING', 'DEPRECATED',
                'password', 'parola', 'parolă', 'secret', 'api', 'key', 'token',
                'admin', 'debug', 'test', 'remove', 'temporary', 'temp',
                'production', 'dev', 'localhost', 'private', 'internal',
                'backdoor', 'workaround', 'fix later', 'do not commit'
            ]

            comentarii_interesante = []

            # Procesăm comentariile single-line
            for com in comentarii_js_single:
                com_clean = com.strip()
                if com_clean and any(cuv.lower() in com_clean.lower() for cuv in cuvinte_suspecte):
                    if len(com_clean) > 200:
                        com_clean = com_clean[:200] + "...[TRUNCHIAT]"
                    comentarii_interesante.append(f"// {com_clean}")

            # Procesăm comentariile multi-line
            for com in comentarii_js_multi:
                com_clean = com.strip()
                # Comentariile multi-line pot avea mai multe rânduri - le compactăm
                com_clean = re.sub(r'\s+', ' ', com_clean)
                if com_clean and any(cuv.lower() in com_clean.lower() for cuv in cuvinte_suspecte):
                    if len(com_clean) > 200:
                        com_clean = com_clean[:200] + "...[TRUNCHIAT]"
                    comentarii_interesante.append(f"/* {com_clean} */")

            # Eliminăm duplicatele păstrând ordinea
            comentarii_unice = list(dict.fromkeys(comentarii_interesante))

            if comentarii_unice:
                rezultat += f"- Am găsit {len(comentarii_unice)} comentarii cu cuvinte cheie suspecte:\n"
                # Limităm la primele 30 ca să nu inundăm raportul AI
                for c in comentarii_unice[:30]:
                    rezultat += f"  • {c}\n"
                if len(comentarii_unice) > 30:
                    rezultat += f"  ... și încă {len(comentarii_unice) - 30} comentarii similare.\n"
            else:
                rezultat += "- Nu am găsit comentarii JS cu cuvinte cheie suspecte (TODO, FIXME, password, api, etc.).\n"
        else:
            rezultat += "- Nu există cod JavaScript de analizat.\n"


        return rezultat

    except Exception as e:
        return f"Eroare la parsarea HTML pentru {url}. Detalii: {str(e)}"
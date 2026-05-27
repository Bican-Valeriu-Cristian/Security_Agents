import requests
from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
from collections import deque

def scaneaza_headere_http(url: str) -> str:
    """
    Scanează headerele HTTP, directoarele sensibile și crawlează site-ul
    pentru a descoperi pagini accesibile (OWASP A02).
    """
    print(f"\n[🔧 Tool Executat] Verific configurările HTTP pentru {url}...")

    try:
        raspuns = requests.get(url, timeout=5)
        headere = raspuns.headers

        rezultat = f"--- Rezultate Scanare HTTP pentru {url} ---\n"
        rezultat += f"Cod de răspuns: {raspuns.status_code}\n\n"

        rezultat += "📡 Headere returnate de server:\n"
        for cheie, valoare in headere.items():
            rezultat += f"- {cheie}: {valoare}\n"

        # === HEADERE DE SECURITATE ===
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
            rezultat += "\n⚠️ [ATENȚIE - A02] Următoarele headere de securitate esențiale LIPSESC:\n"
            for h in lipsesc:
                sev, motiv = severitate_headere.get(h, ('MEDIE', 'Risc de securitate'))
                rezultat += f"- {h} | Severitate: {sev} | Risc: {motiv}\n"
        else:
            rezultat += "\n✅ Toate headerele de securitate esențiale sunt prezente.\n"

        # === CRAWLING RECURSIV LIMITAT ===
        # Pornește de la URL-ul dat, extrage link-urile reale ale site-ului
        # și le verifică — găsește pagini care există efectiv, nu căi ghicite.
        rezultat += "\n📡 CRAWLING SITE (pagini descoperite):\n"

        domeniu_baza = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        vizitate = set()           # URL-uri complete deja procesate
        vizitate_normalizate = set()  # versiuni fără query string, pentru deduplicare
        de_vizitat = deque([(url, 0)])  # (url, adâncime)
        pagini_gasite = []

        ADANCIME_MAX = 2
        PAGINI_MAX = 25

        while de_vizitat and len(vizitate) < PAGINI_MAX:
            url_curent, adancime = de_vizitat.popleft()

            if url_curent in vizitate:
                continue
            vizitate.add(url_curent)

            try:
                r = requests.get(url_curent, timeout=2, allow_redirects=True)
                pagini_gasite.append((url_curent, r.status_code))

                # Dacă nu am atins adâncimea maximă, extragem link-urile din pagină
                if adancime < ADANCIME_MAX and r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    for tag in soup.find_all('a', href=True):
                        link = urljoin(url_curent, tag['href'])

                        # FIX 1: Scoatem fragmentul/ancora (#contact, #top)
                        # /about#contact și /about#team devin amândouă /about
                        link, _ = urldefrag(link)

                        # Păstrăm doar link-urile de pe același domeniu
                        if link.startswith(domeniu_baza) and link not in vizitate:
                            # Excludem fișiere binare
                            if not any(link.endswith(ext) for ext in ['.jpg', '.png', '.gif', '.pdf', '.zip', '.css', '.js']):
                                # FIX 2: Dedup pe versiunea fără query string
                                # /products?id=1 și /products?id=2 vor fi tratate ca aceeași pagină
                                link_normalizat = link.split('?')[0]
                                if link_normalizat not in vizitate_normalizate:
                                    vizitate_normalizate.add(link_normalizat)
                                    de_vizitat.append((link, adancime + 1))
            except:
                continue

        if pagini_gasite:
            rezultat += f"  {len(pagini_gasite)} pagini verificate:\n"
            for pagina, status in pagini_gasite:
                cale = pagina.replace(domeniu_baza, '') or '/'
                rezultat += f"  - {cale} | Status: {status}\n"
        else:
            rezultat += "  Nu au fost descoperite pagini suplimentare.\n"

        # === DIRECTOARE SENSIBILE (lista statică) ===
        # Rulează mereu, indiferent de rezultatele crawling-ului
        directoare_universale = {
            '/.env': 'CRITICĂ',
            '/.git/config': 'CRITICĂ',
            '/.aws/credentials': 'CRITICĂ',
            '/.ssh/id_rsa': 'CRITICĂ',
            '/backup.zip': 'ÎNALTĂ',
            '/config.php.bak': 'ÎNALTĂ',
            '/database.sqlite': 'CRITICĂ',
            '/db.sqlite3': 'CRITICĂ',
            '/admin/': 'ÎNALTĂ',
            '/wp-admin/': 'ÎNALTĂ',
            '/phpinfo.php': 'ÎNALTĂ',
            '/docker-compose.yml': 'ÎNALTĂ',
            '/web.config': 'ÎNALTĂ',
            '/package.json': 'MEDIE',
            '/swagger/v1/swagger.json': 'MEDIE',
            '/api/docs': 'MEDIE',
            '/server-status': 'MEDIE',
            '/robots.txt': 'INFO',
            '/sitemap.xml': 'INFO'
        }

        url_baza = url.rstrip('/')

        try:
            raspuns_homepage = requests.get(url_baza, timeout=3, allow_redirects=True)
            homepage_len = len(raspuns_homepage.text)
        except:
            homepage_len = -1

        rezultat += "\n🗂️ Verificare directoare sensibile globale:\n"
        directoare_gasite = False

        for cale, sev in directoare_universale.items():
            tinta_completa = f"{url_baza}{cale}"
            try:
                r_test = requests.get(tinta_completa, timeout=3, allow_redirects=False)

                if r_test.status_code == 200:
                    diferenta = abs(len(r_test.text) - homepage_len)
                    prag = homepage_len * 0.05
                    if homepage_len > 0 and diferenta < prag:
                        continue
                    directoare_gasite = True
                    rezultat += f"- GĂSIT: {cale} | Severitate: {sev} | STATUS: Accesibil public!\n"

                elif r_test.status_code == 403:
                    directoare_gasite = True
                    rezultat += f"- RESTRICȚIONAT: {cale} | Severitate: SCĂZUTĂ | STATUS: Existent, dar blocat (403)\n"

                elif r_test.status_code in (301, 302):
                    pass

            except:
                continue

        if not directoare_gasite:
            rezultat += "- Nu au fost identificate directoare sau fișiere sensibile expuse.\n"

        return rezultat

    except requests.exceptions.RequestException as e:
        return f"Eroare la conectare: Nu am putut accesa {url}. Detalii: {str(e)}"
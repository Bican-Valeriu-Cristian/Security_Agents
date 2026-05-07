from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

# Importuri LangChain
from langchain_groq import ChatGroq
from langchain_core.tools import Tool
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage # <-- Import NOU pentru analiza individuală

# Importuri Unelte
from tools.a02_scanner import scaneaza_headere_http
from tools.a03_cve_check import verifica_versiuni_si_cve
from tools.a01_scraper import scaneaza_cod_sursa
from tools.a04_injection_check import verifica_html_injection
from tools.virustotal import verifica_reputatie_virustotal

load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

def valideaza_url(url: str):
    """Funcție ajutătoare pentru a valida URL-ul peste tot."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="URL invalid. Folosiți formatul: http(s)://domeniu.com")
    return url

# ==========================================
# RUTA VECHE: SCANAREA COMPLETĂ (Agent AI)
# ==========================================
@app.post("/scan")
async def scan(req: ScanRequest):
    valideaza_url(req.url)

    unelte = [
        Tool(name="Scanner_Configurari_A02", func=scaneaza_headere_http,
             description="Verifică configurările HTTP (OWASP A02). Input: URL complet."),
        Tool(name="Verificator_CVE_A03", func=verifica_versiuni_si_cve,
             description="Detectează versiuni și CVE-uri (OWASP A03). Input: URL complet."),
        Tool(name="Scraper_Cod_Sursa_A01", func=scaneaza_cod_sursa,
             description="Descarcă HTML-ul și găsește comentarii sau date ascunse în sursă. Input: URL complet."),      
        Tool(name="Detector_HTML_Injection_A04", func=verifica_html_injection,
             description="Scanează formularele și câmpurile de input pentru a identifica riscuri de injectare HTML. Input: URL complet."),
        Tool(name="VirusTotal", func=verifica_reputatie_virustotal,
             description="Interoghează baza de date globală VirusTotal pentru reputația domeniului, malware și phishing. Input: URL complet.")
    ]
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile",
                   api_key=os.getenv("GROQ_API_KEY"))
    agent = create_react_agent(llm, tools=unelte)

    instructiuni = f"""Ești un auditor de securitate cibernetică senior. Misiunea ta este să realizezi un audit complet pentru: {req.url}

PASUL 1 - COLECTARE DATE (Obligatoriu - folosește TOATE cele 5 instrumente, în această ordine):
1. Scraper_Cod_Sursa_A01 → analizează codul sursă și fișierele JS
2. Scanner_Configurari_A02 → verifică headerele HTTP și directoarele expuse
3. Verificator_CVE_A03 → identifică tehnologiile și caută vulnerabilități cunoscute
4. Detector_HTML_Injection_A04 → mapează formularele și câmpurile de input
5. VirusTotal → verifică reputația domeniului

Dacă un instrument returnează eroare, menționează eroarea în secțiunea corespunzătoare și continuă cu următorul. Nu te opri și nu omite niciun instrument.

PASUL 2 - REDACTARE RAPORT

Respectă STRICT structura de mai jos. Nu adăuga secțiuni extra. Nu omite secțiuni.
Ton: clinic, obiectiv, fără emojis, fără fraze de umplutură.

---

# RAPORT DE AUDIT DE SECURITATE

**Ținta:** `{req.url}`

## 1. ANALIZA CODULUI SURSĂ (A01)
Pentru fiecare element găsit, folosește formatul:
* **[Tip]** | `[valoare trunchată]` | Risc: [explicație scurtă]

Tipuri posibile: Comentariu HTML | Câmp ascuns | Token JWT | Cheie API | Email intern | Secret hardcodat

Dacă nu s-a identificat nimic: "Niciun element de risc identificat în codul sursă."

## 2. CONFIGURĂRI DE SECURITATE (A02)
**Headere lipsă:**
* **[Nume header]** | Severitate: [CRITICĂ/ÎNALTĂ/MEDIE/SCĂZUTĂ] | Impact: [explicație]

**Directoare/fișiere expuse:**
* **[Cale]** | Severitate: [nivel] | Status: [Accesibil/Restricționat]

Dacă nu s-a identificat nimic: menționează explicit pentru fiecare subsecțiune.

## 3. COMPONENTE VULNERABILE (A03)
**Tehnologii identificate:** [listă cu versiuni]
**CVE-uri găsite:**
* **[CVE-ID]** | Severitate: [nivel CVSS] | Afectează: [tehnologie + versiune] | Detalii: [descriere scurtă]

Dacă nu s-au găsit CVE-uri: "Nu au fost identificate CVE-uri pentru versiunile detectate."

## 4. VECTORI DE INJECTARE (A04)
* **Formular [N]** | Metodă: [GET/POST] | Câmpuri expuse: [lista câmpurilor] | Risc: [explicație]

Dacă nu există formulare: "Niciun formular identificat pe pagina principală."

## 5. REPUTAȚIE DOMENIU (VirusTotal)
* Data ultimei scanări: [dată]
* Vendori care au semnalat probleme: [număr] din [total]
* Concluzie: [CURAT / ATENȚIE / CRITIC] — [o propoziție de justificare]
* Dacă există vendori specifici care au semnalat probleme, listează-i.

## 6. SCOR DE RISC
Calculează scorul astfel (maxim 10):
- Header lipsă cu severitate CRITICĂ sau ÎNALTĂ → +1.5 puncte (maxim 3 headere numărate)
- Header lipsă cu severitate MEDIE → +0.5 puncte (maxim 3 headere numărate)
- Director/fișier accesibil cu severitate CRITICĂ → +2 puncte (maxim 1 numărat)
- CVE cu severitate CRITICĂ sau ÎNALTĂ → +1.5 puncte (maxim 2 numărate)
- VirusTotal: vendors malicious > 0 → +2 puncte | vendors suspicious > 0 → +1 punct
- Secret sau token găsit în sursă → +1 punct

**Scor final: [X.X]/10 — [SCĂZUT 1-3 / MEDIU 4-6 / ÎNALT 7-8 / CRITIC 9-10]**
Justificare: [o singură propoziție cu principalii factori care au determinat scorul]

## 7. PLAN DE REMEDIERE
Listează maxim 5 acțiuni, ordonate de la cea mai urgentă la cea mai puțin urgentă:
1. [Acțiune concretă] — [de ce e prioritară]
2. ...
"""
    try:
        rezultat = agent.invoke({"messages": [("user", instructiuni)]})
        raport = rezultat["messages"][-1].content
        return {"raport": raport}

    except Exception as e:
        tip_eroare = type(e).__name__
        mesaj_eroare = (
            f"## ❌ Eroare la Scanare\n\n"
            f"Scanarea a eșuat.\n"
            f"**Tip eroare:** `{tip_eroare}`\n"
            f"**Detalii:** `{str(e)}`"
        )
        return {"raport": mesaj_eroare}


# ==========================================
# RUTE NOI: EXECUȚIA INDIVIDUALĂ (Dashboard)
# ==========================================

def analizeaza_cu_ai(nume_tool: str, date_brute: str) -> str:
    """Trimite datele brute către Groq pentru un scurt rezumat uman."""
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"))
    
    prompt = f"""Ești un analist de securitate. Am rulat instrumentul '{nume_tool}' și am obținut datele de mai jos.
Te rog să oferi un rezumat explicativ în Markdown. 
Dacă există riscuri, explică-le clar și concis. Dacă totul este în regulă, confirmă acest lucru. Nu adăuga introduceri sau concluzii generice.

DATE BRUTE:
{date_brute}
"""
    try:
        raspuns = llm.invoke([HumanMessage(content=prompt)])
        return raspuns.content
    except Exception as e:
        return f"Eroare la generarea explicației AI: {str(e)}"

@app.post("/api/tool/a01-scraper")
async def run_a01_scraper(req: ScanRequest):
    valideaza_url(req.url)
    date_brute = scaneaza_cod_sursa(req.url)
    analiza_ai = analizeaza_cu_ai("Scraper Cod Sursă", date_brute)
    return {"raw_data": date_brute, "ai_analysis": analiza_ai}

@app.post("/api/tool/a02-headers")
async def run_a02_headers(req: ScanRequest):
    valideaza_url(req.url)
    date_brute = scaneaza_headere_http(req.url)
    analiza_ai = analizeaza_cu_ai("Audit Headere și Directoare", date_brute)
    return {"raw_data": date_brute, "ai_analysis": analiza_ai}

@app.post("/api/tool/a03-cve")
async def run_a03_cve(req: ScanRequest):
    valideaza_url(req.url)
    date_brute = verifica_versiuni_si_cve(req.url)
    analiza_ai = analizeaza_cu_ai("Identificare CVE-uri", date_brute)
    return {"raw_data": date_brute, "ai_analysis": analiza_ai}

@app.post("/api/tool/a04-injection")
async def run_a04_injection(req: ScanRequest):
    valideaza_url(req.url)
    date_brute = verifica_html_injection(req.url)
    analiza_ai = analizeaza_cu_ai("Detector Vectori Injectare", date_brute)
    return {"raw_data": date_brute, "ai_analysis": analiza_ai}

@app.post("/api/tool/virustotal")
async def run_virustotal(req: ScanRequest):
    valideaza_url(req.url)
    date_brute = verifica_reputatie_virustotal(req.url)
    analiza_ai = analizeaza_cu_ai("OSINT VirusTotal", date_brute)
    return {"raw_data": date_brute, "ai_analysis": analiza_ai}
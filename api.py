from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.tools import Tool
from langgraph.prebuilt import create_react_agent
from tools.a02_scanner import scaneaza_headere_http
from tools.a03_cve_check import verifica_versiuni_si_cve
from tools.a01_scraper import scaneaza_cod_sursa
from tools.a04_injection_check import verifica_html_injection

load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def scan(req: ScanRequest):
    unelte = [
        Tool(name="Scanner_Configurari_A02", func=scaneaza_headere_http,
             description="Verifică configurările HTTP (OWASP A02). Input: URL complet."),
        Tool(name="Verificator_CVE_A03", func=verifica_versiuni_si_cve,
             description="Detectează versiuni și CVE-uri (OWASP A03). Input: URL complet."),
        Tool(name="Scraper_Cod_Sursa_A01", func=scaneaza_cod_sursa,
             description="Descarcă HTML-ul și găsește comentarii sau date ascunse în sursă. Input: URL complet."),      
        Tool( name="Detector_HTML_Injection_A04",  func=verifica_html_injection,
              description="Scanează formularele și câmpurile de input pentru a identifica riscuri de injectare HTML. Input: URL complet."
    )]
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile",
                   api_key=os.getenv("GROQ_API_KEY"))
    agent = create_react_agent(llm, tools=unelte)

    instructiuni = f"""Acționezi în rolul de Principal Security Engineer.
    Realizează un audit de securitate tehnic pentru ținta: {req.url}.
    Utilizează exclusiv datele extrase de instrumentele din dotare (Scanner_Configurari_A02, Verificator_CVE_A03, Scraper_Cod_Sursa_A01,Detector_HTML_Injection_A04).

    REGULI DE REDACTARE:
    - Elimină complet emoticoanele și limbajul colocvial.
    - Folosește un ton clinic și obiectiv.
    - NU folosi fraze lungi de umplutură. Treci direct la date.

    STRUCTURA RAPORTULUI DE AUDIT (Folosește strict acest format Markdown):

    # RAPORT DE AUDIT DE SECURITATE (SAST & DAST)
    **Ținta evaluată:** `{req.url}`

    ## 1. REZULTATELE ANALIZEI STATICE (A01 - Source Code Analysis)
    - Documentează clar TOATE comentariile, input-urile ascunse și secretele (API keys, parole, email-uri) găsite.
    - Listează-le sub formă de puncte (bullet points) cu detaliile extrase.
    - Doar dacă nu s-a găsit ABSOLUT NIMIC în sursă, scrie simplu: "Nu au fost identificate elemente de risc în codul sursă (A01)."

    ## 2. AUDITUL CONFIGURĂRILOR (A02 - Security Misconfigurations)
    Listează vulnerabilitățile STRICT sub forma de mai jos, folosind separatorul "|":
    * **[Nume Header/Director]** | Severitate: [CRITICĂ/ÎNALTĂ/MEDIE/SCĂZUTĂ] | Risc: [Scurtă explicație a impactului]

    ## 3. INVENTARUL COMPONENTELOR ȘI CVE-URI (A03 - Vulnerable Components)
    - Amprente tehnologice detectate: [Enumeră serverul/versiunile găsite]
    - CVE-uri identificate (folosește STRICT formatul cu separator "|"):
    * **[ID-ul CVE]** | Severitate: [Scor/Nivel CVSS] | Detalii: [Descriere scurtă tehnică]
    - (Dacă nu găsești CVE-uri, scrie: "Nu au fost identificate vulnerabilități publice pentru tehnologiile curente.")

    ## 4. EVALUAREA RISCULUI GENERAL (RISK POSTURE)
    - Calculează un indice de risc (1 la 10) folosind grila: +2 pt header/director cu risc Înalt/Critic absent, +1 pt header cu risc Mediu, +2 pt fiecare CVE. Scorul maxim este 10.
    - Afișează scorul exact așa: **Scor de risc calculat: [X]/10 - [CRITIC/ÎNALT/MEDIU/SCĂZUT]**
    - Justificare: [O singură frază tehnică care explică scorul]

    ## 5. ANALIZA COLECTĂRII DE DATE (A04 - HTML Injection)
    - Documentează formularele identificate și câmpurile care permit input de la utilizator.
    - Explică riscul dacă datele nu sunt sanitizate.

    ## 6. PLAN DE REMEDIERE (MITIGATION STRATEGY)
    - Listează 3-4 pași exacți și prioritizați pentru a repara problemele găsite, cu focus pe cele CRITICE și ÎNALTE.
    """
    try:
        rezultat = agent.invoke({"messages": [("user", instructiuni)]})
        raport = rezultat["messages"][-1].content
        return {"raport": raport}
        
    except Exception as e:
        # Dacă agentul sau LLM-ul crapă, trimitem eroarea elegant către React
        mesaj_eroare = f"## ❌ Eroare la Scanare\n\nDin păcate, scanarea a eșuat. Detalii tehnice: `{str(e)}`"
        return {"raport": mesaj_eroare}
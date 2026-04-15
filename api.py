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
             description="Detectează versiuni și CVE-uri (OWASP A03). Input: URL complet.")
    ]
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile",
                   api_key=os.getenv("GROQ_API_KEY"))
    agent = create_react_agent(llm, tools=unelte)

    instructiuni = f"""Ești un auditor de securitate cibernetică.
    Evaluează ținta {req.url} folosind ambele unelte la dispoziție:
    1. Folosește Scanner_Configurari_A02 pentru configurări HTTP.
    2. Folosește Verificator_CVE_A03 pentru a detecta versiunile și CVE-urile posibile.

    IMPORTANT: Trebuie să răspunzi STRICT cu un Raport de Audit formatat în Markdown.
    Raportul trebuie să conțină:
    # 🛡️ Raport de Audit de Securitate
    ## 🎯 Ținta Evaluată
    ## 🚨 Vulnerabilități de Configurare (A02)
    - Listează FIECARE header lipsă pe linie separată cu severitatea și riscul exact din datele primite
    - Listează FIECARE director găsit cu severitatea exactă din datele primite
    ## 📦 Versiuni și CVE-uri Descoperite (A03)
    - Listează FIECARE CVE găsit pe linie separată cu severitatea lui
    ## 📊 Scor de Risc General
    - Calculează un scor de la 1 la 10 bazat pe:
    * Header lipsă cu severitate ÎNALTĂ → +2 puncte fiecare
    * Header lipsă cu severitate MEDIE → +1 punct fiecare
    * Director accesibil cu severitate CRITICĂ sau ÎNALTĂ → +2 puncte fiecare
    * CVE cu severitate Critică/Înaltă → +2 puncte fiecare
    - Prezintă scorul ca: 🔴 CRITIC (8-10) / 🟠 ÎNALT (5-7) / 🟡 MEDIU (3-4) / 🟢 SCĂZUT (1-2)
    - Explică în 2-3 propoziții de ce ai dat acel scor
    ## 🛠️ Pași de Remediere (ordonați după prioritate, de la cel mai urgent)
    """
    rezultat = agent.invoke({"messages": [("user", instructiuni)]})
    raport = rezultat["messages"][-1].content
    return {"raport": raport}
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
    Evaluează ținta {req.url} folosind ambele unelte.
    Răspunde STRICT în Markdown cu:
    # 🛡️ Raport de Audit de Securitate
    ## 🎯 Ținta Evaluată
    ## 🚨 Vulnerabilități de Configurare (A02)
    ## 📦 Versiuni și CVE-uri Descoperite (A03)
    ## 🛠️ Pași de Remediere
    """
    rezultat = agent.invoke({"messages": [("user", instructiuni)]})
    raport = rezultat["messages"][-1].content
    return {"raport": raport}
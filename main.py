import os
import warnings
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.tools import Tool
from langgraph.prebuilt import create_react_agent 

# Ignorăm avertismentele
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Importăm unealta
from tools.a02_scanner import scaneaza_headere_http
from tools.a03_cve_check import verifica_versiuni_si_cve 
load_dotenv()

# Definim uneltele
unelte = [
    Tool(
        name="Scanner_Configurari_A02",
        func=scaneaza_headere_http,
        description="Unealtă obligatorie pentru a verifica configurările HTTP (OWASP A02). Așteaptă un URL complet ca input."
    ),
    Tool(
        name="Verificator_CVE_A03",
        func=verifica_versiuni_si_cve,
        description="Unealtă pentru a identifica versiunile tehnologiilor de pe server și a căuta vulnerabilități cunoscute (CVE-uri) conform OWASP A03. Așteaptă un URL complet."
    )
]

# Inițializăm LLM-ul Groq
llm = ChatGroq(
    temperature=0, 
    model="llama-3.3-70b-versatile", 
    api_key=os.getenv("GROQ_API_KEY")
)

# Creăm Agentul
agent = create_react_agent(llm, tools=unelte)

if __name__ == "__main__":
    tinta = "http://localhost:3000"
    
    print("\n" + "="*50)
    print("🤖 AGENTUL AI DE SECURITATE SCANEAZĂ ȘI REDACTEAZĂ...")
    print("="*50 + "\n")
    
    # 2. Prompt-ul pentru raportul de audit
    instructiuni = f"""Ești un auditor de securitate cibernetică.
    Evaluează ținta {tinta} folosind ambele unelte la dispoziție:
    1. Folosește Scanner_Configurari_A02 pentru configurări HTTP.
    2. Folosește Verificator_CVE_A03 pentru a detecta versiunile și CVE-urile posibile.
    
    IMPORTANT: Trebuie să răspunzi STRICT cu un Raport de Audit formatat în Markdown.
    Raportul trebuie să conțină:
    # 🛡️ Raport de Audit de Securitate
    ## 🎯 Ținta Evaluată
    ## 🚨 Vulnerabilități de Configurare (A02)
    ## 📦 Versiuni și CVE-uri Descoperite (A03)
    ## 📊 Scor de Risc General
  - Calculează un scor de la 1 (minim) la 10 (critic) bazat pe:
    * Numărul de headere lipsă cu severitate ÎNALTĂ → +2 puncte fiecare
    * Numărul de headere lipsă cu severitate MEDIE → +1 punct fiecare  
    * Directoare accesibile cu severitate CRITICĂ sau ÎNALTĂ → +2 puncte fiecare
    * CVE-uri cu severitate Critică/Înaltă → +2 puncte fiecare
  - Prezintă scorul ca: 🔴 CRITIC (8-10) / 🟠 ÎNALT (5-7) / 🟡 MEDIU (3-4) / 🟢 SCĂZUT (1-2)
  - Explică în 2-3 propoziții de ce ai dat acel scor
    ## 🛠️ Pași de Remediere
    """
    
    # Pornim agentul
    rezultat = agent.invoke({"messages": [("user", instructiuni)]})
    
    # Extragem textul final generat de AI
    raport_text = rezultat["messages"][-1].content
    
    # 3. Creăm folderul 'raport' și salvăm fișierul
    os.makedirs("raport", exist_ok=True)
    
    cale_fisier = "raport/Raport_Final.md"
    with open(cale_fisier, "w", encoding="utf-8") as f:
        f.write(raport_text)
    
    print("✅ SCANARE COMPLETĂ!")
    print(f"📄 Raportul a fost generat și salvat cu succes în: {cale_fisier}")
    print("="*50)
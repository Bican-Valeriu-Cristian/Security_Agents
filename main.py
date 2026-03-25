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

load_dotenv()

# Definim uneltele
unelte = [
    Tool(
        name="Scanner_Configurari_A02",
        func=scaneaza_headere_http,
        description="Unealtă obligatorie pentru a verifica configurările HTTP și headerele de securitate (OWASP A02). Așteaptă un URL complet ca input."
    )
]

# Inițializăm LLM-ul Groq
llm = ChatGroq(
    temperature=0, 
    model_name="llama-3.3-70b-versatile", 
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
    Evaluează ținta {tinta} pentru vulnerabilități OWASP A02 (Security Misconfiguration) folosind unealta Scanner_Configurari_A02.
    
    IMPORTANT: Trebuie să răspunzi STRICT cu un Raport de Audit formatat în Markdown.
    Raportul trebuie să conțină următoarele secțiuni:
    # 🛡️ Raport de Audit de Securitate
    ## 🎯 Ținta Evaluată
    ## 🚨 Vulnerabilități Descoperite (A02)
    ## 🛠️ Pași de Remediere (Explicați clar)
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
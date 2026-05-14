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

    instructiuni = f"""Ești un auditor de securitate cibernetică senior. Realizează un audit complet pentru: {req.url}

PASUL 1 - COLECTARE DATE (folosește TOATE cele 5 instrumente)
PASUL 2 - REDACTARE RAPORT
Respectă STRICT structura. Ton clinic.

# RAPORT DE AUDIT DE SECURITATE
**Ținta:** `{req.url}`

## 1. ANALIZA CODULUI SURSĂ (A01)
## 2. CONFIGURĂRI DE SECURITATE (A02)
## 3. COMPONENTE VULNERABILE (A03)
## 4. VECTORI DE INJECTARE (A04)
## 5. REPUTAȚIE DOMENIU (VirusTotal)
## 6. PLAN DE REMEDIERE

IMPORTANT: Indiferent de rezultate, la finalul absolut al raportului, pe rânduri noi, scrie EXACT acest bloc (unde X, Y, Z sunt numărul de vulnerabilități distincte găsite, pune 0 dacă nu sunt):
[VULNERABILITĂȚI]
SCĂZUT: X
MEDIU: Y
CRITIC: Z
"""
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

def analizeaza_cu_ai(nume_tool: str, date_brute: str) -> str:
    llm = ChatGroq(temperature=0, model="llama-3.3-70b-versatile", api_key=os.getenv("GROQ_API_KEY"))
    prompt = f"""Ești un analist de securitate. Am rulat '{nume_tool}'. Datele:
{date_brute}

Oferă un rezumat explicativ în Markdown. 
IMPORTANT: La finalul absolut al raportului, scrie EXACT acest bloc cu numărul de probleme găsite în datele de mai sus (pune 0 dacă totul e curat):
[VULNERABILITĂȚI]
SCĂZUT: X
MEDIU: Y
CRITIC: Z
"""
    try:
        return llm.invoke([HumanMessage(content=prompt)]).content
    except Exception as e:
        return f"Eroare AI: {str(e)}"

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
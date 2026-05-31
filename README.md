# 🛡️ WebScanAI - Agent Security Web

WebScanAI este o aplicație web Full-Stack bazată pe un agent AI autonom (LangGraph + Llama 3.3) ce rulează audituri pasive de securitate și analizează:

* 📡 **A01 - Source Scraper:** Identifică scurgeri de secrete (JWT, API keys) și analizează comentariile uitate în HTML și în scripturile JavaScript externe.
* 🔧 **A02 - Server & File Scanner:** Verifică lipsa headerelor HTTP (OWASP), face crawling (BFS) și caută directoare sensibile expuse precum `.env` sau `.git`.
* 🔍 **A03 - CVE Live Detector:** Amprentează tehnologiile serverului și interoghează live API-ul guvernamental al SUA (NIST NVD) pentru vulnerabilități publice.
* 💉 **A04 - Injection Check:** Identifică pasiv formularele web și calculează un scor de risc (1-10) bazat pe euristici de denumire a câmpurilor (SQLi, XSS).
* 🦠 **Threat Intelligence:** Integrează API-ul VirusTotal pentru o verificare live de reputație globală a domeniului.

---

## 📸 Capturi de Ecran 

### 1. Login
<img width="358" height="376" alt="image" src="https://github.com/user-attachments/assets/1d7f8c45-590b-4c0d-a750-2023de4668ba" />

### 2. Dashboard
<img width="1350" height="726" alt="image" src="https://github.com/user-attachments/assets/492c1b95-fbe0-490b-8955-a2b7a75213a1" />

### 3. Data Logs
<img width="1321" height="708" alt="image" src="https://github.com/user-attachments/assets/97480ef4-c0e1-457e-877d-616eb9de2f38" />

---

## 🚀

docker run --rm -p 3000:3000 bkimminich/juice-shop
<br>
python -m uvicorn api:app --reload
<br>
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
<br>
npm run dev
<br>
http://testaspnet.vulnweb.com/
https://dannicula.ro/contact.html

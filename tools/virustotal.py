import requests
import os
import base64
from dotenv import load_dotenv

# Încărcăm variabilele de mediu din .env
load_dotenv()

def verifica_reputatie_virustotal(url: str) -> str:
    """
    Folosește API-ul VirusTotal pentru a verifica
    dacă URL-ul a fost raportat în trecut pentru Malware sau Phishing.
    """
    print(f"\n[🌐 Tool Executat] Verific reputația globală pentru {url} pe VirusTotal...")
    
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "Eroare internă: Cheia VIRUSTOTAL_API_KEY nu este configurată în fișierul .env."

    # VirusTotal v3 cere ca URL-ul să fie codat în format base64url (fără '=' la final)
    # pentru a-l folosi ca ID în interogare.
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    except Exception as e:
        return f"Nu am putut formata URL-ul pentru VirusTotal: {str(e)}"

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        raspuns = requests.get(endpoint, headers=headers, timeout=10)

        if raspuns.status_code == 200:
            date_json = raspuns.json()
            # Extragem direct secțiunea cu statisticile (cati au zis ca e periculos vs curat)
            statistici = date_json.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious = statistici.get('malicious', 0)
            suspicious = statistici.get('suspicious', 0)
            harmless = statistici.get('harmless', 0)
            undetected = statistici.get('undetected', 0)
            total_scans = malicious + suspicious + harmless + undetected

            rezultat = f"--- Rezultate Threat Intelligence (VirusTotal) pentru {url} ---\n\n"
            rezultat += f"Analizat de {total_scans} vendori de securitate (Kaspersky, Bitdefender, Google, etc.):\n"
            rezultat += f"- 🔴 Marcat ca Rău Intenționat (Malicious): {malicious}\n"
            rezultat += f"- 🟠 Marcat ca Suspect (Suspicious): {suspicious}\n"
            rezultat += f"- 🟢 Marcat ca Inofensiv/Nedetectat: {harmless + undetected}\n\n"

            if malicious > 0 or suspicious > 0:
                rezultat += "CONCLUZIE: [CRITIC] Domeniul are un istoric negativ și este prezent pe listele negre (Blacklists)!\n"
            else:
                rezultat += "CONCLUZIE: [CURAT] Domeniul are o reputație bună și nu apare pe listele negre.\n"

            return rezultat

        elif raspuns.status_code == 404:
            return "CONCLUZIE: Domeniul nu există încă în baza de date VirusTotal (Nu a fost scanat niciodată)."
        elif raspuns.status_code == 401:
            return "Eroare VirusTotal: Cheia API este invalidă."
        elif raspuns.status_code == 429:
            return "Eroare VirusTotal: Am atins limita de scanări. Mai așteaptă un minut."
        else:
            return f"Eroare VirusTotal: Cod de răspuns {raspuns.status_code}"

    except requests.exceptions.RequestException as e:
        return f"Eroare de conexiune la API-ul VirusTotal: {str(e)}"


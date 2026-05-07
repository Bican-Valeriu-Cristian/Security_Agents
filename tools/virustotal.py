import datetime
import requests
import os
import base64
from dotenv import load_dotenv

# Încărcăm variabilele de mediu din .env
load_dotenv()

def verifica_reputatie_virustotal(url: str) -> str:
    """
    Folosește API-ul VirusTotal pentru a verifica reputația domeniului.
    Dacă URL-ul este nou sau nu are date de scanare, forțează o scanare activă (Active Submission).
    """
    print(f"\n[🌐 Tool Executat] Verific reputația globală pentru {url} pe VirusTotal...")
    
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "Eroare internă: Cheia VIRUSTOTAL_API_KEY nu este configurată în fișierul .env."

    # VirusTotal v3 cere ca URL-ul să fie codat în format base64url (fără '=' la final)
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    except Exception as e:
        return f"Nu am putut formata URL-ul pentru VirusTotal: {str(e)}"

    endpoint_get = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    endpoint_post = "https://www.virustotal.com/api/v3/urls"
    
    headers_get = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    headers_post = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    try:
        # Pasul 1: Încercăm să luăm datele pasiv (GET)
        raspuns = requests.get(endpoint_get, headers=headers_get, timeout=10)

        # SCENARIUL A: Site-ul există în baza de date
        if raspuns.status_code == 200:
            date_json = raspuns.json()
            atribute = date_json.get('data', {}).get('attributes', {})
            statistici = atribute.get('last_analysis_stats', {})
            
            malicious = statistici.get('malicious', 0)
            suspicious = statistici.get('suspicious', 0)
            harmless = statistici.get('harmless', 0)
            undetected = statistici.get('undetected', 0)
            timeout = statistici.get('timeout', 0) + statistici.get('confirmed-timeout', 0)
            total_scans = malicious + suspicious + harmless + undetected + timeout

            last_analysis_date = atribute.get('last_analysis_date')
            if last_analysis_date:
                data_scanare = datetime.datetime.utcfromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M UTC')
            else:
                data_scanare = "necunoscută"

            rezultat = f"--- Rezultate Threat Intelligence (VirusTotal) pentru {url} ---\n\n"
            rezultat += f"Ultima scanare: {data_scanare}\n"
            rezultat += f"Analizat de {total_scans} vendori de securitate:\n"
            rezultat += f"- 🔴 Marcat ca Rău Intenționat (Malicious): {malicious}\n"
            rezultat += f"- 🟠 Marcat ca Suspect (Suspicious): {suspicious}\n"
            rezultat += f"- 🟢 Marcat ca Inofensiv/Nedetectat: {harmless + undetected}\n"
            if timeout > 0:
                rezultat += f"- ⏱️ Timeout (nu au putut analiza): {timeout}\n"
            rezultat += "\n"

            # Concluzie și FORȚAREA SCANĂRII ACTIVE dacă nu sunt date
            if total_scans == 0:
                rezultat += "CONCLUZIE: [INFO] Domeniul nu are date suficiente. Inițiez o scanare activă către laboratoarele VirusTotal...\n"
                try:
                    submit_resp = requests.post(endpoint_post, headers=headers_post, data=f"url={url}", timeout=10)
                    if submit_resp.status_code == 200:
                        rezultat += "✅ SUCCES: URL-ul a fost trimis pentru analiză. Datele vor fi disponibile la o scanare ulterioară (peste ~2 minute).\n"
                    else:
                        rezultat += f"❌ EROARE: Nu am putut forța scanarea (Cod: {submit_resp.status_code}).\n"
                except Exception as e:
                    rezultat += f"❌ EROARE la conexiunea de submit: {str(e)}\n"

            elif malicious > 0:
                rezultat += "CONCLUZIE: [CRITIC] Domeniul este marcat ca rău intenționat și apare pe listele negre!\n"
            elif suspicious > 0:
                rezultat += f"CONCLUZIE: [ATENȚIE] {suspicious} vendor(i) au marcat domeniul ca suspect. Necesită investigație suplimentară.\n"
            else:
                rezultat += "CONCLUZIE: [CURAT] Domeniul are o reputație bună și nu apare pe listele negre.\n"

            # Extragem și afișăm ce vendor a raportat problema
            rezultate_individuale = atribute.get('last_analysis_results', {})
            vendori_periculosi = [
                (vendor, info.get('result', 'unknown'))
                for vendor, info in rezultate_individuale.items()
                if info.get('category') in ('malicious', 'suspicious')
            ]
            if vendori_periculosi:
                rezultat += "\nVendori care au semnalat probleme:\n"
                for vendor, motiv in vendori_periculosi[:10]:
                    rezultat += f"  - {vendor}: {motiv}\n"

            return rezultat

        # SCENARIUL B: Site-ul este complet necunoscut (Eroare 404)
        elif raspuns.status_code == 404:
            rezultat = f"--- Rezultate Threat Intelligence (VirusTotal) pentru {url} ---\n\n"
            rezultat += "CONCLUZIE: [INFO] URL-ul este complet necunoscut în baza de date VirusTotal.\n"
            rezultat += "Inițiez o scanare activă automată...\n"
            
            try:
                submit_resp = requests.post(endpoint_post, headers=headers_post, data=f"url={url}", timeout=10)
                if submit_resp.status_code == 200:
                    rezultat += "✅ SUCCES: Domeniul a fost trimis către antiviruși. Vă rugăm să reluați auditul în ~2 minute pentru a vedea rezultatele.\n"
                else:
                    rezultat += f"❌ EROARE: Nu am putut forța scanarea (Cod: {submit_resp.status_code}).\n"
            except Exception as e:
                rezultat += f"❌ EROARE la forțarea scanării: {str(e)}\n"
            
            return rezultat

        # SCENARIUL C: Erori de conexiune/API
        elif raspuns.status_code == 401:
            return "Eroare VirusTotal: Cheia API este invalidă."
        elif raspuns.status_code == 429:
            return "Eroare VirusTotal: Am atins limita de scanări (Rate Limit). Mai așteaptă un minut."
        else:
            return f"Eroare VirusTotal: Cod de răspuns {raspuns.status_code}"

    except requests.exceptions.RequestException as e:
        return f"Eroare de conexiune la API-ul VirusTotal: {str(e)}"


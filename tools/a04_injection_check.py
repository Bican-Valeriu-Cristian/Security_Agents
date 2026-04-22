import requests
from bs4 import BeautifulSoup

def verifica_html_injection(url: str) -> str:
    """
    Analizează formularele și câmpurile de intrare pentru a identifica vectori 
    potențiali de HTML Injection (OWASP A03:2021 - Injection).
    """
    print(f"\n[💉 Tool Executat] Analizez vectorii de injectare pentru {url}...")
    
    try:
        raspuns = requests.get(url, timeout=5)
        soup = BeautifulSoup(raspuns.text, 'html.parser')
        
        rezultat = f"--- Rezultate Verificare HTML Injection pentru {url} ---\n\n"
        
        formulare = soup.find_all('form')
        if not formulare:
            return rezultat + "✅ Nu au fost găsite formulare vizibile pe această pagină.\n"
        
        rezultat += f"🔎 Am găsit {len(formulare)} formulare care pot fi vulnerabile:\n"
        
        for i, form in enumerate(formulare, 1):
            actiune = form.get('action', '(aceeași pagină)')
            metoda = form.get('method', 'get').upper()
            rezultat += f"\nFormular {i} [Metoda: {metoda} | Acțiune: {actiune}]:\n"
            
            inputuri = form.find_all(['input', 'textarea'])
            for inp in inputuri:
                tip = inp.get('type', 'text')
                nume = inp.get('name', 'fără-nume')
                
                # Ignorăm butoanele și câmpurile ascunse (tratate deja în A01)
                if tip not in ['submit', 'hidden', 'button']:
                    rezultat += f"  - Câmp detectat: '{nume}' (Tip: {tip})\n"
                    rezultat += f"    Risc: Permite introducerea de tag-uri <html> sau <script>.\n"

        rezultat += "\n💡 Recomandare: Testați aceste câmpuri introducând manual un payload de test: <h1>Test</h1>"
        return rezultat

    except Exception as e:
        return f"Eroare la scanarea pentru injectare: {str(e)}"

if __name__ == "__main__":
    print(verifica_html_injection("http://localhost:3000"))
import smtplib
import requests
from bs4 import BeautifulSoup
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import argparse

# Configuration email
EMAIL_SENDER = "a.fernandes0107@gmail.com"
EMAIL_PASSWORD = "uiimeytvafrjmbla"
EMAIL_RECEIVER = "a.fernandes0107@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Retourne le nom du fichier où stocker le dernier CVE détecté pour un mot-clé donné
def get_storage_file(keyword):
    safe_keyword = keyword.lower().replace(" ", "_")
    return f"last_cve_{safe_keyword}.txt"

# Recherche la dernière CVE publiée correspondant au mot-clé
def get_latest_cve(keyword):
    url = f"https://nvd.nist.gov/vuln/search/results?query={keyword}&search_type=all"
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        results = soup.select("a[href^='/vuln/detail/CVE']")
        if results:
            first_result = results[0]
            cve_id = first_result.text.strip()
            cve_url = "https://nvd.nist.gov" + first_result["href"]
            return cve_id, f"{cve_id} détectée pour '{keyword}'\nLien : {cve_url}"
        else:
            return None, f"Aucune CVE trouvée pour : {keyword}"

    except Exception as e:
        return None, f"Erreur lors de la récupération des données : {e}"

# Envoi d'email
def send_email(subject, body):
    message = MIMEMultipart()
    message["From"] = EMAIL_SENDER
    message["To"] = EMAIL_RECEIVER
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, message.as_string())
        server.quit()
        print("📧 Alerte CVE envoyée avec succès.")
    except Exception as e:
        print("❌ Erreur lors de l'envoi de l'e-mail :", e)

# Lecture et mise à jour du fichier de suivi local
def read_last_cve(filename):
    if not os.path.exists(filename):
        return None
    with open(filename, "r") as f:
        return f.read().strip()

def write_last_cve(filename, cve_id):
    with open(filename, "w") as f:
        f.write(cve_id)

# Point d'entrée
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Surveille les CVE pour un mot-clé donné.")
    parser.add_argument("--keyword", required=True, help="Nom de l'outil ou du mot-clé à surveiller (ex: GLPI, Zimbra, etc.)")
    args = parser.parse_args()

    keyword = args.keyword
    storage_file = get_storage_file(keyword)

    current_cve_id, cve_info = get_latest_cve(keyword)
    if current_cve_id:
        last_cve_id = read_last_cve(storage_file)
        if current_cve_id != last_cve_id:
            send_email(f"🛡 Nouvelle vulnérabilité détectée pour '{keyword}'", cve_info)
            write_last_cve(storage_file, current_cve_id)
        else:
            print(f"✅ Aucune nouvelle vulnérabilité pour '{keyword}'.")
    else:
        print(f"⚠️ {cve_info}")

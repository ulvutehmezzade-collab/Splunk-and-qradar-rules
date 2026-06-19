import requests
import urllib3
import os

# Tehlukesizlik xeberdarliqlarini gizleyirik
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Konfiqurasiya melumatlari
SPLUNK_HOST = "35.175.66.83"
SPLUNK_PORT = "8089"

# Tokeni muhit deyiseninden (Environment Variable) oxuyuruq
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")

# Eger token tapilmazsa, skriptin xeta vermesini temin edirik
if not SPLUNK_TOKEN:
    raise ValueError("XETA: SPLUNK_TOKEN muhit deyiseni teyin edilmeyib!")

# Splunk REST API unvani
url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/admin/search/saved/searches"

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}"
}

rule_data = {
    "name": "GitHub_Detected_Brute_Force",
    "search": "index=firewall action=blocked | stats count by src_ip | filter count > 100",
    "description": "GitHub vasitesile avtomatik yuklenmis kritik hucum qaydasi",
    "is_scheduled": "1",
    "cron_schedule": "*/5 * * * *"
}

response = requests.post(url, headers=headers, data=rule_data, verify=False)

if response.status_code == 201:
    print("Ugurlu! Qayda Splunk serverine yuklendi.")
else:
    print(f"Xeta bas verdi! Status Code: {response.status_code}")
    print(response.text)

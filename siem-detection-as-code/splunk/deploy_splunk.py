import requests
import urllib3
import os

# Tehlukesizlik xeberdarliqlarini gizleyirik (eger SSL sertifikatin yoxdursa)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Konfiqurasiya melumatlari
SPLUNK_HOST = "35.175.66.83"
SPLUNK_PORT = "8089"
# Tokeninizi bura daxil edin
SPLUNK_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJ1bHZ1MTM0MiBmcm9tIGlwLTE3Mi0zMS00Ny0yNDEiLCJzdWIiOiJ1bHZ1MTM0MiIsImF1ZCI6IkdpdEh1YiBBdXRvbWF0aW9uIiwiaWRwIjoiU3BsdW5rIiwianRpIjoiMjI5ZjZkZGFiZmQ3MWEyMzgwNmM3NTI0OGZmNjYxM2VlODRiNGNlYWNhZmNlMmFmMGY4NzNmYWRlYTY1ZWQ2NiIsImlhdCI6MTc4MTc5Mzg4MiwiZXhwIjoxNzg0Mzg1ODgyLCJuYnIiOjE3ODE3OTM4ODJ9.yFqh1t1tQn0eoT9lwVuF0M8pNh63b9yOTMf0fqziMvG3qj99sInbRb4EZvu0tR6m9OG21Vm1VR_gVUwm0rFp0A" 

# Splunk REST API unvani (Qaydalar - Saved Searches elave etmek ucun endpoint)
url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/admin/search/saved/searches"

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}"
}

# GitHub-dan yuklemek istediyiniz numune bir qayda (Brute Force askarlama)
rule_data = {
    "name": "GitHub_Detected_Brute_Force",
    "search": "index=firewall action=blocked | stats count by src_ip | filter count > 100",
    "description": "GitHub vasitesile avtomatik yuklenmis kritik hucum qaydasi",
    "is_scheduled": "1",
    "cron_schedule": "*/5 * * * *" # Her 5 deqiqeden bir islesin
}

# API sorgusunu gonderirik
response = requests.post(url, headers=headers, data=rule_data, verify=False)

if response.status_code == 201:
    print("Ugurlu! Qayda GitHub-dan birbasa Splunk serverine yuklendi.")
else:
    print(f"Xeta bas verdi! Status Code: {response.status_code}")
    print(response.text)
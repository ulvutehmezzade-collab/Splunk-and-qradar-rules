import os
import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "").strip()
# IP adresini kodun icinden silib sistemden oxuyuruq:
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "").strip()

if not SPLUNK_TOKEN or not SPLUNK_HOST:
    print("XATA: SPLUNK_TOKEN ve ya SPLUNK_HOST tapilmadi!")
    exit(1)

API_URL = f"{SPLUNK_HOST}/servicesNS/nobody/search/saved/searches"

headers = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/x-www-form-urlencoded"
}

RULES_FILE = "siem-detection-as-code/splunk/rules.json"

def deploy_rules():
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            rules = json.load(f)
    except FileNotFoundError:
        try:
            with open("rules.json", "r", encoding="utf-8") as f:
                rules = json.load(f)
        except Exception as e:
            print(f"XATA: rules.json tapilmadi: {e}")
            exit(1)

    print(f"Sinxronizasiya basladi. Qaydalarin sayi: {len(rules)}")

    for rule in rules:
        rule_name = rule.get("name")
        rule_data = {
            "name": rule_name,
            "search": rule.get("search"),
            "is_scheduled": 1,
            "cron_schedule": rule.get("cron_schedule", "*/5 * * * *"),
            "dispatch.earliest_time": rule.get("earliest_time", "-15m"),
            "dispatch.latest_time": rule.get("latest_time", "now"),
            "action.webhook": 1,
            "action.webhook.cfg.url": rule.get("webhook_url"),
            "disabled": 0,
            "force_overwrite": "true"
        }

        print(f"Qayda gonderilir: {rule_name}")
        
        try:
            response = requests.post(API_URL, headers=headers, data=rule_data, verify=False, timeout=15)

            if response.status_code in [200, 201]:
                print(f"UGUR: Qayda yaradildi: {rule_name}")
            elif response.status_code == 409:
                update_url = f"{API_URL}/{rule_name}"
                response = requests.post(update_url, headers=headers, data=rule_data, verify=False, timeout=15)
                if response.status_code == 200:
                    print(f"UGUR: Qayda yenilendi: {rule_name}")
                else:
                    print(f"XATA: Qayda yenilenmedi ({rule_name}): {response.text}")
            else:
                print(f"XATA: Status kodu: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"XATA: Baglanti qurula bilmedi ({rule_name}): {e}")

if __name__ == "__main__":
    deploy_rules()

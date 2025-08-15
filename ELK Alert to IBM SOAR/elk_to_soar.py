import base64
import json
import requests
import aiohttp
import asyncio
import re
from elasticsearch8 import Elasticsearch
from datetime import datetime

# -----------------------------
# ----- Global Settings --
# -----------------------------
###True esetén konzolra és fájlba is kiírja az ELK-s lekérdezéseket, illetve a SOAR-ba beküldendő adatokat.
debug_mode = False
###False esetén az ELK-ból lekért és formázott adatokat, nem küldi be a SOAR felé.
send_to_soar = True

# Config (ide tedd be külső fájlból is akár)
es_host = "https://1.1.1.1:9200"
es_user = "user"
es_pass = "password"

# Index neve (Opcionálisan cserélhető)
es_index = ".internal.alerts-security.alerts-default-*"

soar_host = "2.2.2.2"
api_key_id = "xxxxxxxxxxxxxxxxxxxxxxx"
api_key_secret = "yyyyyyyyyyyyyyyyyyyyy"
org_id = "201"

# -----------------------------
# ----- Functions ----------
# -----------------------------
    
    ##########################
      # Connect to Elastic #
    ##########################
async def connect_to_elasticsearch():
    es_client = Elasticsearch(
        es_host,
        basic_auth=(es_user, es_pass),
        verify_certs=False
    )
    return es_client
    
    ##########################
      # Search doc from ES #
    ##########################
async def search_documents_from_es(es_host, index, query_body, size=100, filename="elk_results.txt"):
    try:
        # Az Elasticsearch URL-je
        url = f"{es_host}/{index}/_search"
        
        headers = {
            "Content-Type": "application/json"
        }

        # Autentikáció
        auth = aiohttp.BasicAuth(es_user, es_pass)

        # A size paraméter hozzáadása a query_body-hoz
        query_body["size"] = size

        # Aszinkron HTTP kapcsolat létrehozása
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=query_body, headers=headers, auth=auth, verify_ssl=False) as response:
                # Ha a válasz sikeres (HTTP 200)
                if response.status == 200:
                    data = await response.json()
                    hits = data["hits"]["hits"]

                    # Debug mód engedélyezése esetén
                    if debug_mode:
                        print(f"DEBUG MODE: ✅ Elasticsearch keresési találatok száma: {len(hits)}")
                        for hit in hits:
                            print(json.dumps(hit["_source"], indent=2, ensure_ascii=False))

                    # Ha szükséges, a találatok fájlba mentése
                    if debug_mode:
                        with open(filename, 'w', encoding='utf-8') as file:
                            json.dump(hits, file, indent=2, ensure_ascii=False)
                            print(f"✔️ Az adatokat sikeresen elmentettük a '{filename}' fájlba.")

                    return hits
                else:
                    raise Exception(f"Elasticsearch kérés hiba: {response.status}")
    except Exception as e:
        raise RuntimeError(f"Hiba az Elasticsearch keresésnél: {e}")

    ####################
      # SOAR Connect #
    ####################
def get_soar_headers():
    auth = f"{api_key_id}:{api_key_secret}"
    encoded_auth = base64.b64encode(auth.encode()).decode()
    return {
        "Content-Type": "application/json",
        "Authorization": "Basic " + encoded_auth
    }

    #######################################
      # Check SIEM Rule Name with Query #
    #######################################
def build_query_with_rule_name_check(prefix="TST_", tags=["tst", "TST"]):
    return {
        "query": {
            "bool": {
                "should": [  # "should" = vagy-vagy kapcsolat
                    {
                        "wildcard": {
                            "kibana.alert.rule.name": {
                                "value": f"{prefix}*"
                            }
                        }
                    },
                    {
                        "terms": {
                            "kibana.alert.rule.tags": tags 
                        }
                    }
                ],
                "minimum_should_match": 1  # Legalább egy feltételnek teljesülnie kell
            }
        },
        "sort": [
            {
                "kibana.alert.original_event.ingested": {
                    "order": "desc"
                }
            }
        ]
    }

    ###############################
      # Create payload from doc #
    ###############################
def create_payload_from_doc(doc, hit, alert_id=None):
    
    index_name = hit["_index"]  # Lekérjük az index nevét
    alert_id = hit["_id"]  # Lekérjük az alert ID-t
    
    rule_name = doc.get("kibana.alert.rule.name", "Unknown Rule")
    hostname = doc.get("host", {}).get("hostname", "No hostname")
    ip_address = doc.get("host", {}).get("ip", [])[0]
    severity = doc.get("kibana.alert.severity", "Low")  # Alapértelmezett "Low", ha nincs érték
    message = doc.get("message", "Nincs üzenet.")
    alert_url = doc.get("kibana.alert.url", "No Alert URL")
    event_ingested = doc.get("kibana.alert.original_event.ingested", "No time for this event")
    
    # Leírás elkészítése
    description = (
        f"SIEM Rule: {rule_name}\n"
        f"Hostname: {hostname}\n"
        f"Severity: {severity}\n" #Az incidens kreálása során a SOAR-ban severity-t is megadom, ergo félig felesleges a desc-ben is megadni, de mivel az ELK-ban van "critical" szint is, így talán hasznos lehet
        f"Message: {message}\n"
        f"Event ingested: {event_ingested}\n"
        f"ELK Index name: {index_name}\n"
        f"ELK Alert ID: {alert_id}\n"
        f"ELK Alert URL: {alert_url}"
    )

    severity_map = {
    "low": "Low",
    "medium": "Medium",
    "high": "High"
    }

    #SOAR-ban nincs "Critical" severity, csak "High", így a lekért adat releváns részét módosítjuk.
    severity = "high" if severity == "critical" else severity
    severity_code = severity_map.get(severity.lower(), "Low")

    payload = {
        "name": f"ELK Incident: {rule_name} - {ip_address}",
        "description": description.strip(),
        "severity_code": severity_code,
        "discovered_date": int(datetime.now().timestamp() * 1000)
        #"incident_type_ids": [incident_type_id]
    }

    return payload

    #################################
      # Create artifacts from doc #
    #################################
def extract_artifacts_from_doc(doc):
    artifacts = []
    #Ha definiáljuk a tömb elemeit, hogy pontosan mikre lesz szükség, akkor majd ezt módosítani/élesíteni lehet.
    ##A kinyerendő mezők listája és hozzájuk tartozó metaadatok
    keys_to_check = [
        {"path": ["host", "ip"], "type": "IP Address", "description": "IP cím a SIEM alertből"}, #kiszedi az ipv4/6-ot is egyszer
        {"path": ["host", "hostname"], "type": "String", "description": "Hostname a SIEM alertből"}
        #{"path": ["network", "domain"], "type": "Domain", "description": "Domain név a logból"},
        #{"path": ["file", "name"], "type": "File Name", "description": "Fájlnév a SIEM alertből"},
        #{"path": ["host", "mac"], "type": "MAC Address", "description": "MAC cím a hostból"},
        # Itt bővíthető tovább más mezőkkel
    ]

    for key_info in keys_to_check:
        # Bejárja a megadott "útvonalat" a doc-on belül
        data = doc
        for k in key_info["path"]:
            data = data.get(k, None)
            if data is None:
                break

        # Ha adat van és az lista, akkor vegyük az elsőt
        if data:
            if isinstance(data, list):
                for value in data:
                    artifacts.append({
                        "type": key_info["type"],
                        "value": value,
                        "description": key_info["description"]
                    })
            else:
                artifacts.append({
                    "type": key_info["type"],
                    "value": data,
                    "description": key_info["description"]
                })
                
    return artifacts
    
    ######################################
      # SOAR Incident description trim#
    ######################################
def extract_alert_id_from_description(description):
    # Feltételezzük, hogy az alert ID az 'ELK Alert ID' kulcsszó után következik
    if "ELK Alert ID:" in description:
        # A split segítségével kinyerjük az alert id-t
        parts = description.split("ELK Alert ID:")
        if len(parts) > 1:
            return parts[1].split("\n")[0].strip()  # Az alert ID a következő sorban
    return None

    #######################################
      # Get existing Alert ID from SOAR #
    #######################################
async def get_soar_alert_ids(alert_id):
    query_payload = {
        "filters": [
            {
                "conditions": [
                    {
                        "field_name": "description",
                        "method": "contains",
                        "value": alert_id
                    }
                ]
            }
        ],
        "start": 0,
        "length": 100  # Például 100 találat lekérése
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://{soar_host}/rest/orgs/{org_id}/incidents/query_paged",
                headers=get_soar_headers(),
                data=json.dumps(query_payload),
                ssl=False
            ) as response:
                response.raise_for_status()
                result = await response.json()
                soar_alert_ids = []

                for incident in result.get("data", []):
                    desc = incident.get("description", "")
                    # Kinyerjük az alert_id-t a description-ból
                    soar_alert_id = extract_alert_id_from_description(desc)
                    if soar_alert_id:
                        soar_alert_ids.append(soar_alert_id)  # Csak az alert_id-kat tároljuk
                return soar_alert_ids
    except Exception as e:
        print(f"Hiba a SOAR lekérdezésénél: {e}")
        return []

    ####################################
      # Check if the incident exists #
    ####################################
async def check_if_alert_exists(alert_id):
    soar_alert_ids = await get_soar_alert_ids(alert_id)
    # Megnézzük, hogy bármelyik SOAR description tartalmazza-e az alert_id-t
    for soar_alert_id in soar_alert_ids:
        if alert_id in soar_alert_id:
            return True
    return False


    #############################
      # Send incident to SOAR #
    #############################
async def send_incident_to_soar(payload):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://{soar_host}/rest/orgs/{org_id}/incidents",
                headers=get_soar_headers(),
                data=json.dumps(payload),
                ssl=False
            ) as response:
                print(f"\n📤 SOAR válasz: {response.status}")
                response_data = await response.json()
                print(json.dumps(response_data, indent=2))
                return response
    except aiohttp.ClientError as e:
        print(f"Hiba a SOAR incident küldésénél: {e}")
        return None

    #####################
      # Debug BANNER #
    #####################
def log_debug_banner():
    if debug_mode:
        print("########################")
        print("########################")
        print("## DEBUG MODE is True ##")
        print("########################")
        print("########################")

    #####################
      # DEBUG Output #
    #####################
def handle_debug_output(payload, artifacts, alert_id, doc):
    if debug_mode:
        print("🚫 SOAR-ba küldés le van tiltva (send_to_soar = False).")
        print("🧾 Küldendő payload a SOAR-ba:")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        
        filename = "soar_payloads.txt"
        with open(filename, 'a', encoding='utf-8') as file:
            json.dump({
                "payload": payload,
                "artifacts": artifacts,
                "alert_id": alert_id
            }, file, indent=2, ensure_ascii=False)
            file.write("\n")
        print(f"✔️ A SOAR payload sikeresen elmentve a '{filename}' fájlba.")
        print(doc)

    ######################################
      # Send payload/incident to SOAR #
    ######################################
async def handle_payload_sending(alert_id, payload):
    soar_alert_ids = await get_soar_alert_ids(alert_id)
    
    # Ha már létezik a SOAR-ban az alert_id, ne küldjük el újra
    if alert_id in soar_alert_ids:
        print(f"⚠️ Incident már létezik SOAR-ban alert_id alapján: '{alert_id}'. Küldés kihagyva.")
    else:
        # Ha nem található a SOAR-ban, elküldjük az adatokat
        response = await send_incident_to_soar(payload)  # A send_incident_to_soar aszinkron
        if response and response.status == 200:
            if debug_mode:
                print("DEBUG: Válasz státuszkód:", response.status)
                print("DEBUG: Válasz tartalom:", response.text)
                print("Incidens SOAR-ban létrejött!")
        else:
            print("❌ Hiba történt az incidens létrehozásakor!")

    ###############################
      # Processes a single hit # 
    ###############################
async def process_hit(hit):
    doc = hit["_source"]
    alert_id = hit["_id"]
    payload = create_payload_from_doc(doc, hit)
    artifacts = extract_artifacts_from_doc(doc)

    if artifacts:
        payload["artifacts"] = artifacts

    if not send_to_soar:
        handle_debug_output(payload, artifacts, alert_id, doc)
    else:
        await handle_payload_sending(alert_id, payload)


    ########################################
      # Processes every hit individually #
    ########################################
async def process_hits(hits):
    tasks = []
    for hit in hits:
        tasks.append(process_hit(hit))  # Aszinkron hívás hozzáadása
    await asyncio.gather(*tasks)  # Minden aszinkron művelet végrehajtása párhuzamosan
        
# ----------------------------- #
# ----- Main végrehajtás ------ #
# ----------------------------- #
async def main():
    log_debug_banner()

    es = await connect_to_elasticsearch()
    query = build_query_with_rule_name_check()
    hits = await search_documents_from_es(es_host, es_index, query, size=100)

    await process_hits(hits)  # Aszinkron feldolgozás

if __name__ == "__main__":
    asyncio.run(main())  # Aszinkron main futtatása

import requests
import json
import urllib3
import pyodbc
import time
from datetime import datetime

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
MANAGER_IP = "192.168.16.202"
AGENT_ID = "001"
WAZUH_USER = "admin"
WAZUH_PASS = "Chkeir12@"

# SQL Server Configuration (ODBC Driver 18)
SQL_CONN_STR = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=SOC_AI;"
    "Trusted_Connection=yes;"
    "Encrypt=no;"
    "TrustServerCertificate=yes;"
)

def format_wazuh_date(date_str):
    """
    Fixes Error 22007: Converts '2025-12-19T16:38:35+00:00' 
    to a SQL-friendly Python datetime object.
    """
    try:
        # Strip 'T' and remove everything after '+' (timezone)
        clean_date = date_str.replace('T', ' ').split('+')[0]
        return datetime.strptime(clean_date, '%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.now()

def get_token():
    """Authenticates with Wazuh and returns a JWT token."""
    auth_url = f"https://{MANAGER_IP}:55000/security/user/authenticate?raw=true"
    try:
        response = requests.get(auth_url, auth=(WAZUH_USER, WAZUH_PASS), verify=False)
        if response.status_code == 200:
            return response.text.strip()
        print(f"❌ Login Failed: {response.status_code}")
        return None
    except Exception as e:
        print(f"❌ Connection Error during login: {e}")
        return None

def run_ingestion():
    """Fetches latest FIM events and stores them in SOC_AI database."""
    token = get_token()
    if not token: return

    url = f"https://{MANAGER_IP}:55000/syscheck/{AGENT_ID}"
    headers = {'Authorization': f'Bearer {token}'}
    params = {'limit': 20, 'select': 'file,mtime,size,uname,md5', 'sort': '-mtime'}

    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code}")
            return

        items = response.json().get('data', {}).get('affected_items', [])
        
        # Connect to Database
        conn = pyodbc.connect(SQL_CONN_STR)
        cursor = conn.cursor()
        new_count = 0

        for item in items:
            file_path = item.get('file')
            sql_time = format_wazuh_date(item.get('mtime'))

            # 1. DEDUPLICATION CHECK
            cursor.execute("""
                SELECT COUNT(*) FROM wazuh_security_details 
                WHERE file_path = ? AND detected_at = ?
            """, (file_path, sql_time))
            
            if cursor.fetchone()[0] > 0:
                continue # Skip existing record

            # 2. INSERT INTO logs_raw
            cursor.execute(
                "INSERT INTO logs_raw (source, raw_log, log_time) OUTPUT INSERTED.id VALUES (?, ?, ?)",
                ('Wazuh-FIM', json.dumps(item), sql_time)
            )
            raw_id = cursor.fetchone()[0]

            # 3. INSERT INTO logs_parsed
            cursor.execute(
                "INSERT INTO logs_parsed (raw_log_id, alert_name, priority) OUTPUT INSERTED.id VALUES (?, ?, ?)",
                (raw_id, 'FIM Event Detected', 3)
            )
            parsed_id = cursor.fetchone()[0]

            # 4. INSERT INTO wazuh_security_details (Unified Table)
            cursor.execute(
                """
                INSERT INTO wazuh_security_details 
                (parsed_log_id, agent_id, event_category, [description], file_path, file_hash_md5, [system_user], detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (parsed_id, AGENT_ID, 'FIM', 'File Integrity Change', file_path, item.get('md5'), item.get('uname'), sql_time)
            )
            new_count += 1
        
        conn.commit()
        cursor.close()
        conn.close()

        if new_count > 0:
            print(f"✅ [{datetime.now().strftime('%H:%M:%S')}] Added {new_count} new unique events.")
        else:
            print(f"ℹ️ [{datetime.now().strftime('%H:%M:%S')}] No new activity.")

    except Exception as e:
        print(f"❌ Processing Error: {e}")

if __name__ == "__main__":
    print("🛡️ SOC_AI Ingestion Engine Started (De-duplication Active)")
    print(f"Monitoring Agent {AGENT_ID} every 5 minutes...")
    
    while True:
        run_ingestion()
        time.sleep(30) # Sleep for 5 minutes
import pyodbc
import requests
import time

# ================= CONFIG =================
API_KEY = "2db12f3c66ee3480782196633ad477a61c015246c639a2d73855ff857a62db22"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

SQL_CONN_STR = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=SOC_AI;"
    "Trusted_Connection=yes;"
    "Encrypt=no;"
)

POLL_INTERVAL = 30  # run every 5 minutes
# ==========================================

def get_db_connection():
    return pyodbc.connect(SQL_CONN_STR)

def fetch_new_logs(cursor):
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'last_enrichment')
        CREATE TABLE last_enrichment (
            id INT PRIMARY KEY,
            last_parsed_id INT
        )
    """)

    cursor.execute("SELECT last_parsed_id FROM last_enrichment WHERE id = 1")
    row = cursor.fetchone()
    last_id = row[0] if row else 0

    cursor.execute("""
        SELECT id, src_ip, dst_ip
        FROM logs_parsed
        WHERE id > ?
        ORDER BY id ASC
    """, last_id)

    logs = cursor.fetchall()
    return logs, last_id

def save_last_id(cursor, last_id):
    cursor.execute("""
        MERGE last_enrichment AS target
        USING (SELECT 1 AS id, ? AS last_parsed_id) AS src
        ON target.id = src.id
        WHEN MATCHED THEN UPDATE SET last_parsed_id = src.last_parsed_id
        WHEN NOT MATCHED THEN INSERT (id, last_parsed_id) VALUES (src.id, src.last_parsed_id);
    """, last_id)

def query_virustotal(ip):
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(VT_URL.format(ip), headers=headers)
        if response.status_code == 200:
            data = response.json()
            # Extract basic info
            reputation = data.get("data", {}).get("attributes", {}).get("reputation", "unknown")
            last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            score = last_analysis_stats.get("malicious", 0)
            return reputation, score
        else:
            return "unknown", 0
    except Exception as e:
        print(f"[VT ERROR] {ip} -> {e}")
        return "error", 0

def enrich_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    logs, last_id = fetch_new_logs(cursor)
    if not logs:
        conn.close()
        return
    
    for log in logs:
        parsed_id = log.id
        for ip, direction in [(log.src_ip, "src"), (log.dst_ip, "dst")]:
            # Skip private IPs
            #if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
             #   continue
            
            reputation, score = query_virustotal(ip)
            
            cursor.execute("""
                INSERT INTO enrichment_results (
                    parsed_log_id,
                    indicator_type,
                    indicator_value,
                    source,
                    reputation,
                    score,
                    enriched_at
                ) VALUES (?, ?, ?, ?, ?, ?, GETDATE())
            """, parsed_id, "ip", ip, "VirusTotal", reputation, score)

        last_id = parsed_id

    save_last_id(cursor, last_id)
    conn.commit()
    conn.close()
    
    print(f"[+] Enriched {len(logs)} logs")

def main():
    print("[+] VirusTotal enrichment service started")
    while True:
        try:
            enrich_logs()
        except Exception as e:
            print(f"[ERROR] {e}")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

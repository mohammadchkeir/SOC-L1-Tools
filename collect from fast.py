import time
import re
import pyodbc
import os

# ===================== CONFIG =====================
FAST_LOG_PATH = r"C:\Program Files\Suricata\log\fast.log"
POLL_INTERVAL = 30  # seconds

SQL_CONN_STR = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=SOC_AI;"
    "Trusted_Connection=yes;"
    "Encrypt=no;"
)
# =================================================

# Regex to parse Suricata fast.log alerts
FAST_LOG_REGEX = re.compile(
    r'(?P<timestamp>\d+/\d+/\d+-\d+:\d+:\d+\.\d+)\s+'
    r'\[\*\*\]\s+\[\d+:\d+:\d+\]\s+'
    r'(?P<alert>.+?)\s+\[\*\*\]\s+'
    r'\[Classification:\s(?P<classification>.+?)\]\s+'
    r'\[Priority:\s(?P<priority>\d+)\]\s+'
    r'\{(?P<protocol>\w+)\}\s+'
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+'
    r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)'
)

# ===================== DB CONNECTION =====================
def get_db_connection():
    return pyodbc.connect(SQL_CONN_STR)

# ===================== OFFSET TRACKING =====================
def get_last_offset(cursor):
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'file_offset')
        CREATE TABLE file_offset (
            id INT PRIMARY KEY,
            offset BIGINT
        )
    """)
    cursor.execute("SELECT offset FROM file_offset WHERE id = 1")
    row = cursor.fetchone()
    return row[0] if row else 0

def save_offset(cursor, offset):
    cursor.execute("""
        MERGE file_offset AS target
        USING (SELECT 1 AS id, ? AS offset) AS src
        ON target.id = src.id
        WHEN MATCHED THEN UPDATE SET offset = src.offset
        WHEN NOT MATCHED THEN INSERT (id, offset) VALUES (src.id, src.offset);
    """, offset)

# ===================== PROCESS LOGS =====================
def process_logs():
    conn = get_db_connection()
    cursor = conn.cursor()

    last_offset = get_last_offset(cursor)

    if not os.path.exists(FAST_LOG_PATH):
        print("[!] fast.log not found")
        return

    with open(FAST_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_offset)

        for line in f:
            raw_line = line.strip()
            if not raw_line:
                continue

            # 1️⃣ Insert RAW log and get ID
            cursor.execute("""
                INSERT INTO logs_raw (source, raw_log, log_time)
                OUTPUT INSERTED.id
                VALUES (?, ?, GETDATE())
            """, "suricata", raw_line)

            raw_log_id = cursor.fetchone()[0]

            # 2️⃣ Parse structured alert
            match = FAST_LOG_REGEX.search(raw_line)
            if match:
                data = match.groupdict()
                cursor.execute("""
                    INSERT INTO logs_parsed (
                        raw_log_id,
                        alert_name,
                        classification,
                        priority,
                        protocol,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                raw_log_id,
                data["alert"],
                data["classification"],
                int(data["priority"]),
                data["protocol"],
                data["src_ip"],
                data["dst_ip"],
                int(data["src_port"]),
                int(data["dst_port"])
                )

        # 3️⃣ Save the file offset
        save_offset(cursor, f.tell())

    conn.commit()
    conn.close()

# ===================== MAIN LOOP =====================
def main():
    print("[+] Suricata fast.log collector started")
    while True:
        try:
            process_logs()
        except Exception as e:
            print(f"[ERROR] {e}")
        time.sleep(POLL_INTERVAL)
        print("1")

if __name__ == "__main__":
    main()

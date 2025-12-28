import os
import time
import json
import re
import pyodbc
from dotenv import load_dotenv
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_groq import ChatGroq
from langchain.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

# --- 1. CONFIGURATION & LOG LOADING ---
load_dotenv(override=True)
INDEX_FOLDER = "faiss_index"
GROQ_MODEL_NAME = "llama-3.3-70b-versatile"
INTERVAL = 30  # Wait time between database checks
SQL_CONN_STR = os.getenv("SQL_CONN_STR")

# --- 2. INITIALIZE GLOBAL COMPONENTS ---
# These are outside the loop to keep the script fast
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
vectorstore = FAISS.load_local(INDEX_FOLDER, embeddings, allow_dangerous_deserialization=True)
llm = ChatGroq(
    temperature=0, 
    model_name=GROQ_MODEL_NAME, 
    groq_api_key=os.getenv("GROQ_API_KEY")
)

# --- 3. HELPER: JSON EXTRACTOR ---
def extract_json(text):
    """
    Finds and extracts JSON from a string even if the LLM 
    adds markdown backticks or conversational 'thinking' text.
    """
    try:
        # 1. Try to find content between ```json { ... } ```
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if match:
            return match.group(1)
        # 2. Try to find the first '{' and last '}'
        match = re.search(r'(\{.*\})', text, re.DOTALL)
        if match:
            return match.group(1)
        return text.strip()
    except Exception:
        return text.strip()

# --- 4. PROMPT TEMPLATES ---
REWRITER_TEMPLATE = """
### ROLE
You are a Cyber Threat Intelligence (CTI) Parser. Your goal is to strip noise from raw security logs to create high-fidelity search queries.

### TASK
1. Remove timestamps, hex codes, and redundant transaction IDs.
2. Identify the core 'Attack Signature' (e.g., 'LSASS Memory Dump' instead of 'MSRPC request').
3. Identify the target service or binary involved (e.g., 'rundll32.exe', 'SMB', 'PowerShell').

INPUT: {raw_alert}

### OUTPUT RULES
- Return ONLY valid JSON.
- The "enhanced_query" must be optimized for semantic vector search against MITRE ATT&CK documentation.

OUTPUT (JSON only):
{{
  "enhanced_query": "specific technical attack keywords", 
  "iocs": {{
    "source_ip": "...", 
    "dest_ip": "...",
    "protocol": "..."
  }}
}}
"""

ANALYST_TEMPLATE = """
### ROLE
You are 'CyberRAG', a Senior Tier-3 SOC Analyst and MITRE ATT&CK Specialist.

### CONTEXT (Atomic Red Team Procedures):
{context}

### TARGET LOG:
{original_alert}

### ANALYSIS GUIDELINES
1. **Behavioral Mapping**: Compare the log's process execution or network traffic against the 'executor' commands in the Context.
2. **Confidence Rubric**:
   - 0.9-1.0: Exact command match or process-behavior match.
   - 0.6-0.8: Log suggests the technique but specific parameters differ.
   - 0.1-0.5: Vague similarity only.
3. **Strategic Mitigation**: Don't give generic advice. Provide steps based on the retrieved Atomic Red Team 'cleanup' or 'prerequisite' sections.

### OUTPUT STRUCTURE (Strict JSON Only)
{{
  "mitre": {{
    "technique_id": "Txxxx",
    "technique_name": "Official MITRE Name",
    "tactic": "Primary Tactic",
    "confidence": 0.0
  }},
  "analysis": {{
    "summary": "Detailed technical explanation of how the log matches the retrieved procedure.",
    "risk_level": "Low|Medium|High",
    "mitigation_steps": [
       "Immediate containment action",
       "Specific configuration hardening based on context",
       "Hunting query or indicator to watch for"
    ],
    "analyst_notes": "Cite specific technical evidence from the provided context."
  }}
}}
"""

# Initialize Chains
rewriter_chain = PromptTemplate(template=REWRITER_TEMPLATE, input_variables=["raw_alert"]) | llm | StrOutputParser()
analyst_chain = PromptTemplate(template=ANALYST_TEMPLATE, input_variables=["context", "original_alert"]) | llm | StrOutputParser()

# --- 5. DATABASE FUNCTIONS ---
def connect_db():
    if not SQL_CONN_STR:
        raise ValueError("SQL_CONN_STR is missing from .env file!")
    return pyodbc.connect(SQL_CONN_STR)

def get_last_processed_id(cursor):
    """Checks the ai_analysis table to see what the highest processed log ID is."""
    cursor.execute("SELECT ISNULL(MAX(parsed_log_id), 0) FROM ai_analysis")
    return cursor.fetchone()[0]

# --- 6. CORE LOGIC ---
def process_new_logs():
    conn = connect_db()
    cursor = conn.cursor()
    
    last_id = get_last_processed_id(cursor)
    
    # Select only logs we haven't processed yet
    cursor.execute("""
        SELECT id, alert_name, classification, priority, protocol, src_ip, dst_ip 
        FROM logs_parsed WHERE id > ? ORDER BY id ASC
    """, last_id)
    
    rows = cursor.fetchall()
    if not rows:
        conn.close()
        return

    print(f"[*] Found {len(rows)} new logs. Processing...")

    for row in rows:
        log_id = row[0]
        alert_name = row[1]
        raw_text = f"Alert: {alert_name}, IPs: {row[5]} -> {row[6]}"
        
        try:
            # Step 1: Query Rewriting
            raw_rw = rewriter_chain.invoke({"raw_alert": raw_text})
            rw_data = json.loads(extract_json(raw_rw))
            query = rw_data.get("enhanced_query", alert_name)

            # Step 2: RAG Vector Search
            docs = vectorstore.similarity_search(query, k=3)
            context_str = "\n".join([d.page_content for d in docs])

            # Step 3: Analysis
            raw_analysis = analyst_chain.invoke({
                "context": context_str, 
                "original_alert": raw_text
            })
            ai_data = json.loads(extract_json(raw_analysis))

            # Step 4: Save to Database
            m = ai_data["mitre"]
            a = ai_data["analysis"]
            mitigation = "\n".join(a["mitigation_steps"])

            # Table 1: mitre_mapping
            cursor.execute("""
                INSERT INTO mitre_mapping (parsed_log_id, technique_id, technique_name, tactic, confidence, mapped_at)
                VALUES (?, ?, ?, ?, ?, GETDATE())
            """, log_id, m["technique_id"], m["technique_name"], m["tactic"], m["confidence"])

            # Table 2: ai_analysis
            cursor.execute("""
                INSERT INTO ai_analysis (parsed_log_id, ai_model, summary, risk_level, mitigation_steps, created_at)
                VALUES (?, ?, ?, ?, ?, GETDATE())
            """, log_id, GROQ_MODEL_NAME, a["summary"], a["risk_level"], mitigation)

            conn.commit()
            print(f"[+] Log {log_id} analyzed and saved.")

        except Exception as e:
            print(f"[!] Critical Error on Log {log_id}: {e}")
            conn.rollback()

    conn.close()

# --- 7. MAIN LOOP ---
if __name__ == "__main__":
    print(f"--- CyberRAG SOC Engine Running ---")
    while True:
        try:
            process_new_logs()
        except Exception as e:
            print(f"[ERROR] Database connection failed: {e}")
        time.sleep(INTERVAL)
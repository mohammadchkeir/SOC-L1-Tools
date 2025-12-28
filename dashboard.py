from flask import Flask, render_template_string, request, jsonify
import pyodbc
import subprocess
from datetime import datetime

app = Flask(__name__)

# ================= CONFIGURATION =================
SQL_CONN_STR = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=SOC_AI;"
    "Trusted_Connection=yes;"
    "Encrypt=no;"
)

# ================= MODERN UI WRAPPER =================
def get_html_wrapper(title, content):
    return f"""
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} | SOC Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            :root {{ --neon-blue: #00d2ff; --neon-green: #00ff9d; --neon-red: #ff3e3e; --bg-main: #0b0f19; --card-bg: #161b22; }}
            body {{ background-color: var(--bg-main); color: #e6edf3; font-family: 'Inter', sans-serif; }}
            .navbar {{ background: rgba(22, 27, 34, 0.8); backdrop-filter: blur(12px); border-bottom: 1px solid #30363d; }}
            .card {{ background: var(--card-bg); border: 1px solid #30363d; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.3); }}
            .table {{ color: #c9d1d9; border-color: #30363d; cursor: pointer; }}
            .table-hover tbody tr:hover {{ background-color: #1c2128 !important; border-left: 4px solid var(--neon-blue); transition: 0.2s; }}
            .badge-high {{ background: var(--neon-red); color: white; }}
            .badge-med {{ background: #f2994a; color: white; }}
            .badge-low {{ background: var(--neon-green); color: black; }}
            .modal-content {{ background: #0d1117; border: 1px solid var(--neon-blue); box-shadow: 0 0 20px rgba(0,210,255,0.2); }}
            .btn-defense {{ background: linear-gradient(45deg, #f85032, #e73827); border: none; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }}
            pre {{ background: #010409; padding: 15px; border-radius: 8px; color: var(--neon-green); border: 1px solid #30363d; }}
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg sticky-top mb-4">
          <div class="container">
            <a class="navbar-brand fw-bold" href="/"><i class="fas fa-shield-halved me-2 text-info"></i> SOC <span class="text-info">CENTRAL</span></a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
              <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
              <ul class="navbar-nav ms-auto">
                <li class="nav-item"><a class="nav-link" href="/"><i class="fas fa-microchip me-1"></i> AI Intel</a></li>
                <li class="nav-item"><a class="nav-link" href="/logs"><i class="fas fa-database me-1"></i> Logs</a></li>
                <li class="nav-item"><a class="nav-link" href="/mitre"><i class="fas fa-crosshairs me-1"></i> MITRE</a></li>
                <li class="nav-item"><a class="nav-link" href="/virustotal"><i class="fas fa-vial me-1"></i> Threat Intel</a></li>
                <li class="nav-item ms-lg-3"><a class="nav-link btn btn-outline-danger btn-sm text-white px-3" href="/defense">Defense Hub</a></li>
              </ul>
            </div>
          </div>
        </nav>
        <div class="container">{content}</div>

        <div class="modal fade" id="detailModal" tabindex="-1">
          <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
              <div class="modal-header border-0">
                <h5 class="modal-title fw-bold" id="modalTitle">System Intelligence Detail</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
              </div>
              <div class="modal-body py-4" id="modalBody"></div>
            </div>
          </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            function openDetails(title, data) {{
                document.getElementById('modalTitle').innerText = title;
                let html = '<div class="row g-4">';
                for (const [key, value] of Object.entries(data)) {{
                    html += `
                        <div class="col-12">
                            <label class="text-muted small text-uppercase fw-bold mb-1">${{key.replace('_', ' ')}}</label>
                            <div class="p-3 rounded shadow-sm" style="background: #161b22; border: 1px solid #30363d;">
                                ${{key.toLowerCase().includes('steps') || key.toLowerCase().includes('summary') ? `<pre class="mb-0">${{value}}</pre>` : `<span class="h6">${{value}}</span>`}}
                            </div>
                        </div>`;
                }}
                html += '</div>';
                document.getElementById('modalBody').innerHTML = html;
                new bootstrap.Modal(document.getElementById('detailModal')).show();
            }}
        </script>
    </body>
    </html>
    """

# ================= ROUTES =================

@app.route('/')
def index():
    try:
        conn = pyodbc.connect(SQL_CONN_STR)
        cursor = conn.cursor()
        cursor.execute("SELECT parsed_log_id, ai_model, summary, risk_level, mitigation_steps, created_at FROM ai_analysis ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        
        content = """
        <div class="d-flex justify-content-between align-items-end mb-4">
            <div><h2 class="fw-bold m-0 text-white">AI Security Intelligence</h2><p class="text-muted m-0">Real-time MITRE ATT&CK Behavioral Analysis</p></div>
            <span class="badge bg-primary px-3 py-2">LIVE MONITORING</span>
        </div>
        <div class="card overflow-hidden">
            <div class="card-body p-0">
                <table class="table table-hover mb-0">
                    <thead class="bg-dark text-muted">
                        <tr><th class="ps-4">LOG ID</th><th>RISK</th><th>SUMMARY</th><th>TIMESTAMP</th></tr>
                    </thead>
                    <tbody>
                        {% for row in rows %}
                        <tr onclick='openDetails("AI Forensic Report", {
                            "Log_ID": "{{row[0]}}",
                            "Risk_Level": "{{row[3]}}",
                            "Model_Used": "{{row[1]}}",
                            "AI_Analysis_Summary": "{{row[2] | replace("\n", " ") | replace("'", "")}}",
                            "Mitigation_Steps": "{{row[4] | replace("\n", " ") | replace("'", "")}}"
                        })'>
                            <td class="ps-4 fw-bold">#{{ row[0] }}</td>
                            <td><span class="badge {% if row[3]=='High' %}badge-high{% elif row[3]=='Medium' %}badge-med{% else %}badge-low{% endif %}">{{ row[3] }}</span></td>
                            <td><div class="text-truncate" style="max-width: 500px;">{{ row[2] }}</div></td>
                            <td>{{ row[5].strftime('%H:%M:%S') if row[5] else 'N/A' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        """
        return render_template_string(get_html_wrapper("AI Analysis", content), rows=rows)
    except Exception as e: return f"Database Error: {str(e)}"

@app.route('/logs')
def logs():
    try:
        conn = pyodbc.connect(SQL_CONN_STR)
        cursor = conn.cursor()
        cursor.execute("SELECT id, alert_name, classification, priority, protocol, src_ip, dst_ip FROM logs_parsed ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        content = """
        <h2 class="fw-bold text-white mb-4">Parsed Event Logs</h2>
        <div class="card">
            <div class="card-body p-0">
                <table class="table table-hover mb-0">
                    <thead class="bg-dark text-muted">
                        <tr><th class="ps-4">ID</th><th>ALERT NAME</th><th>SOURCE IP</th><th>DESTINATION</th></tr>
                    </thead>
                    <tbody>
                        {% for row in rows %}
                        <tr onclick='openDetails("Log Metadata", {
                            "ID": "{{row[0]}}",
                            "Alert": "{{row[1]}}",
                            "Classification": "{{row[2]}}",
                            "Priority": "{{row[3]}}",
                            "Protocol": "{{row[4]}}",
                            "Source": "{{row[5]}}",
                            "Destination": "{{row[6]}}"
                        })'>
                            <td class="ps-4">#{{ row[0] }}</td>
                            <td>{{ row[1] }}</td>
                            <td class="text-info">{{ row[5] }}</td>
                            <td>{{ row[6] }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        """
        return render_template_string(get_html_wrapper("Event Logs", content), rows=rows)
    except Exception as e: return f"Error: {str(e)}"

@app.route('/mitre')
def mitre():
    try:
        conn = pyodbc.connect(SQL_CONN_STR)
        cursor = conn.cursor()
        cursor.execute("SELECT parsed_log_id, technique_id, technique_name, tactic, confidence, mapped_at FROM mitre_mapping ORDER BY mapped_at DESC")
        rows = cursor.fetchall()
        conn.close()
        content = """
        <h2 class="fw-bold text-white mb-4">MITRE ATT&CK Mapping</h2>
        <div class="card">
            <div class="card-body p-0">
                <table class="table table-hover mb-0 text-center align-middle">
                    <thead class="bg-dark text-muted">
                        <tr><th class="ps-4">ID</th><th>TECHNIQUE</th><th>NAME</th><th>TACTIC</th><th>CONFIDENCE</th></tr>
                    </thead>
                    <tbody>
                        {% for row in rows %}
                        <tr onclick='openDetails("MITRE Framework Detail", {{ {
                            "Log_ID": row[0],
                            "Technique_ID": row[1],
                            "Technique_Name": row[2],
                            "Tactic": row[3],
                            "Confidence_Score": (row[4]|float * 100)|round(1)|string + "%"
                        } | tojson }})'>
                            <td class="ps-4">#{{ row[0] }}</td>
                            <td><span class="badge bg-primary px-2">{{ row[1] }}</span></td>
                            <td class="text-start">{{ row[2] }}</td>
                            <td><small class="fw-bold text-info">{{ row[3] }}</small></td>
                            <td class="fw-bold text-success">{{ (row[4]|float * 100)|round(0) }}%</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        """
        return render_template_string(get_html_wrapper("MITRE Mapping", content), rows=rows)
    except Exception as e: return f"Error: {str(e)}"

@app.route('/virustotal')
def virustotal():
    try:
        conn = pyodbc.connect(SQL_CONN_STR)
        cursor = conn.cursor()
        cursor.execute("SELECT parsed_log_id, indicator_type, indicator_value, source, reputation, score, enriched_at FROM enrichment_results ORDER BY enriched_at DESC")
        rows = cursor.fetchall()
        conn.close()
        content = """
        <h2 class="fw-bold text-white mb-4">Threat Intel Enrichment</h2>
        <div class="card">
            <div class="card-body p-0">
                <table class="table table-hover mb-0">
                    <thead class="bg-dark text-muted">
                        <tr><th class="ps-4">ID</th><th>TYPE</th><th>INDICATOR</th><th>REPUTATION</th></tr>
                    </thead>
                    <tbody>
                        {% for row in rows %}
                        <tr class="{% if row[4]|int < 0 %}text-danger{% endif %}">
                            <td class="ps-4">#{{ row[0] }}</td>
                            <td><small class="badge bg-secondary">{{ row[1] }}</small></td>
                            <td><code>{{ row[2] }}</code></td>
                            <td class="fw-bold">{{ row[4] }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        """
        return render_template_string(get_html_wrapper("VirusTotal", content), rows=rows)
    except Exception as e: return f"Error: {str(e)}"

@app.route('/defense', methods=['GET', 'POST'])
def defense():
    status_log = []
    if request.method == 'POST':
        scripts = ["query_rag.py", "collect from fast.py", "parsed suricata logs.py", "parsed wazuh log.py", "map to mitre.py"]
        for script in scripts:
            try:
                subprocess.Popen(["python", script])
                status_log.append(f"✅ SYSTEM ACTIVATED: {script}")
            except Exception as e:
                status_log.append(f"❌ ERROR: {script} - {str(e)}")

    content = """
    <div class="text-center py-5">
        <i class="fas fa-shield-virus fa-5x text-danger mb-4"></i>
        <h1 class="fw-bold">Defense Control Center</h1>
        <p class="text-muted mx-auto" style="max-width: 600px;">Deploy all security engines simultaneously. This will trigger the AI analyst, log collection, and SIEM parsers.</p>
        <form method="post" class="mt-4">
            <button type="submit" class="btn btn-defense btn-lg px-5 py-3 shadow-lg"><i class="fas fa-power-off me-2"></i> INITIATE GLOBAL DEFENSE</button>
        </form>
        {% if status_log %}
        <div class="mt-5 text-start bg-black p-4 rounded border border-danger mx-auto" style="max-width: 700px; font-family: monospace;">
            <h6 class="text-danger fw-bold"><i class="fas fa-terminal me-2"></i> KERNEL COMMAND LOG:</h6>
            {% for log in status_log %}<div class="text-light small mb-1">{{ log }}</div>{% endfor %}
        </div>
        {% endif %}
    </div>
    """
    return render_template_string(get_html_wrapper("Defense Hub", content), status_log=status_log)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
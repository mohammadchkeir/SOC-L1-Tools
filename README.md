SOC Level-1 Automation: AI-Driven MITRE ATT&CK Mapping for Real-Time Threat Analysis,

The biggest bottleneck in a modern SOC is not a lack of data,
 but the time required to transform a raw alert into a technical and actionable response.
I’m excited to share our latest project: a Dual-LLM RAG Engine designed to operate as an AI-assisted Tier-1 SOC Analyst, automating alert enrichment and MITRE ATT&CK mapping with operational precision.

System Architecture:
The platform is built as a real-time, high-performance security pipeline:
Telemetry Ingestion
 Network and endpoint data collected from Suricata (NIDS) and Wazuh (HIDS), enriched with Sysmon for deep endpoint visibility.
Centralized Intelligence Layer
 All security events are normalized and stored in Microsoft SQL Server 2025 to enable fast retrieval and historical correlation.
Threat Enrichment
 Automated integration with VirusTotal to analyze and score suspicious IPs and IOCs in real time.

Dual-LLM RAG Engine:
Layer 1 – Semantic Optimizer
 Uses Llama 3.3 70B to clean noisy logs, extract high-fidelity IOCs, and infer attacker intent.
Layer 2 – Contextual Analyst
 Uses FAISS vector search with HuggingFace embeddings to retrieve precise attack context from the Atomic Red Team dataset (1,700+ validated attack tests).

Grounded SOC Synthesis:
 Alerts are mapped directly to MITRE ATT&CK techniques and tactics, with validated mitigation commands derived from real attack data, eliminating hallucinations.
Key Capabilities
Live Monitoring
 A custom Flask-based dashboard provides real-time visibility into security events.

Actionable Intelligence:
 Each alert includes a concise technical summary, MITRE mapping, and mitigation guidance.
Noise Reduction by Design
 The semantic rewriting layer filters false positives and focuses analysis on high-confidence threats.
One-Click Operation
 A single action triggers full analysis: alert enrichment, threat validation, and MITRE ATT&CK mapping, without manual intervention.

Technology Stack
Languages: Python (Flask)
AI / LLM: Llama 3.3 70B, LangChain, FAISS
SIEM & Monitoring: Wazuh, Suricata, Sysmon
Database: Microsoft SQL Server 2025
Threat Intelligence: MITRE ATT&CK(Atomic Red Team)
This project shifts AI in cybersecurity from conversational analysis to operational automation, enforcing validation against real-world adversary techniques and enabling faster, more reliable SOC decision-making.

Notes:
This project is designed to be fully scalable, allowing seamless integration with any SIEM platform, threat-intelligence API, or search engine through a modular architecture.
It supports a wide spectrum of attack techniques across all MITRE ATT&CK tactics, making it adaptable to diverse enterprise and SOC environments.
It is designed to easily integrate with any Large Language Model LLM (OpenAI, Ollama, etc.)

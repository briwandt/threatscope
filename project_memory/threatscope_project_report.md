# ThreatScope Project Overview & Status Report

We have located all components of the **ThreatScope** project, studied the codebase, reviewed git history, and reorganized the repository to establish a clean foundation for development.

---

## 🏗️ Core Technology Stack
ThreatScope is designed as an interactive threat-hunting cockpit with the following tech stack:
* **Frontend/Dashboard**: [Streamlit](https://streamlit.io/) (configured for a dark-themed SOC-style visual cockpit).
* **AI/LLM Engine**: [Groq API](https://groq.com/) using the `llama-3.3-70b-versatile` model for CTI threat brief extraction and final hunt report summaries.
* **Graph Visualization**: [NetworkX](https://networkx.org/) and [PyVis](https://pyvis.readthedocs.io/) for generating interactive entity correlation networks.
* **SIEM Connector**: [Elasticsearch](https://www.elastic.co/) (run locally via Docker Compose) to index and query simulated security event logs.
* **Automation & Keep-Awake**: [Playwright](https://playwright.dev/) running in a scheduled GitHub Actions workflow to prevent Streamlit Cloud from sleeping.

---

## 📁 Repository Directory Structure

The project codebase is organized as follows:

```text
threatscope/
├── .github/
│   └── workflows/
│       └── keep_awake.yml     # Scheduled GHA workflow (runs every 30m with keepalive protection)
├── .streamlit/
│   └── secrets.toml           # Local Streamlit secrets (holds GROQ_API_KEY)
├── detections/
│   ├── identity.yml           # YAML definitions for identity-focused threat rules
│   └── identity_detector.py   # Rule matching engine (formerly detectionsidentity.json)
├── engine/
│   └── detections.py          # Core threat detection engine (Python implementation)
├── lib/
│   ├── bindings/              # Static dependency bindings
│   ├── tom-select/            # UI components
│   └── vis-9.1.2/             # Local JS visualizer files for network graphs
├── reports/
│   └── sample_hunt_report.md  # Populated sample threat hunt report template
├── screenshots/               # High-fidelity dashboard screenshot assets for README.md
│   ├── detection_engine.png
│   ├── timeline.png
│   ├── entity_graph.png
│   ├── hunt_report.png
│   └── ai_analysis.png
├── app.py                     # Main Streamlit dashboard application
├── docker-compose.yml         # Starts local Elasticsearch and Kibana containers
├── keepalive.txt              # Timestamp log updated automatically by GHA to prevent cron expiry
├── keep_awake.py              # Playwright browser script to auto-wake sleeping app
├── load_sample_logs.py        # Indices simulated log events into local Elasticsearch
├── requirements.txt           # Python library dependencies
└── README.md                  # Project documentation and landing page
```

---

## ⚙️ Core Modules & File Analysis

### 1. Main Dashboard ([app.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/app.py))
The central driver of the cockpit layout. Refactored into a premium, four-tab interface:
* **📥 Ingest & Intel**: Allows selection of simulated SIEM threat scenarios, connecting to local Elasticsearch, uploading CTI files (.txt, .pdf), or pasting a threat report URL. It features live LLM extraction of threat briefs (exec summaries, behaviors, and IOCs) via Groq, with an optimized offline fallback logic.
* **📊 Detections & Timeline**: Displays custom HTML/CSS metric cards for *Risk Score*, *Overall Severity*, and *Correlated Detections*, followed by the detection rule outputs and a chronological EDR/SIEM timeline grid.
* **🕸️ Entity Correlation Graph**: Extracts identity relationships (IPs, users, hosts, roles, protocols, apps) from incoming logs, creates a network topology using NetworkX, renders it to an HTML component using PyVis, and displays it.
* **📝 AI Analysis & Report**: Formulates a detailed markdown report for the threat hunter to download and lets the analyst trigger a deep, contextual AI review of the threat scenario.

### 2. Detection Engine ([engine/detections.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/engine/detections.py))
Implements **24 distinct python-based detection rules** running on parsed log dicts or raw telemetry inputs. Mapped techniques include:
* `T1078` - Valid Accounts (Suspicious foreign VPN logins, contractor risks)
* `T1621` - MFA Request Generation (MFA fatigue/push approvals)
* `T1059.001` - PowerShell Execution
* `T1047` - Windows Management Instrumentation (WMI lateral movement)
* `T1098` - Account Manipulation (Azure GlobalAdmin escalations, Kubernetes RoleBindings)
* `T1550` - Use Alternate Authentication Material (OAuth persistence)
* `T1430` - Location Tracking (SS7/Diameter/GTP signaling anomalies)
* `T1562.001` - Disable/Modify Audit Trails (CloudTrail stopping)
* `T1490` - Inhibit System Recovery (Volume shadow copy deletion)
* `T1562.002` - Clear Event Logs (wevtutil security log wipes)
* `T1195.002` - Supply Chain Compromise (Malicious CI/CD npm packages)
* `T1560` - Data Archiving (7z encrypted exfiltration staging)
* `T1496` - Resource Hijacking (Kubernetes XMRig cryptomining)
* `T1567.002` - Exfiltration Over Cloud Storage (Uploads to Mega)

### 3. Simulation & Lab Infrastructure
* **[docker-compose.yml](file:///c:/Users/user/Documents/AntiGravity/threatscope/docker-compose.yml)**: Configures Elasticsearch (`single-node`, security disabled for demo simplicity) and Kibana on ports `9200` and `5601`.
* **[load_sample_logs.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/load_sample_logs.py)**: Indexes realistic JSON-formatted threat trails into Elasticsearch, covering Kerberoasting, Golden Tickets, Mimikatz DCSync, Kubernetes abuse, API scraping, and SIM swap sequences.

### 4. Keep-Awake Automation & Inactivity Protection
* **[keep_awake.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/keep_awake.py)**: Spins up a Playwright-managed headless Chromium browser, navigates to the app URL, waits for elements to render, and if it detects Streamlit's native "sleeping app" screen, automatically clicks the **"Yes, get this app back up!"** button.
* **[.github/workflows/keep_awake.yml](file:///c:/Users/user/Documents/AntiGravity/threatscope/.github/workflows/keep_awake.yml)**: To keep the public Streamlit Cloud deployment active and responsive to visitors, this cron job executes every 30 minutes. To prevent GitHub Actions from automatically disabling this cron after 60 days of inactivity, the job checks the date of the last commit. If it is older than 30 days, GHA commits a timestamp update to `keepalive.txt` and pushes it, resetting the 60-day inactivity timer automatically.

---

## ⚙️ Completed Reorganizations
During the handover transition, the following cleanups and file structures were completed:
1. **Removed Untracked Noise**: Deleted the empty, unused file `detections/carver.py`.
2. **Corrected Script Extension**: Renamed `detections/detectionsidentity.json` (which contained Python rule matching logic) to a standard Python script extension: [detections/identity_detector.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/detections/identity_detector.py).
3. **Fixed Hunt Report Name & Data**: Renamed the empty 0-byte file `reports/reportssample_hunt_report.md` to [reports/sample_hunt_report.md](file:///c:/Users/user/Documents/AntiGravity/threatscope/reports/sample_hunt_report.md) and populated it with a complete markdown threat hunt report template.
4. **Rescued Chronological Memory**: Copied the previous conversation's planning files directly into this conversation's active memory directory.

---

## 📈 Identified Improvement Opportunities
1. **Graph Edges**: Directionality could be added to graph relationships (e.g., source IP -> victim user -> target host) for a clearer intrusion map.
2. **Sigma Rules Support**: Supporting native Sigma or STIX/TAXII formats rather than custom key-value string parses.

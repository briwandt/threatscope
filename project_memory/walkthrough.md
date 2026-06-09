# ThreatScope Walkthrough & Project Memory

This document contains the consolidated project memory, detailing both the past layout upgrades and the recent workspace handover and reorganization.

---

## 📅 Project Phase History & Context

### 1. High-Fidelity Tabbed Workspace Overhaul (Completed)
We grouped components into four distinct analyst tabs, styled to look like custom button docks:
* **📥 Ingest & Intel**: Simulated source selection, local Elastic connection deck, and manual telemetry editor + brief extraction columns.
* **📊 Detections & Timeline**: The core detections list displayed side-by-side with the chronological hunt timeline.
* **🕸️ Entity Correlation Graph**: NetworkX and PyVis interactive node visualization.
* **📝 AI Analysis & Report**: The Llama 3.3 analyst assistant chatbot and markdown hunt report generation.

### 2. Status & Metric Panels
* **Pulsing Status Indicator**: Animated CSS keyframe pulsing beacon (`pulse-glow`) in the top-right corner indicating that the autonomous threat hunting engine is polling and active.
* **Custom HTML Metric Cards**: Replaced standard Streamlit metrics with sleek, dark-slate HTML cards containing custom top borders (colored by alert severity) and centered icons.

### 3. Telemetry Scenarios & Rules Added
We expanded the telemetry database with three new highly realistic cybersecurity scenarios:
* **Kubernetes Cryptojacking (K8s Abuse)**: Unauthorized container pod (`api-cache-manager`) running an XMRig cryptomining binary.
* **Active Directory DCSync & Ticket Abuse**: Kerberoasting, anomalous TGT ticket lifetimes, and Mimikatz DCSync credential dumping.
* **API Token Abuse & Data Scraping**: Compromised API credentials harvesting 5.28M customer records and exfiltrating via curl to mega.nz.
* **Telecom Signaling Anomalies**: Roaming authentication alerts (Diameter), location query volume spikes (SS7), and GTP tunnel tracking checks.

### 4. Keep-Awake Automation (Anti-Sleep)
* **Playwright Engine**: [keep_awake.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/keep_awake.py) spins up a headless Chromium browser using Playwright, navigates to the Streamlit app URL, and automatically clicks the Streamlit wake-up button (`Yes, get this app back up!`) if the app has gone to sleep.
* **GitHub Actions**: [.github/workflows/keep_awake.yml](file:///c:/Users/user/Documents/AntiGravity/threatscope/.github/workflows/keep_awake.yml) runs this process every 30 minutes in the cloud.

---

## 🛠️ Codebase Reorganization (Conversationcb6d1e36-6a8c-4c3d-8209-70642a8098ec)

Upon migrating the project, we executed the following code sanitization and workspace reorganization:
* **Deleted Untracked Noise**: Removed the empty placeholder file `detections/carver.py`.
* **Corrected Script Extension**: Renamed `detections/detectionsidentity.json` (which contained Python detection runner logic) to [detections/identity_detector.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/detections/identity_detector.py).
* **Restored Hunt Report Template**: Renamed the empty 0-byte file `reports/reportssample_hunt_report.md` to [reports/sample_hunt_report.md](file:///c:/Users/user/Documents/AntiGravity/threatscope/reports/sample_hunt_report.md) and populated it with a complete markdown template.
* **Saved Memory Artifacts**: Transferred all project memory files (`implementation_plan.md`, `task.md`, and `walkthrough.md`) to the current conversation's brain directory to maintain a contiguous operational history.
* **Prevented Cron Inactivity Suspension**: Added an automated keepalive check within the GitHub Actions workflow [.github/workflows/keep_awake.yml](file:///c:/Users/user/Documents/AntiGravity/threatscope/.github/workflows/keep_awake.yml). The workflow now fetches complete history, checks if the last commit date is older than 30 days, and automatically pushes a dummy commit to `keepalive.txt` if so. This resets GitHub's 60-day inactivity timer and prevents the scheduled wake-up cron from being disabled.

---

## 🚀 How to Run & Verify

1. **Start Local Lab (Optional)**:
   ```bash
   docker compose up -d
   python load_sample_logs.py
   ```
2. **Launch Dashboard**:
   ```bash
   streamlit run app.py
   ```
3. **Verify Keep-Awake Workflows**:
   Run the local keep-awake script to verify it launches and captures the browser state:
   ```bash
   python keep_awake.py
   ```

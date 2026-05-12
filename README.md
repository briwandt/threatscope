# ThreatScope

AI-assisted telecom threat hunting and CTI analysis platform designed for defensive security operations, telecom threat detection, and SOC automation.

---

# Overview

ThreatScope is a defensive cyber threat hunting platform built to simulate how modern SOC and CTI teams can use AI-assisted workflows to identify suspicious activity across:

- Telecom signaling infrastructure
- Cloud identity systems
- VPN and remote access telemetry
- Endpoint activity
- Edge network devices
- Contractor and insider threat scenarios

The platform combines:

- Elastic SIEM telemetry
- Correlation-based detection logic
- AI-generated threat analysis
- MITRE ATT&CK mapping
- Telecom-specific threat modeling
- Autonomous hunt workflows

ThreatScope was designed as a portfolio project to demonstrate practical detection engineering, AI-assisted threat hunting, and telecom-focused CTI capabilities.

---

# Features

## Autonomous Threat Hunting
- Continuous telemetry polling
- Automated threat correlation
- Real-time alert generation
- Autonomous hunt engine behavior

## Telecom Threat Detection
- SS7 abuse indicators
- Diameter signaling anomalies
- GTP roaming abuse
- Telecom surveillance detection
- Edge infrastructure targeting

## Living-off-the-Land (LOTL) Detection
- PowerShell abuse
- WMI execution
- Remote management activity
- Valid account misuse
- OAuth persistence

## Initial Access Broker (IAB) Detection
- VPN credential abuse
- Suspicious contractor access
- Remote access anomalies
- Privilege escalation behavior
- Cloud identity abuse

## AI-Assisted CTI Analysis
- Executive summaries
- Threat actor behavior analysis
- MITRE ATT&CK mapping
- Defensive hunt recommendations
- Containment recommendations

## Elastic SIEM Integration
- Elasticsearch connector support
- Simulated SIEM telemetry
- Local Docker-based Elastic lab
- Real-time telemetry ingestion

---

# Stack

- Python
- Streamlit
- Elasticsearch
- Docker
- Groq API
- Llama 3
- Prompt Engineering
- MITRE ATT&CK
- Telecom CTI
- Detection Engineering

---

# Architecture

ThreatScope continuously:

1. Polls telemetry sources
2. Correlates weak threat indicators
3. Calculates risk scores
4. Generates autonomous alerts
5. Produces AI-assisted CTI analysis

The platform simulates how AI-enhanced SOC tooling can accelerate:
- threat triage
- detection engineering
- analyst workflows
- telecom threat hunting

---

# Telecom Threat Coverage

## Signaling Threats
- SS7 abuse
- Diameter abuse
- GTP anomalies
- Roaming manipulation
- Location tracking indicators
- SMS interception indicators

## Edge Infrastructure Threats
- VPN appliances
- Cisco edge devices
- Routers
- Firewalls
- Remote management interfaces

## Identity Threats
- Fraudulent contractors
- Insider risk
- OAuth abuse
- Privileged role escalation
- Impossible travel activity

---

# MITRE ATT&CK Coverage

Examples include:

- T1078 — Valid Accounts
- T1059 — Command and Scripting Interpreter
- T1047 — Windows Management Instrumentation
- T1136 — Create Account
- T1098 — Account Manipulation
- T1021 — Remote Services
- T1556 — Modify Authentication Process

---

# Local Elastic SIEM Lab

ThreatScope supports a local Elastic SIEM lab using Docker.

Telemetry can be:
- simulated
- ingested into Elasticsearch
- automatically polled by ThreatScope
- correlated into AI-assisted detections

---

# Public Demo

Public Streamlit deployment uses:
- simulated telemetry
- autonomous threat correlation
- AI-assisted CTI analysis

Elastic SIEM integration was tested locally using Docker and Elasticsearch.

---

# Run Locally

## Clone Repository

```bash
git clone https://github.com/briwandt/threatscope.git
cd threatscope
```

## Install Requirements

```bash
pip install -r requirements.txt
```

## Run Streamlit

```bash
streamlit run app.py
```

---

# Elastic SIEM Lab Setup

## Start Elastic + Kibana

```bash
docker compose up -d
```

## Load Sample Telemetry

```bash
python load_sample_logs.py
```

## Open Elasticsearch

```text
http://localhost:9200
```

---

# Streamlit Secrets

Create:

```text
.streamlit/secrets.toml
```

Add:

```toml
GROQ_API_KEY = "your_api_key_here"
```

---

# Future Enhancements

- Sigma rule ingestion
- UEBA correlation
- Threat intelligence enrichment
- Live alert streaming
- Detection tuning
- SOAR integration
- Multi-tenant telemetry support
- Threat graph visualization
- SOC dashboarding

---

# Purpose

This project demonstrates:
- AI-assisted threat hunting
- Telecom CTI analysis
- Detection engineering
- SIEM integration
- Autonomous SOC workflows
- Practical defensive AI applications

---

# Disclaimer

This project is intended strictly for:
- defensive security research
- threat hunting education
- detection engineering demonstrations

No offensive functionality is included.

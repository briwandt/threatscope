import json
import tempfile

import networkx as nx
import streamlit as st
from elasticsearch import Elasticsearch
from openai import OpenAI
from pyvis.network import Network
from streamlit_autorefresh import st_autorefresh

from engine.detections import run_detections

# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title="ThreatScope",
    layout="wide"
)

# =========================
# GROQ CLIENT
# =========================

client = OpenAI(
    api_key=st.secrets["GROQ_API_KEY"],
    base_url="https://api.groq.com/openai/v1"
)

# =========================
# TITLE
# =========================

st.title("ThreatScope")

st.write(
    "AI-assisted telecom, identity, and infrastructure threat hunting platform."
)

st.success(
    "ThreatScope Autonomous Hunt Engine: ACTIVE"
)

st.caption(
    "Correlating telemetry, mapping detections to MITRE ATT&CK, visualizing entity relationships, and generating AI-assisted hunt analysis."
)

# =========================
# ELASTIC FUNCTIONS
# =========================

def fetch_elastic_events(index_name="threatscope-logs", limit=25):
    es = Elasticsearch("http://localhost:9200")

    response = es.search(
        index=index_name,
        size=limit,
        sort=[
            {
                "@timestamp": {
                    "order": "asc"
                }
            }
        ],
        query={
            "match_all": {}
        }
    )

    events = []

    for hit in response["hits"]["hits"]:
        events.append(hit["_source"])

    return events


def events_to_text(events):
    lines = []

    for event in events:
        lines.append(
            json.dumps(event, default=str)
        )

    return "\n".join(lines)

# =========================
# SAMPLE LOGS
# =========================

sample_logs = {
    "Full Correlated Hunt Case": """
2026-05-11T07:41:22Z source=SIEM event=vpn_login user=contractor.mills status=success source_ip=185.220.101.44 country=RU device=new-device
2026-05-11T07:44:02Z source=SIEM event=vpn_login user=contractor.mills status=success source_ip=104.28.45.12 country=US device=known-laptop
2026-05-11T07:48:19Z source=SIEM event=mfa_push user=contractor.mills result=approved source_ip=185.220.101.44
2026-05-11T07:56:10Z source=SIEM device=cisco-edge-12 event=remote_mgmt_enabled protocol=ssh actor=contractor.mills
2026-05-11T08:02:44Z host=CORP-LT-448 process=powershell.exe command="-enc SQBFAFgA..." parent=winword.exe
2026-05-11T08:04:30Z host=CORP-LT-448 process=wmic.exe command="wmic process call create powershell.exe"
2026-05-11T08:06:55Z user=contractor.mills azure_role_assignment role=GlobalAdmin actor=contractor.mills
2026-05-11T08:21:55Z source=telecom_signaling protocol=Diameter event=unusual_roaming_auth subscriber_region=US request_origin=foreign_network
2026-05-11T08:25:13Z source=telecom_signaling protocol=SS7 event=location_query_volume_spike subscriber_count=218 request_origin=foreign_network
2026-05-11T08:29:45Z source=telecom_signaling protocol=GTP event=abnormal_roaming_session subscriber_region=US request_origin=foreign_network
2026-05-11T08:31:42Z applicant=remote.engineer.17 resume_signal=overlapping_employment verification_status=unverified requested_access=vpn,router_admin
2026-05-11T08:40:12Z worker=contractor.mills login_location_change=US_to_RU time_window_minutes=15 device_status=new-device
2026-05-11T08:44:19Z user=contractor.mills oauth_app_consent app=UnknownMailSync permissions=Mail.Read offline_access
""",

    "VPN / Initial Access Broker Activity": """
2026-05-11T07:41:22Z source=SIEM event=vpn_login user=contractor.mills status=success source_ip=185.220.101.44 country=RU device=new-device
2026-05-11T07:44:02Z source=SIEM event=vpn_login user=contractor.mills status=success source_ip=104.28.45.12 country=US device=known-laptop
2026-05-11T07:48:19Z source=SIEM event=mfa_push user=contractor.mills result=approved source_ip=185.220.101.44
""",

    "Edge Device / LOTL Activity": """
2026-05-11T07:56:10Z source=SIEM device=cisco-edge-12 event=remote_mgmt_enabled protocol=ssh actor=contractor.mills
2026-05-11T08:02:44Z host=CORP-LT-448 process=powershell.exe command="-enc SQBFAFgA..." parent=winword.exe
2026-05-11T08:04:30Z host=CORP-LT-448 process=wmic.exe command="wmic process call create powershell.exe"
2026-05-11T08:06:55Z user=contractor.mills azure_role_assignment role=GlobalAdmin actor=contractor.mills
""",

    "Telecom Signaling Threats": """
2026-05-11T08:21:55Z source=telecom_signaling protocol=Diameter event=unusual_roaming_auth subscriber_region=US request_origin=foreign_network
2026-05-11T08:25:13Z source=telecom_signaling protocol=SS7 event=location_query_volume_spike subscriber_count=218 request_origin=foreign_network
2026-05-11T08:29:45Z source=telecom_signaling protocol=GTP event=abnormal_roaming_session subscriber_region=US request_origin=foreign_network
""",

    "Fraudulent Worker / Contractor Risk": """
2026-05-11T08:31:42Z applicant=remote.engineer.17 resume_signal=overlapping_employment verification_status=unverified requested_access=vpn,router_admin
2026-05-11T08:40:12Z worker=contractor.mills login_location_change=US_to_RU time_window_minutes=15 device_status=new-device
2026-05-11T08:44:19Z user=contractor.mills oauth_app_consent app=UnknownMailSync permissions=Mail.Read offline_access
"""
}

# =========================
# SIDEBAR
# =========================

st.sidebar.header("ThreatScope Settings")

data_source = st.sidebar.selectbox(
    "Data Source",
    [
        "Built-in Samples",
        "Elastic SIEM Connector (Local Demo)"
    ]
)

alert_threshold = st.sidebar.slider(
    "Alert Threshold",
    1,
    15,
    8
)

st.sidebar.success("Autonomous Hunt Engine Enabled")
st.sidebar.write("Status: ACTIVE")
st.sidebar.write("Polling telemetry")
st.sidebar.write("Running detection engine")
st.sidebar.write("Building entity graph")
st.sidebar.write("Generating AI analysis")

# =========================
# AUTO REFRESH
# =========================

# Auto-refresh disabled so AI analysis and reports do not disappear.
# st_autorefresh(
#     interval=5000,
#     key="threatscope_refresh"
# )

# =========================
# DATA SOURCE LOGIC
# =========================

if data_source == "Built-in Samples":
    selected_source = st.selectbox(
        "Simulated SIEM / Environment Source",
        list(sample_logs.keys())
    )

    input_text = st.text_area(
        "Simulated Telemetry",
        value=sample_logs[selected_source],
        height=300
    )

elif data_source == "Elastic SIEM Connector (Local Demo)":

    st.subheader("Elastic SIEM Connector")

    elastic_index = st.text_input(
        "Elastic Index",
        value="threatscope-logs"
    )

    limit = st.slider(
        "Number of Events",
        5,
        100,
        25
    )

    try:
        elastic_events = fetch_elastic_events(
            index_name=elastic_index,
            limit=limit
        )

        st.success(
            f"Connected to Elastic index: {elastic_index}"
        )

        input_text = events_to_text(elastic_events)

        st.text_area(
            "Elastic Telemetry",
            value=input_text,
            height=300
        )

    except Exception as error:
        st.error(
            f"Elastic connection failed: {error}"
        )

        input_text = ""

# =========================
# THREAT DETECTION ENGINE
# =========================

detections = run_detections(input_text)

# =========================
# RISK SCORING
# =========================

risk_score = 0

severity_weights = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

for detection in detections:
    risk_score += severity_weights.get(
        detection["severity"],
        1
    )

# =========================
# OVERALL SEVERITY
# =========================

if risk_score >= 12:
    severity = "CRITICAL"
elif risk_score >= 8:
    severity = "HIGH"
elif risk_score >= 4:
    severity = "MEDIUM"
else:
    severity = "LOW"

# =========================
# ALERTING
# =========================

if severity == "CRITICAL":
    st.error("ALERT: Critical correlated threat activity detected")
elif severity == "HIGH":
    st.warning("WARNING: High-risk suspicious activity identified")
elif severity == "MEDIUM":
    st.info("NOTICE: Medium-risk suspicious activity observed")
else:
    st.success("No significant threat indicators detected")

# =========================
# DETECTION SUMMARY
# =========================

st.subheader("ThreatScope Detection Engine")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Risk Score", risk_score)

with col2:
    st.metric("Overall Severity", severity)

with col3:
    st.metric("Detections", len(detections))

# =========================
# DETECTION RESULTS
# =========================

if len(detections) > 0:
    for detection in detections:
        if detection["severity"] == "CRITICAL":
            st.error(
                f"{detection['title']} ({detection['severity']})"
            )
        elif detection["severity"] == "HIGH":
            st.warning(
                f"{detection['title']} ({detection['severity']})"
            )
        else:
            st.info(
                f"{detection['title']} ({detection['severity']})"
            )

        st.write(detection["description"])

        st.caption(
            f"MITRE ATT&CK: {detection['mitre']} | Confidence: {detection['confidence']}"
        )

        st.caption(
            f"Hunt Pivot: {detection['hunt_pivot']}"
        )
else:
    st.success("No significant detections identified.")

# =========================
# MITRE ATT&CK MAPPING
# =========================

st.subheader("MITRE ATT&CK Mapping")

mapped_techniques = set()

for detection in detections:
    mapped_techniques.add(
        detection["mitre"]
    )

if len(mapped_techniques) > 0:
    for technique in sorted(mapped_techniques):
        st.write(f"- {technique}")
else:
    st.write("No ATT&CK mappings identified.")

# =========================
# THREAT TIMELINE
# =========================

st.subheader("Threat Timeline")

timeline_events = []

if "vpn_login" in input_text:
    timeline_events.append({
        "time": "07:41",
        "event": "Foreign VPN Login",
        "severity": "HIGH"
    })

if "mfa_push" in input_text:
    timeline_events.append({
        "time": "07:48",
        "event": "MFA Approval",
        "severity": "MEDIUM"
    })

if "protocol=ssh" in input_text or 'protocol": "ssh' in input_text:
    timeline_events.append({
        "time": "07:56",
        "event": "SSH Remote Management Enabled",
        "severity": "HIGH"
    })

if "powershell.exe" in input_text:
    timeline_events.append({
        "time": "08:02",
        "event": "PowerShell Execution",
        "severity": "HIGH"
    })

if "wmic.exe" in input_text:
    timeline_events.append({
        "time": "08:04",
        "event": "WMI Remote Execution",
        "severity": "HIGH"
    })

if "GlobalAdmin" in input_text:
    timeline_events.append({
        "time": "08:06",
        "event": "Privileged Role Escalation",
        "severity": "CRITICAL"
    })

if "Diameter" in input_text:
    timeline_events.append({
        "time": "08:21",
        "event": "Diameter Roaming Authentication Anomaly",
        "severity": "HIGH"
    })

if "SS7" in input_text:
    timeline_events.append({
        "time": "08:25",
        "event": "SS7 Signaling Spike",
        "severity": "HIGH"
    })

if "GTP" in input_text:
    timeline_events.append({
        "time": "08:29",
        "event": "GTP Roaming Session Anomaly",
        "severity": "HIGH"
    })

if "unverified" in input_text:
    timeline_events.append({
        "time": "08:31",
        "event": "Unverified Contractor Access Request",
        "severity": "MEDIUM"
    })

if "oauth" in input_text.lower():
    timeline_events.append({
        "time": "08:44",
        "event": "OAuth Persistence Activity",
        "severity": "CRITICAL"
    })

if len(timeline_events) > 0:
    for event in timeline_events:
        if event["severity"] == "CRITICAL":
            st.error(
                f"{event['time']} | {event['event']}"
            )
        elif event["severity"] == "HIGH":
            st.warning(
                f"{event['time']} | {event['event']}"
            )
        else:
            st.info(
                f"{event['time']} | {event['event']}"
            )
else:
    st.success("No correlated timeline activity identified.")

# =========================
# ENTITY CORRELATION GRAPH
# =========================

st.subheader("Entity Correlation Graph")

graph = nx.Graph()

def add_graph_node(name, color):
    if name not in graph:
        graph.add_node(
            name,
            color=color,
            title=name
        )


def add_graph_edge(source, target):
    graph.add_edge(
        source,
        target
    )

if "contractor.mills" in input_text:
    add_graph_node("contractor.mills", "red")

if "185.220.101.44" in input_text:
    add_graph_node("185.220.101.44", "orange")

if "104.28.45.12" in input_text:
    add_graph_node("104.28.45.12", "orange")

if "cisco-edge-12" in input_text:
    add_graph_node("cisco-edge-12", "purple")

if "CORP-LT-448" in input_text:
    add_graph_node("CORP-LT-448", "purple")

if "powershell.exe" in input_text:
    add_graph_node("powershell.exe", "yellow")

if "wmic.exe" in input_text:
    add_graph_node("wmic.exe", "yellow")

if "GlobalAdmin" in input_text:
    add_graph_node("GlobalAdmin", "pink")

if "UnknownMailSync" in input_text:
    add_graph_node("UnknownMailSync", "blue")

if "Diameter" in input_text:
    add_graph_node("Diameter", "green")

if "SS7" in input_text:
    add_graph_node("SS7", "green")

if "GTP" in input_text:
    add_graph_node("GTP", "green")

if "remote.engineer.17" in input_text:
    add_graph_node("remote.engineer.17", "gray")

if "contractor.mills" in input_text and "185.220.101.44" in input_text:
    add_graph_edge("contractor.mills", "185.220.101.44")

if "contractor.mills" in input_text and "104.28.45.12" in input_text:
    add_graph_edge("contractor.mills", "104.28.45.12")

if "contractor.mills" in input_text and "cisco-edge-12" in input_text:
    add_graph_edge("contractor.mills", "cisco-edge-12")

if "contractor.mills" in input_text and "CORP-LT-448" in input_text:
    add_graph_edge("contractor.mills", "CORP-LT-448")

if "CORP-LT-448" in input_text and "powershell.exe" in input_text:
    add_graph_edge("CORP-LT-448", "powershell.exe")

if "powershell.exe" in input_text and "wmic.exe" in input_text:
    add_graph_edge("powershell.exe", "wmic.exe")

if "contractor.mills" in input_text and "GlobalAdmin" in input_text:
    add_graph_edge("contractor.mills", "GlobalAdmin")

if "contractor.mills" in input_text and "UnknownMailSync" in input_text:
    add_graph_edge("contractor.mills", "UnknownMailSync")

if "contractor.mills" in input_text and "Diameter" in input_text:
    add_graph_edge("contractor.mills", "Diameter")

if "contractor.mills" in input_text and "SS7" in input_text:
    add_graph_edge("contractor.mills", "SS7")

if "contractor.mills" in input_text and "GTP" in input_text:
    add_graph_edge("contractor.mills", "GTP")

if "remote.engineer.17" in input_text and "contractor.mills" in input_text:
    add_graph_edge("remote.engineer.17", "contractor.mills")

if len(graph.nodes) > 0:
    net = Network(
        height="500px",
        width="100%",
        bgcolor="#111111",
        font_color="white"
    )

    net.from_nx(graph)

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".html"
    ) as tmp_file:
        net.save_graph(tmp_file.name)

        with open(
            tmp_file.name,
            "r",
            encoding="utf-8"
        ) as graph_file:
            html_content = graph_file.read()

    st.components.v1.html(
        html_content,
        height=550
    )
else:
    st.info("No entity relationships identified.")

# =========================
# HUNT SUMMARY
# =========================

st.subheader("Hunt Summary")

if len(detections) > 0:
    st.write(
        "ThreatScope identified correlated suspicious activity across identity, infrastructure, endpoint, and telecom telemetry sources."
    )
else:
    st.write(
        "No significant suspicious activity identified in current telemetry."
    )
# =========================
# HUNT REPORT GENERATOR
# =========================

st.subheader("Hunt Report")

report_lines = []

report_lines.append("# ThreatScope Hunt Report")
report_lines.append("")
report_lines.append("## Executive Summary")
report_lines.append(
    f"ThreatScope identified {len(detections)} detection(s) with an overall severity of {severity} and a risk score of {risk_score}."
)
report_lines.append("")

report_lines.append("## Detection Findings")
report_lines.append("")

if len(detections) > 0:
    for detection in detections:
        report_lines.append(f"### {detection['title']}")
        report_lines.append(f"- Severity: {detection['severity']}")
        report_lines.append(f"- Confidence: {detection['confidence']}")
        report_lines.append(f"- MITRE ATT&CK: {detection['mitre']}")
        report_lines.append(f"- Description: {detection['description']}")
        report_lines.append(f"- Hunt Pivot: {detection['hunt_pivot']}")
        report_lines.append("")
else:
    report_lines.append("No significant detections identified.")
    report_lines.append("")

report_lines.append("## Timeline")
report_lines.append("")

if len(timeline_events) > 0:
    for event in timeline_events:
        report_lines.append(
            f"- {event['time']} | {event['event']} | {event['severity']}"
        )
else:
    report_lines.append("No timeline events identified.")

report_lines.append("")
report_lines.append("## Recommended Next Steps")
report_lines.append("")
report_lines.append("- Validate the source IPs, users, and devices involved.")
report_lines.append("- Review privileged role assignments and OAuth consent grants.")
report_lines.append("- Investigate telecom signaling anomalies across SS7, Diameter, and GTP.")
report_lines.append("- Confirm whether activity aligns with approved maintenance or contractor access.")
report_lines.append("- Preserve relevant logs for incident response review.")
report_lines.append("")

hunt_report = "\n".join(report_lines)

st.download_button(
    label="Download Hunt Report",
    data=hunt_report,
    file_name="threatscope_hunt_report.md",
    mime="text/markdown"
)

with st.expander("Preview Hunt Report"):
    st.markdown(hunt_report)
# =========================
# AI PROMPT
# =========================

prompt = f"""
You are a defensive cyber threat intelligence analyst supporting a telecom environment.

Analyze the telemetry for:

- Initial Access Broker activity
- VPN compromise
- MFA abuse
- PowerShell abuse
- WMI execution
- Living-off-the-land techniques
- SS7 abuse
- Diameter abuse
- GTP abuse
- cloud privilege escalation
- OAuth persistence
- contractor fraud
- insider threat
- telecom signaling abuse
- edge infrastructure targeting

Telemetry:
{input_text}

Structured Detections:
{json.dumps(detections, indent=2)}

Timeline:
{json.dumps(timeline_events, indent=2)}

Risk Score:
{risk_score}

Severity:
{severity}

Provide:

1. Executive Summary
2. Correlated Threat Indicators
3. Potential Threat Actor Behavior
4. MITRE ATT&CK Mapping
5. Telecom Threat Risk
6. Identity Risk
7. Recommended Hunt Queries
8. Recommended Containment Steps
9. False Positive Considerations
10. Confidence
11. Severity

Focus ONLY on defensive analysis and threat hunting.
"""

# =========================
# AI ANALYSIS
# =========================

st.subheader("ThreatScope AI Analysis")

st.info(
    "AI-assisted analysis is generated on demand to conserve API usage."
)

if st.button("Generate AI Analysis"):
    try:
        with st.spinner("Analyzing telemetry with ThreatScope AI..."):
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a defensive cyber threat intelligence analyst. Only provide defensive analysis, threat hunting guidance, and containment recommendations."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1200
            )

        ai_output = response.choices[0].message.content

        if ai_output and ai_output.strip():
            st.markdown(ai_output)
        else:
            st.warning("Groq returned an empty response. Try again or reduce the prompt size.")
            st.json(response.model_dump())

    except Exception as error:
        st.error("AI analysis failed.")
        st.exception(error)
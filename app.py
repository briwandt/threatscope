import json
import streamlit as st
from openai import OpenAI
from elasticsearch import Elasticsearch
from streamlit_autorefresh import st_autorefresh

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
    "AI-assisted telecom threat hunting and CTI analysis platform."
)

st.success(
    "ThreatScope Autonomous Hunt Engine: ACTIVE"
)

st.caption(
    "Continuously polling Elastic SIEM telemetry, correlating threat indicators, and generating AI-assisted CTI analysis."
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
        "Elastic SIEM Connector"
    ]
)

alert_threshold = st.sidebar.slider(
    "Alert Threshold",
    1,
    15,
    2
)

st.sidebar.success(
    "Autonomous Hunt Engine Enabled"
)

st.sidebar.write("Status: ACTIVE")
st.sidebar.write("Polling Elastic SIEM")
st.sidebar.write("Correlating telemetry")
st.sidebar.write("Generating AI analysis")

# =========================
# AUTO REFRESH
# =========================

st_autorefresh(
    interval=5000,
    key="threatscope_refresh"
)

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

else:

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

        input_text = events_to_text(
            elastic_events
        )

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
# ALWAYS-ON ANALYSIS
# =========================

risk_score = 0
findings = []

# =========================
# CORRELATION ENGINE
# =========================

if "vpn_login" in input_text:
    risk_score += 1
    findings.append(
        "VPN access activity detected"
    )

if "country\": \"RU" in input_text or "country=RU" in input_text:
    risk_score += 2
    findings.append(
        "Foreign login location detected"
    )

if "powershell.exe" in input_text:
    risk_score += 2
    findings.append(
        "PowerShell execution detected"
    )

if "wmic.exe" in input_text:
    risk_score += 2
    findings.append(
        "WMI execution detected"
    )

if "GlobalAdmin" in input_text:
    risk_score += 3
    findings.append(
        "Privileged cloud role assignment detected"
    )

if "SS7" in input_text:
    risk_score += 3
    findings.append(
        "SS7 signaling anomaly detected"
    )

if "Diameter" in input_text:
    risk_score += 2
    findings.append(
        "Diameter signaling anomaly detected"
    )

if "GTP" in input_text:
    risk_score += 2
    findings.append(
        "GTP signaling anomaly detected"
    )

if "oauth" in input_text.lower():
    risk_score += 2
    findings.append(
        "OAuth persistence activity detected"
    )

if "unverified" in input_text:
    risk_score += 2
    findings.append(
        "Unverified contractor activity detected"
    )

if "protocol\": \"ssh" in input_text or "protocol=ssh" in input_text:
    risk_score += 1
    findings.append(
        "SSH remote management activity detected"
    )

# =========================
# SEVERITY
# =========================

if risk_score >= 10:
    severity = "CRITICAL"

elif risk_score >= 7:
    severity = "HIGH"

elif risk_score >= 4:
    severity = "MEDIUM"

else:
    severity = "LOW"

# =========================
# ALERTING
# =========================

if len(findings) >= 2 and risk_score >= alert_threshold:

    st.error(
        "ALERT: Correlated telecom threat activity detected"
    )

elif len(findings) >= 1:

    st.warning(
        "NOTICE: Suspicious activity observed"
    )

else:

    st.success(
        "No significant threat indicators detected"
    )

# =========================
# DISPLAY FINDINGS
# =========================

st.subheader(
    "Correlation Engine Findings"
)

st.write(
    f"Risk Score: {risk_score}"
)

st.write(
    f"Severity: {severity}"
)

for finding in findings:

    st.write(
        f"- {finding}"
    )

# =========================
# PROMPT
# =========================

prompt = f"""
You are a defensive cyber threat intelligence analyst supporting a telecom environment.

Analyze the telemetry for:

- Initial Access Broker activity
- VPN compromise
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

Correlation Findings:
{findings}

Risk Score:
{risk_score}

Severity:
{severity}

Focus ONLY on defensive analysis, detection, containment, and threat hunting.

Provide:

1. Executive Summary
2. Correlated Threat Indicators
3. Potential Threat Actor Behavior
4. MITRE ATT&CK Mapping
5. Telecom Threat Risk
6. Identity Risk
7. Recommended Hunt Queries
8. Recommended Containment Steps
9. Confidence
10. Severity
"""

# =========================
# AI ANALYSIS
# =========================

st.subheader("ThreatScope AI Analysis")

st.info(
    "Autonomous hunting is active. AI analysis is generated on demand to conserve API tokens."
)

if st.button("Generate AI Analysis"):

    try:
        with st.spinner("Analyzing telemetry with ThreatScope AI..."):

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=700
            )

        st.write(response.choices[0].message.content)

    except Exception as error:
        st.error(f"AI analysis temporarily unavailable: {error}")
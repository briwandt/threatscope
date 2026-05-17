"""
ThreatScope Elastic sample loader.

This script loads simulated telecom, identity, endpoint, and contractor-risk
telemetry into a local Elasticsearch index called threatscope-logs.

Run this only when Elasticsearch is running locally and you want to test the
Elastic SIEM Connector mode in app.py.
"""

from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch("http://localhost:9200")

# Index name
index_name = "threatscope-logs"

# Sample telecom / CTI telemetry
events = [

    {
        "@timestamp": "2026-05-11T07:41:22Z",
        "source": "SIEM",
        "event": "vpn_login",
        "user": "contractor.mills",
        "status": "success",
        "source_ip": "185.220.101.44",
        "country": "RU",
        "device": "new-device",
        "category": "vpn_iab"
    },

    {
        "@timestamp": "2026-05-11T07:44:02Z",
        "source": "SIEM",
        "event": "vpn_login",
        "user": "contractor.mills",
        "status": "success",
        "source_ip": "104.28.45.12",
        "country": "US",
        "device": "known-laptop",
        "category": "vpn_iab"
    },

    {
        "@timestamp": "2026-05-11T07:48:19Z",
        "source": "SIEM",
        "event": "mfa_push",
        "user": "contractor.mills",
        "result": "approved",
        "source_ip": "185.220.101.44",
        "category": "vpn_iab"
    },

    {
        "@timestamp": "2026-05-11T07:56:10Z",
        "source": "SIEM",
        "device": "cisco-edge-12",
        "event": "remote_mgmt_enabled",
        "protocol": "ssh",
        "actor": "contractor.mills",
        "category": "edge_device"
    },

    {
        "@timestamp": "2026-05-11T08:02:44Z",
        "source": "EDR",
        "host": "CORP-LT-448",
        "process": "powershell.exe",
        "command": "-enc SQBFAFgA...",
        "parent": "winword.exe",
        "category": "lotl"
    },

    {
        "@timestamp": "2026-05-11T08:04:30Z",
        "source": "EDR",
        "host": "CORP-LT-448",
        "process": "wmic.exe",
        "command": "wmic process call create powershell.exe",
        "category": "lotl"
    },

    {
        "@timestamp": "2026-05-11T08:06:55Z",
        "source": "CloudIdentity",
        "user": "contractor.mills",
        "event": "azure_role_assignment",
        "role": "GlobalAdmin",
        "actor": "contractor.mills",
        "category": "cloud_identity"
    },

    {
        "@timestamp": "2026-05-11T08:21:55Z",
        "source": "telecom_signaling",
        "protocol": "Diameter",
        "event": "unusual_roaming_auth",
        "subscriber_region": "US",
        "request_origin": "foreign_network",
        "category": "signaling"
    },

    {
        "@timestamp": "2026-05-11T08:25:13Z",
        "source": "telecom_signaling",
        "protocol": "SS7",
        "event": "location_query_volume_spike",
        "subscriber_count": 218,
        "request_origin": "foreign_network",
        "category": "signaling"
    },

    {
        "@timestamp": "2026-05-11T08:29:45Z",
        "source": "telecom_signaling",
        "protocol": "GTP",
        "event": "abnormal_roaming_session",
        "subscriber_region": "US",
        "request_origin": "foreign_network",
        "category": "signaling"
    },

    {
        "@timestamp": "2026-05-11T08:31:42Z",
        "source": "HRRisk",
        "applicant": "remote.engineer.17",
        "resume_signal": "overlapping_employment",
        "verification_status": "unverified",
        "requested_access": "vpn,router_admin",
        "category": "contractor_risk"
    },

    {
        "@timestamp": "2026-05-11T08:40:12Z",
        "source": "Identity",
        "worker": "contractor.mills",
        "login_location_change": "US_to_RU",
        "time_window_minutes": 15,
        "device_status": "new-device",
        "category": "identity_risk"
    },

    {
        "@timestamp": "2026-05-11T08:44:19Z",
        "source": "CloudIdentity",
        "user": "contractor.mills",
        "oauth_app_consent": "UnknownMailSync",
        "permissions": "Mail.Read offline_access",
        "category": "oauth_risk"
    }
]

# Load events into Elasticsearch
for event in events:
    es.index(
        index=index_name,
        document=event
    )

print(f"Loaded {len(events)} events into {index_name}")
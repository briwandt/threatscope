import time
import urllib.request
from datetime import datetime

URL = "https://threatscope-ame8t7utwmtjl8rnyauohb.streamlit.app/"
INTERVAL = 3600  # 1 hour (in seconds)

print(f"[{datetime.now()}] ThreatScope Keep-Awake automation daemon started.")
print(f"Target URL: {URL}")
print(f"Interval: {INTERVAL}s")

while True:
    try:
        # Simulate browser user agent to ensure requests are processed normally
        req = urllib.request.Request(
            URL,
            headers={"User-Agent": "ThreatScopeKeepAlive/1.0"}
        )
        with urllib.request.urlopen(req, timeout=20) as response:
            print(f"[{datetime.now()}] Ping successful. Status: {response.getcode()}")
    except Exception as e:
        print(f"[{datetime.now()}] Ping failed: {e}")
    
    time.sleep(INTERVAL)

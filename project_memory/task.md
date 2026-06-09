# ThreatScope Layout Redesign Tasks

- `[x]` Refactor `app.py` styling to include animations, glowing pulse status beacon, and font configurations
- `[x]` Add custom metrics card renderer function in `app.py`
- `[x]` Implement tabbed workspace structure in `app.py`
- `[x]` Relocate ingestion, detection summary, graph, and report components into their respective tabs
- `[x]` Verify local execution and visual appeal
- `[x]` Add advanced simulated threat scenarios to built-in sample logs and briefs (K8s Cryptomining, AD DCSync, API Token Abuse)
- `[x]` Extend detections engine (rules 18-24) to support alert generation for the new scenarios
- `[x]` Update Elastic sample loader script (`load_sample_logs.py`) to align with the new scenarios
- `[x]` Add GitHub Actions scheduled keep-awake workflow using Playwright to automatically click sleep/wake buttons
- `[x]` Upgrade GitHub Action dependencies (checkout@v4, setup-python@v5, upload-artifact@v4) to avoid deprecation errors
- `[x]` Extract and update high-resolution screenshots of the new dashboard layouts for README.md

## Reorganization & Transition Tasks

- `[x]` Migrate operational memory files (`implementation_plan.md`, `task.md`, `walkthrough.md`) to new active workspace brain directory
- `[x]` Remove empty placeholder file [detections/carver.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/detections/carver.py)
- `[x]` Rename legacy `detections/detectionsidentity.json` script to [detections/identity_detector.py](file:///c:/Users/user/Documents/AntiGravity/threatscope/detections/identity_detector.py)
- `[x]` Rename typo file `reports/reportssample_hunt_report.md` to [reports/sample_hunt_report.md](file:///c:/Users/user/Documents/AntiGravity/threatscope/reports/sample_hunt_report.md) and populate with full markdown template
- `[x]` Add Keepalive Auto-Commit to [keep_awake.yml](file:///c:/Users/user/Documents/AntiGravity/threatscope/.github/workflows/keep_awake.yml) to prevent GHA cron workflow suspension after 60 days of inactivity

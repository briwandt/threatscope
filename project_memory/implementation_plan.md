# ThreatScope Layout & UI Redesign

This plan details a complete visual overhaul of the ThreatScope dashboard, replacing the generic, stacked Streamlit layout with a high-fidelity, tabbed security console featuring premium CSS styling, animations, and custom HTML/CSS metric panels.

## User Review Required

Please review the proposed design modifications and confirm if you would like to proceed with implementing them:
- **Tabbed Interface**: Group controls and visualizations into four professional workspace tabs:
  1. 📥 **Data Ingest & Threat Intel Brief**
  2. 📊 **Hunt Overview & Detections**
  3. 🕸️ **Entity Correlation Graph**
  4. 📝 **AI Analysis & Hunt Report**
- **Glowing Status Pulsator**: Replace the standard static alert for the hunt engine status with an animated, CSS-pulsing cybersecurity status beacon.
- **Custom HTML Metric Cards**: Remove standard `st.metric` widgets and replace them with custom-styled HTML/CSS cards containing dark backgrounds, accent-colored top borders, and centered threat icons.
- **Glassmorphism Panels**: Apply rounded cards with subtle box-shadows and hover effects to the manual log editor and brief extractor to make them feel alive and responsive.
- **Enhanced Sidebar Deck**: Add subtle CSS overlays to the sidebar to make controls (e.g. data source selection and alert threshold sliders) blend seamlessly into the cockpit aesthetics.

## Proposed Changes

### Main Application Styling & Components

#### [MODIFY] [app.py](file:///C:/Users/user/Documents/threatscope/app.py)
Update page components and flow:
- **Style Injection**: Add keyframe animations (`pulse-glow`) and tab customizations directly to the global style block.
- **Status Indicator**: Implement a custom HTML block displaying a glowing cyan indicator representing the active autonomous engine.
- **Custom Metric Renderers**:
  - `render_metric_card(label, value, color, icon)`: Renders glowing cards for Risk Score (orange/red), Severity (red/cyan), and Detection Count (blue).
- **Workspace Tabs Structure**:
  - Wrap existing segments in a tabbed layout:
    ```python
    tab_ingest, tab_detections, tab_graph, tab_report = st.tabs([
        "📥 Data Ingest", 
        "📊 Hunt Detections & Timeline", 
        "🕸️ Entity Correlation Graph", 
        "📝 AI Analysis & Report"
    ])
    ```
  - Place Manual Input + Threat Brief inside `tab_ingest`.
  - Place Severity Alerts, Metric Cards, Detections list, and Threat Timeline inside `tab_detections`.
  - Place the PyVis entity relationship visualizer inside `tab_graph`.
  - Place AI Threat Intelligence analysis and Hunt Report export controls inside `tab_report`.

## Verification Plan

### Manual Verification
1. Run `streamlit run app.py` and verify that the new tab headers are rendered and look styled.
2. Verify that the top-left status bar displays a pulsing cyan beacon with the text "Autonomous Hunt Engine: ACTIVE & POLLING".
3. Check the "Hunt Detections & Timeline" tab and confirm that the metric panels are styled with custom icons and top borders.
4. Verify that clicking on tabs dynamically updates the content without throwing errors.

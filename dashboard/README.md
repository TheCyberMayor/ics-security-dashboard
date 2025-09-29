# ICS Security Risk Dashboard

A self-contained web dashboard visualizing ICS/PLC cybersecurity risk with:

- Network topology graph with color-coded risk (vis-network)
- Real-time risk score timeline (Chart.js)
- Attack distribution pie chart (Chart.js)
- System health indicators
- Alert management panel (filter, select, acknowledge/suppress, export CSV)
- Interactions: zoom/pan, filter by time/severity/zone, drill-down on nodes, toggle layout, fit-to-view, click pie slice to filter

## Run

No build needed. Open `index.html` directly in your browser.

Optionally, serve locally (avoids any cross-origin issues on some browsers):

```powershell
# From the dashboard folder
python -m http.server 8080
# then open http://localhost:8080
```

If Python isn't installed, just double-click `index.html` to open it.

## Files

- `index.html` – Page layout and CDN libraries
- `styles.css` – Dark theme and layout styles
- `script.js` – Demo data, charts, topology, interactions

## Notes

- All data is generated locally for demo purposes. Replace generators in `script.js` with real API/WebSocket sources to integrate with your system.
- Chart.js time scale uses `date-fns` via the `chartjs-adapter-date-fns` adapter included from CDN.

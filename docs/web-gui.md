# Web GUI Guide

The web GUI runs on port 8080 (8088 in the default Docker compose) and is accessible from any browser.

---

## Dashboard (`/`)

- **Stat cards** — Total Targets, Groups, Tags, Last Scan
- **Last scan severity summary** — Critical / High / Medium / Low / Info counts
- **Top Threats table** — aggregated findings from the last 10 scans, sorted by severity and frequency
- **Most Vulnerable Targets** — score-based ranking (critical×10 + high×5)
- **Finding Trend chart** — CSS stacked bar chart for the last 7 completed scans
- **Recent Findings feed** — latest 15 findings, clickable to the relevant scan
- **Quick targets grid** — per-target scan buttons
- **Run New Scan modal** — scope by all targets, group, or tag

---

## Targets (`/targets`)

- Filter by name/host search, group, or tag
- **Host / Hostname column** — shows both the resolved hostname and the original host entry
- **Resolve button** (teal refresh icon) — re-runs DNS/reverse-DNS lookup on demand
- Add / Edit / Delete targets via modal
- Enable/disable toggle per target
- Scan individual targets from the Actions column

---

## Groups (`/groups`) and Tags (`/tags`)

- Create, edit, delete groups and tags
- **Scan Group** button on each group card

---

## Scan History (`/scans`)

Lists every scan with status, timestamps, and finding counts. Click any row to open the Scan Detail page.

---

## Scan Detail (`/scans/<id>`)

- Header with metadata and Export JSON button
- 5 severity count cards
- Horizontal stacked severity distribution bar
- **Filter bar** — filter by severity, target, check module, or keyword search
- **Findings grouped by target** (collapsible) then by check module
- Each finding shows severity badge, title, and expandable details (description, recommendation, technical details, CVE/CVSS)

---

## Live Scan Progress Modal

Triggered whenever you start a scan. Shows:
- Current check being run
- Progress bar
- Colour-coded findings feed (WebSocket, real-time)
- Severity summary on completion
- Link to scan detail page

---

## API

Swagger UI available at `/api/docs`.

---

## Related Pages

- [Managing Targets](targets.md)
- [Groups & Tags](groups-and-tags.md)
- [CLI Reference](cli.md)

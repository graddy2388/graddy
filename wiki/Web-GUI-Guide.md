# Web GUI Guide

The web GUI runs on port 8080 (8088 in the default Docker compose) and is accessible from any browser.

---

## Dashboard (`/`)

- **Stat cards** — Total Targets, Groups, Tags, Last Scan
- **Last scan severity summary** — Critical / High / Medium / Low / Info counts
- **Recent scans table** — clickable rows linking to scan detail
- **Quick targets grid** — per-target scan buttons
- **Run Scan button** — triggers a scan of all enabled targets

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
- **Filter bar** — filter by severity, target, check module
- Findings table with expandable recommendation text
- Passed checks shown with PASS badge

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

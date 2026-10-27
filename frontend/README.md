# Frontend: Threat Console

React app for the analyst console (SJSU-114, under SJSU-112 Frontend–backend integration). Built from UI design v1.1 (scheme A, Midnight Ops) and API contract v0.4.1 (`docs/api/openapi.yaml`). It talks to the FastAPI backend in `backend/` (SJSU-115).

Stack: Node.js, Vite, React 19, React Router, plain CSS. JavaScript, no TypeScript.

## Run

You need Node.js 20.19 or newer (`node -v`).

1. Start the backend (see `backend/README.md`). Note the `API_KEY` you set there.
2. In another terminal:

```bash
cd frontend
npm install
cp .env.example .env.local   # set VITE_API_KEY to the backend's API_KEY
npm run dev
```

3. Open <http://localhost:5173> and press **Play**.

Port 5173 is already allowed in the backend's `CORS_ORIGINS`.

`npm run build` writes a static site to `dist/` for deployment. Set `VITE_API_BASE_URL` to the deployed backend before building.

## What is built

| Page | Route | Status |
|---|---|---|
| Overview | `/` | Built. Replay controls, key numbers, needs review, traffic, techniques |
| Incidents | `/incidents` | Built. Update banner, status tabs, filters, bulk confirm/dismiss, CSV export |
| Incident detail | `/incidents/:id` | Built. Triage, Response and Research tabs, status workflow, technique override, notes |
| Reports, Evaluation, Knowledge base | `/reports`, `/evaluation`, `/knowledge-base` | Placeholder, next round |

## How it works

- **Replay** (`src/state/ReplayContext.jsx`): the browser drives the replay. Each tick calls `POST /detect`, then `GET /incidents`. Default speed is one window every 5 seconds. The replay keeps running while you move between pages.
- **New incidents wait behind a banner** on the Incidents page so the list never jumps. The banner is red when a new incident is high severity (or, without severity, attack probability ≥ 0.80), yellow otherwise.
- **Explanations** are written in the background. The detail page polls `GET /incidents/{id}` every 2 seconds while `explanation.status` is `generating`, and offers **Regenerate** when `stale` is true.
- **No severity yet**: the backend's fallback detector returns `severity: null`. The UI then shows an "Unrated" chip, ranks by attack probability (as the contract says), and the urgent count uses probability ≥ 0.80 (`URGENT_PROBABILITY` in `src/utils/incidents.js`).

## Code map

```
src/
  api/client.js            All API calls; adds the X-API-Key header
  state/ReplayContext.jsx  Replay loop and shared incident list
  pages/                   Overview, Incidents, IncidentDetail, ComingNext (placeholder)
  components/              Sidebar, ReplayBar, badges, icons, EvidenceFunnel
  utils/                   Formatting and incident rules (status order, priority)
  styles/tokens.css        Design tokens: every color, font and radius
  styles/app.css           Component styles
```

Colors live only in `tokens.css`. To change a color, change it there.

## Known gaps

- "Compared with normal traffic" and connection states (REJ, SF) from the design need fields the API does not return yet, so the Traffic panel shows connections, bytes and protocol only.
- `GET /incidents` returns every incident and window on each tick. It gets slower as the replay goes on (about 1 MB after 2,400 windows). A `since` parameter on the backend would fix this.
- Service and port show "—" with the Oct 6 demo data, which has no service column.

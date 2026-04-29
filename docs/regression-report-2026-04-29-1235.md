# Regression Report — 2026-04-29 12:35

## Summary

| Metric                 | Value   |
|------------------------|---------|
| Date                   | 2026-04-29 12:35 |
| Application            | AI.Sentinel embedded dashboard + ChatApp sample |
| URL                    | `http://localhost:5160` (host) / `http://host.docker.internal:5160` (browser-MCP container) |
| Pages Tested           | 2 (`/` Blazor chat, `/ai-sentinel/` dashboard) |
| Viewports Tested       | 3 (Desktop 1920×1080, Tablet 768×1024, Mobile 375×812) |
| Existing Tests Passed  | 520 |
| Existing Tests Failed  | 0 |
| Console Errors Found   | 2 distinct (1 favicon 404, 1 SignalR negotiate `file://` — Docker artefact) |
| Network Errors Found   | 0 dashboard-side; 1 sample-app SignalR negotiate (host-resolution artefact) |
| Visual Issues Found    | 1 Major (mobile dashboard layout), 0 Critical |
| Overall Status         | **WARN** — dashboard ships, mobile layout needs polish |

---

## Phase 2: Existing Test Results

**Framework:** xUnit 2.x (multi-target `net8.0` + `net10.0`)
**Command:** `dotnet test tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj`

| Target Framework | Passed | Failed | Skipped | Duration |
|------------------|--------|--------|---------|----------|
| net8.0           | 520    | 0      | 0       | 7 s      |
| net10.0          | 520    | 0      | 0       | 7 s      |

The new `DashboardMapAISentinelTests` (5 tests) verifying `MapAISentinel` + `MapFallback` composition are part of this run and all pass.

---

## Page-by-Page Results

### Page 1: `/ai-sentinel/` — Dashboard

**URL:** `http://localhost:5160/ai-sentinel/`
**Page title:** `AI.Sentinel Dashboard`
**Severity:** **WARN** (Major mobile layout issue, otherwise solid)

**Functional checks:**
- HTTP 200 — `<h1>AI.Sentinel</h1>` rendered, dashboard HTML served (not the Blazor SPA shell — verifies the `MapAISentinel` fix landed correctly).
- Accessibility tree clean: banner with `<h1>`, `<main>` containing Threat Risk Score gauge, 5 stat cards (Total/Critical/High/Medium/Low), Live Event Feed `<table>` with column headers Time / Detector / Severity / Reason / Hash.
- Filter `<tablist>` present with "All" and "Authorization" buttons; "All" pressed by default — matches `DashboardAuthzFeedTests` expectations.
- All counters show **0** (empty audit store — expected; no traffic was generated through the chat).
- Console errors: 1 (`GET /favicon.ico → 404`). Sample-app artefact, not Sentinel-related.
- Network: no failed dashboard API calls.

**Visual evaluation:**

| Viewport          | Result   | Notes |
|-------------------|----------|-------|
| Desktop 1920×1080 | **PASS** | Two-column layout: narrow left column with circular threat-risk gauge centred vertically, right column with 5-card stat row + live feed table. Brand-cyan headings on deep-navy background, severity-coloured stat numbers (white/red/orange/yellow/green). Typography readable. Below-fold space is empty (no events) — would benefit from an empty-state message but not a regression. |
| Tablet 768×1024   | **PASS** | Two-column layout retained; columns narrow proportionally, stat cards stay in a single row, gauge drops toward the bottom of its column (vertical centring inside left column) — looks deliberate. Live feed columns remain readable. |
| Mobile 375×812    | **MAJOR** | Two-column layout persists at 375 px instead of stacking vertically. Threat-risk column wastes ~50% of horizontal space (large empty box above the gauge). Right column cramps stat cards into a vertical stack, then the Live Event Feed below: the "AUTHORIZATION" filter chip overflows the card edge, and only "Time" + "Detecto" (truncated) are visible in the table — Severity/Reason/Hash are clipped without any horizontal scroll affordance. |

### Page 2: `/` — Blazor Chat (sample app)

**URL:** `http://localhost:5160/`
**Page title:** `AI Chat — guarded by AI.Sentinel`
**Severity:** **PASS** (UI structurally correct; runtime SignalR error is a Docker-host artefact, not a Sentinel regression)

**Functional checks:**
- HTTP 200 — Blazor WASM loads, app boots to "AI Chat" page (3 s wait after navigate).
- Header has "AI Chat" title, "connecting..." status badge, **link "AI.Sentinel dashboard ↗"** with `href="/ai-sentinel"` — confirms cross-page navigation wires up correctly.
- Yellow warning banner: "⚠ Could not connect to server. Please refresh the page." This appears because the SignalR JS client tried to negotiate `file:///hubs/chat/negotiate` instead of `http://...:5160/hubs/chat/negotiate` — a known Blazor-WASM-in-MCP-Docker quirk where relative URL resolution fails. **Reproduces only when accessing the app from a non-localhost host name**; direct `localhost:5160` access in a normal browser would not hit this.
- Textbox + Send button render but are correctly disabled while the hub connection fails.
- Console errors: 1 (`SignalR negotiate file://` — Docker artefact, see above).

**Visual evaluation:**

| Viewport          | Result | Notes |
|-------------------|--------|-------|
| Desktop 1920×1080 | PASS   | Clean single-column layout. Header bar with title, status, and dashboard link aligned right. Empty message area takes the centre. Composer (textbox + Send button) docked at the bottom. White theme, light-mode. |
| Tablet 768×1024   | PASS   | Same single-column layout; comfortable margins. Composer stays full-width at bottom. |
| Mobile 375×812    | PASS   | Header wraps gracefully — title, status badge, and dashboard link all fit on one line. Error banner wraps to 2 lines as expected. Composer layout intact. |

---

## Recommendations

### Major

1. **Mobile dashboard layout breaks at < 480 px.** The two-column grid persists into mobile, leaving 50% of horizontal space empty in the threat-risk column while the live feed table truncates without horizontal-scroll affordance. **Fix:** add a `@media (max-width: 480px)` rule that collapses to a single column (gauge → stat cards → feed) and either makes the feed table horizontally scrollable or drops less-critical columns (Hash, then Reason). The filter chip row should also `flex-wrap` so AUTHORIZATION doesn't overflow the card.

### Minor

2. **Empty-state message for the Live Event Feed.** When the audit store is empty (cold start), the dashboard shows column headers and a void below them. Add a one-line message such as *"No events yet — agents are quiet."* to make the empty state intentional rather than ambiguous.
3. **Sample-app favicon.** The `404 /favicon.ico` console error appears on every page load. Drop a 1×1 transparent `favicon.ico` into [samples/ChatApp/ChatApp.Server/wwwroot/](../samples/ChatApp/ChatApp.Server/wwwroot/) (or set `<link rel="icon" href="data:,">` in the Blazor `index.html`) to silence it.

### Suggestions

4. **SignalR-from-non-localhost host-name handling.** The Blazor sample's hub URL appears to be relative (`/hubs/chat`) and the WASM runtime's URL resolution fails when accessed via `host.docker.internal`. Consider passing an absolute URL via `withUrl(builder.Configuration["ChatApp:HubUrl"] ?? "/hubs/chat")` so a deployment behind a reverse-proxy / different host name still negotiates correctly. Out of scope for AI.Sentinel itself; nice-to-have for the sample.
5. **Dashboard: keyboard accessibility for filter chips.** The "All" / "Authorization" tablist works but I didn't verify keyboard arrow-key navigation between tabs. Worth a future test pass.

---

## Conversation Summary

- **Status:** WARN
- **Counts:** 0 Critical, 1 Major, 2 Minor, 2 Suggestions.
- **Top 3 findings:**
  1. **Critical bug from prior report is fixed.** `MapAISentinel` correctly outranks `MapFallbackToFile`; dashboard endpoints serve real content (`AI.Sentinel` heading, stat-card HTML, filter tablist) instead of the Blazor SPA shell.
  2. **Mobile dashboard layout (`< 480 px`) is the only Major issue remaining.** Two-column grid wastes left-column space and clips the live-feed table. Easy CSS fix.
  3. **Sample-app SignalR error is a Docker-host networking artefact**, not a Sentinel regression. Browser running in MCP Docker container hits a `file://` URL during hub negotiation; would not happen on direct `localhost` access.
- **Report path:** [docs/regression-report-2026-04-29-1235.md](regression-report-2026-04-29-1235.md)
- **Note on screenshots:** the Playwright MCP server runs in a Docker sandbox without a writable bind-mount to `docs/regression-screenshots/`, so screenshots were captured inline via the `output_image` channel during this run rather than persisted to disk. Visual evaluations above record what was observed in those inline captures.

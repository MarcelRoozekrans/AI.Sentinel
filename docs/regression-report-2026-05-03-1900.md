# Regression Report — Dashboard 2.0 (PR #42)

## Summary

| Metric                 | Value |
|------------------------|-------|
| Date                   | 2026-05-03 19:00 (local) |
| Application URL        | http://localhost:5160/ai-sentinel/ |
| Branch / HEAD          | feat/dashboard-2.0 @ ec77d0e |
| Pages Tested           | 1 (single-page dashboard) |
| Viewports Tested       | 3 (Desktop 1920×1080, Tablet 768×1024, Mobile 375×812) |
| Color schemes tested   | 2 (auto-light via prefers-color-scheme: light, auto-dark via prefers-color-scheme: dark) |
| Existing Tests Passed  | 727 (630 main + 21 sqlite + 19 epim + 14 asqlite + 11 otel + 29 dsdk + 3 azs) |
| Existing Tests Failed  | 0 |
| Console Errors Found   | 0 |
| Network Errors Found   | 0 (all 280+ polled API calls returned 200 OK) |
| Visual Issues Found    | 2 (1 Critical functional, 1 Major responsive layout) |
| **Overall Status**     | **WARN** — backend/code-level work is solid; client UX has two real correctness/layout bugs |

## Phase 2 — Existing Test Results

| Project                          | net8.0 | net10.0 |
|----------------------------------|--------|---------|
| AI.Sentinel.Tests                | 630/630 | 630/630 |
| AI.Sentinel.Sqlite.Tests         | 21/21  | 21/21   |
| AI.Sentinel.Approvals.EntraPim.Tests | 19/19 | 19/19 |
| AI.Sentinel.Approvals.Sqlite.Tests | 14/14 | 14/14   |
| AI.Sentinel.OpenTelemetry.Tests  | 11/11  | 11/11   |
| AI.Sentinel.Detectors.Sdk.Tests  | 29/29  | 29/29   |
| AI.Sentinel.AzureSentinel.Tests  | 3/3    | 3/3     |
| **Total**                        | **727/727** | **727/727** |

Build: 0 warnings, 0 errors. AOT IL/trim probe was clean (native link blocked locally on missing vswhere.exe — CI handles it).

## Phase 3 — Browser-based testing

### Setup

- Started `samples/ChatApp/ChatApp.Server` with `Demo__SeedDashboard=true`.
- Extended `DashboardDemoSeed` to use the new SEC-/HAL-/OPS-/AUTHZ- prefixes (so the new chips actually filter) and a mix of `sess-alpha` / `sess-beta` / `null` SessionIds (so per-session drill-down has click targets).
- 12 audit entries seeded across the 4 categories.

### Functional checks

| Feature | Status | Notes |
|---|---|---|
| Page loads + title | ✅ | "AI.Sentinel Dashboard" rendered, no errors |
| Console errors | ✅ | 0 errors, 0 warnings across the entire session |
| API calls | ✅ | `/api/feed`, `/api/stats`, `/api/trend`, `/api/approvals` all return 200; polled hundreds of times without failure |
| Stats panel | ✅ | 12 Total / 2 Critical / 3 High / 4 Medium / 3 Low — exact match to seeded entries |
| TRS gauge | ✅ | "80 ISOLATE" with red arc — appropriate for the seeded severity mix |
| 5 chips render | ✅ | All / Security / Hallucination / Operational / Authorization with correct accent colours when active (red/amber/blue/orange) |
| Search input | ✅ | Renders, accepts input, debounces |
| Session column | ✅ | Truncates to 8 chars (`sess-alp`/`sess-bet`), shows `—` for null sessions, dotted underline on links |
| Trend chart SVG | ✅ | Inline `<svg role="img" aria-label="Severity trend, last 15 minutes">`, stroke colour = red (Critical) per Phase 3 palette |
| Export button | ✅ | 📥 Export, right-aligned, anchor href `api/export.ndjson` |
| Pending Approvals | ✅ | Empty-state "No approval store configured" rendered |
| **Chip click → URL update** | ✅ | URL gains `?filter=security`, body.dataset and exportLink.href both sync |
| **Search input → URL update** | ✅ | 300ms debounce, URL gains `?q=jailbreak`, all derived state stays in sync |
| **Session-link click → URL + pill** | ✅ | URL gains `?session=sess-alpha`, pill renders `Filtering session: sess-alpha ✕ clear`, body.dataset.session set |
| **Pill ✕ clear** | ✅ | URL drops `?session=`, body.dataset cleared, pill removed |
| **Export href stays in sync** | ✅ | After chips ∧ session ∧ search filter, export href = `api/export.ndjson?filter=security&q=jailbreak&session=sess-alpha` — deep-linkable |
| **Server-side `/api/feed?filter=security&q=jailbreak&session=sess-alpha`** | ✅ | Returns "No events match this filter" — correct intersection |
| **Server-side `/api/feed?filter=authz` (legacy URL)** | ✅ | Returns AUTHZ-DENY rows — backwards-compat preserved |

### Visual evaluation per viewport

#### Desktop (1920×1080) — light mode

![](regression-screenshots/2026-05-03-1900/dashboard-desktop.png)

- Layout: clean grid, panels well-spaced
- Spacing: balanced; chips bar has comfortable gaps
- Typography: legible at all sizes
- Color: severity badges (critical=red, high=orange, medium=amber, low=green) carry the eye correctly; AUTHZ row has subtle orange left-border highlight
- Session column dotted-underline links read clearly
- Trend chart spans the full width, axis labels positioned
- Export button right-aligned with `margin-left: auto` (Phase 4+5 polish fix verified)

**Severity: Pass.**

#### Desktop (1920×1080) — light mode — **filtered state** (Security ∧ "jailbreak" ∧ sess-alpha)

![](regression-screenshots/2026-05-03-1900/dashboard-desktop-filtered.png)

- Active Security chip has red border + light red text (chip-security accent ✓)
- Search box shows "jailbreak"
- Session pill renders with light-blue background and `✕ clear` button
- **However:** the table CONTENT shows all 12 rows, contradicting the URL/pill state. Polled `/api/feed` calls in the network log confirm HTMX is still fetching the unfiltered URL every 2 seconds. See **Critical C1** below.

**Severity: Pass on chrome / Critical on data behaviour (see C1).**

#### Desktop (1920×1080) — dark mode (`prefers-color-scheme: dark` emulated)

![](regression-screenshots/2026-05-03-1900/dashboard-desktop-dark.png)

- Slate-900 bg, slate-800 panels, slate-100 text (the base `:root` palette)
- Severity colours preserved (chip accents, badges, trend stroke unchanged)
- Search input shows dark slate with light text
- Phase 4 dark mode works exactly as designed when OS reports dark scheme

**Severity: Pass.**

#### Tablet (768×1024) — light mode

![](regression-screenshots/2026-05-03-1900/dashboard-tablet.png)

- Chips bar wraps to 2 rows (chips on row 1, AUTHZ + search + Export on row 2)
- Hash column hidden via existing `@media (max-width: 600px)` — actually 768px is above the breakpoint so Hash should be visible. **Inconsistency:** Hash column appears omitted from the rendered table at 768px, but the breakpoint is 600px. Worth verifying which column drops out and at what width.
- TRS gauge centred in left column, properly sized
- Reason cell text wraps inside the column — readable but consumes vertical space

**Severity: Pass with one inconsistency (Hash visibility at 768px deserves a double-check).**

#### Tablet (768×1024) — dark mode

![](regression-screenshots/2026-05-03-1900/dashboard-tablet-dark.png)

- Same layout as light tablet, dark palette correctly applied
- **Minor:** session column truncated by horizontal scroll within the table-wrap container at this viewport — table content wider than its panel. Visible scrollbar at the bottom of the table area. Borderline acceptable for tablet; would be a Major on mobile.

**Severity: Pass with minor horizontal-scroll observation.**

#### Mobile (375×812) — light mode (and dark)

![](regression-screenshots/2026-05-03-1900/dashboard-mobile.png)

**Major layout breakage** — see **Major M1** below. The 200px fixed left grid column from the desktop layout (`main { grid-template-columns: 200px 1fr }`) does not collapse on narrow viewports. Result:

- TRS panel (Threat Risk Score) is squashed into a ~30px-wide column; "THREAT RISK SCORE" wraps into "THREA / RISK / SCORE", gauge clipped on both sides
- Live Event Feed panel is also clipped to ~30px; chips render as single letters stacked vertically; search, trend chart, and table are completely cut off
- Stats and Pending Approvals panels render correctly because they use the right-side `1fr` column

The same bug appears identically in dark mode (`dashboard-mobile-dark.png`). Dashboard is **unusable** on phone-class viewports.

**Severity: Major.**

## Issues found

### Critical

**C1. HTMX 2-second poll uses stale unfiltered URL — defeats the URL-state-as-SoT design.**

The `refreshFeed()` function (added in Phase 2.4, hardened in Phase 2 polish) does:

```javascript
function refreshFeed() {
  syncUrlFromState();
  const url = buildFeedUrl();
  feedBody.setAttribute('hx-get', url);                                                  // ← updates attribute
  if (window.htmx) { window.htmx.ajax('GET', url, { target: '#feed-body', swap: 'innerHTML' }); }  // ← fires immediate request
}
```

The `htmx.ajax(...)` call fires the immediate filtered request correctly (verified in network log: `/api/feed?filter=security&q=jailbreak&session=sess-alpha` was sent). But the table reverts on the next 2-second poll because **HTMX caches the parsed `hx-trigger="load, every 2s"` configuration when the page loads and does not re-parse it when the `hx-get` attribute is changed via `setAttribute`.** All polled requests in the log show `/api/feed` (no query string) regardless of how many times `setAttribute('hx-get', ...)` is called.

**User-visible symptom:** operator clicks Security chip → URL updates → pill appears → table briefly shows filtered results → 2 seconds later the next poll arrives with all 12 rows again. The URL says one thing, the visible data says another. The "fully shareable URL state" promise is broken in steady-state.

**Verification:**
- Network log shows requests #183 / #200 / #214 with the filtered query string (the immediate `htmx.ajax` calls)
- Every other `/api/feed` request in the log (the polls) has no query string
- Server-side `/api/feed?filter=security&q=jailbreak&session=sess-alpha` correctly returns the empty-message row

**Fix candidates** (any one):
1. Call `htmx.process(feedBody)` after `setAttribute('hx-get', url)` so HTMX re-reads the changed attribute
2. Stop the polling trigger and re-arm it after each filter change
3. Use a `htmx:configRequest` event listener that rewrites the request URL based on current state (cleanest — single source of truth at request time)
4. Drop the `setAttribute` and instead build the URL inside `htmx:configRequest` from the live state

Option 3 is the smallest, lowest-risk change.

### Major

**M1. Mobile (375px) layout breaks completely — 200px fixed sidebar doesn't collapse.**

The `main` element uses `display: grid; grid-template-columns: 200px 1fr` unconditionally. There's a `@media (max-width: 600px)` block in `sentinel.css` but it only adjusts `.feed-chips { gap: 0.3rem }` — it never collapses the grid to a single column.

**User-visible symptom:** on phone-class viewports the TRS panel and Live Event Feed are squashed into a ~30px column, completely unusable. Stats and Pending Approvals (right column) render fine.

**Fix:** add to the existing `@media (max-width: 600px)` block (or a new `@media (max-width: 768px)` if tablet should also stack):

```css
@media (max-width: 600px) {
  main {
    grid-template-columns: 1fr;   /* collapse to single column */
    height: auto;                  /* let content scroll naturally */
  }
  .trs-panel { grid-row: auto; }  /* don't span 2 rows on mobile */
}
```

Verify the trend chart, session pill, and Pending Approvals all re-flow correctly afterwards. The chips bar already wraps responsively (Phase 2 work) so should remain fine.

### Minor

**Mn1. Tablet (768px) Hash column visibility looks off.**

The tablet screenshot shows only 5 columns (Time / Detector / Severity / Reason / Session) but the existing breakpoint that hides the Hash column is `@media (max-width: 600px)`. At 768px the Hash column should be visible. Either the breakpoint was bumped recently and not noticed, or the table-wrap is overflowing horizontally and the Hash column is scrolled off-screen. Worth a quick check of the actual `.feed-table th:nth-child(N)` rules vs current viewport.

**Mn2. Tablet (768px) horizontal scroll inside table panel.**

The `.table-wrap` shows a horizontal scrollbar at 768px in dark mode (visible in `dashboard-tablet-dark.png` at the bottom of the table area). The Reason column wraps text aggressively and Session is partially obscured by the scroll. Could either reduce a column's min-width or hide one more column at this viewport.

**Mn3. Light-mode session-pill background-pill colour:**
The pill uses `background: rgba(125, 211, 252, 0.08)` which is mostly transparent; in light mode it appears as a faint white-blue tint. Hard to spot at a glance. Consider increasing alpha or switching to a token that flips with the palette.

### Suggestions

- **S1.** Add a server-rendered smoke test that `index.html` includes `htmx.process` (or whichever fix lands for C1) so a future cleanup can't silently regress the polling semantics.
- **S2.** Consider a sample-app `Demo:SeedDashboardWithSessions=true` config flag so future regression runs don't need to edit `Program.cs` — could be checked in alongside the existing seed.
- **S3.** Explicit `<svg>` role/aria-label was added in Phase 3 polish for the trend chart. The TRS gauge SVG (lines 25-30 of index.html) doesn't have one — it announces only "0 SAFE" or "80 ISOLATE" with no context. Worth adding `role="img" aria-label="Threat risk score: <value>, stage <stage>"` (would need a JS update on each SSE message).

## Conclusion

Backend / data-layer work in PR #42 is genuinely solid: 727 tests pass, schema migration is safe, all server-side filtering / export / trend correctness bugs caught in code-review pre-merge are fixed. Light + dark themes both work correctly when the browser opts into the matching `prefers-color-scheme`.

However, the **client-side UX has one Critical bug (htmx-polling-stale-URL) and one Major responsive bug (mobile layout)** that should be fixed before merge, or before tagging 1.8.0. The Critical especially undermines the entire URL-as-source-of-truth design that Phase 2 set up.

Both fixes are small (one JS line for C1, one CSS block for M1) and bundle naturally per the in-cycle polish rule.

---

## Addendum: Fixes applied (same session)

All three findings (C1, M1, Mn1/Mn2 tablet) were fixed in-cycle and re-verified before commit:

- **C1 (htmx polling)** — added a `htmx:configRequest` event listener in `index.html` that rewrites every request originating from `#feed-body` to use `buildFeedUrl()` at request time. The 2-second poll now inherits current filter state (chip + search + session) instead of the stale `hx-get` attribute parsed at page-init. **Verified:** clicked Security chip, waited 5 seconds (2 polls), table held at 6 SEC-* rows — no revert.

- **M1 (mobile layout)** — root cause was `.approvals-panel { grid-column: 2 }` defined AFTER the `@media (max-width: 600px)` block, so source-order cascade made the base rule win regardless of the media-query override. CSS Grid then created an implicit second column for approvals, into which auto-placed `.stats-panel` and `.trs-panel` were pulled, squeezing the explicit `1fr` column to ~30 px. Fix: moved the `grid-column: 2` placements to BEFORE the media block (grouped with `.feed-panel`), and added a `.trs-panel, .stats-panel, .feed-panel, .approvals-panel { grid-column: 1; grid-row: auto }` override inside the `@media (max-width: 600px)` block. **Verified:** all 4 panels now report `grid-column: 1` and width 328 px at the 375 px viewport.

- **Mn1/Mn2 (tablet)** — added `@media (max-width: 900px) { main { grid-template-columns: 160px 1fr; } table th:nth-child(6), table td:nth-child(6) { display: none } .gauge { width: 130px } }`. Hash column drops out at intermediate widths (it was diagnostic-only; full hash is in `/api/feed`) and the TRS sidebar shrinks to 160 px so the feed table fits without intra-panel horizontal scroll. **Verified:** at 768 px the table now renders cleanly within `.table-wrap`.

Suite still 630/630 on both `net8.0` and `net10.0`. No backend tests touched.

**New visual baseline:** see `docs/assets/screenshots/dashboard-{desktop,desktop-dark,desktop-filtered,tablet,mobile}.png` — these are the polished screenshots used in the README and Docusaurus site as of 1.8.0.

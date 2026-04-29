# Dashboard Regression Report — 2026-04-29 14:00

## Summary

| Metric                 | Value   |
|------------------------|---------|
| Date                   | 2026-04-29 14:00 |
| Application            | AI.Sentinel embedded dashboard via [ChatApp.Server](../samples/ChatApp/ChatApp.Server/Program.cs) |
| URL                    | `http://localhost:5160/ai-sentinel` |
| Pages Tested           | 1 (mount point only — endpoints unreachable) |
| Viewports Attempted    | Desktop 1920×1080 (others skipped — no dashboard to render) |
| Existing Tests Passed  | 10 / 10 ([AspNetCore middleware tests](../tests/AI.Sentinel.Tests/AspNetCore/)) |
| Existing Tests Failed  | 0 |
| Console Errors Found   | 0 (Blazor SPA loads cleanly; dashboard never reached) |
| Network Errors Found   | 0 (every request returns 200 with Blazor index) |
| Visual Issues Found    | n/a — dashboard does not render |
| Overall Status         | **FAIL** |

---

## Critical Finding: Dashboard endpoints unreachable in `WebApplication` + Blazor WASM hosts

### Symptom

In the [ChatApp.Server sample](../samples/ChatApp/ChatApp.Server/Program.cs), every path under `/ai-sentinel/*` (including `/`, `/api/stats`, `/api/feed`, `/api/trs`, `/static/dashboard.css`) returns **HTTP 200** with the Blazor WASM `index.html`. The Blazor router then renders **"Not Found — Sorry, the content you are looking for does not exist."** client-side.

### Root cause

[ApplicationBuilderExtensions.cs:20-34](../src/AI.Sentinel.AspNetCore/ApplicationBuilderExtensions.cs#L20-L34) wraps the dashboard in `app.Map(pathPrefix, branch => { branch.UseRouting(); branch.UseEndpoints(...) })`. In a `WebApplication` host, `app.UseRouting()` is auto-injected at the first `MapXxx` call **at the root pipeline level**, and `MapFallbackToFile("index.html")` ([Program.cs:58](../samples/ChatApp/ChatApp.Server/Program.cs#L58)) registers a catch-all endpoint on that root dataset. The catch-all fallback wins at routing time before the request ever enters the `Map` branch.

This pattern works in `HostBuilder + UseTestServer` scenarios (the existing dashboard tests) because no `MapFallbackToFile` is registered there to compete.

### Evidence

- **All 10 [AspNetCore tests](../tests/AI.Sentinel.Tests/AspNetCore/) pass on `net8.0` and `net10.0`** — middleware mounts and serves correctly under `HostBuilder + UseTestServer`.
- **Live `curl` against ChatApp.Server** returned `<!DOCTYPE html>` of the Blazor index for every probed path under `/ai-sentinel/*`.
- **Browser load** of `http://host.docker.internal:5160/ai-sentinel` rendered the Blazor "Not Found" page after WASM bootstrap.

### Severity

**Critical.** The dashboard ships as a key feature of `AI.Sentinel.AspNetCore`. Any consumer wiring it into a Blazor WASM / SPA host (the most common ASP.NET Core hosting pattern in 2026) gets a silently broken integration.

### Suggested fix

Replace `app.Map(prefix, branch => branch.UseRouting().UseEndpoints(...))` with direct top-level endpoint registration so dashboard routes participate in normal endpoint matching and outrank the fallback by route specificity:

```csharp
public static IEndpointRouteBuilder MapAISentinel(
    this IEndpointRouteBuilder endpoints,
    string pathPrefix = "/ai-sentinel")
{
    var group = endpoints.MapGroup(pathPrefix);
    group.MapGet("/",            DashboardHandlers.IndexAsync);
    group.MapGet("/api/stats",   DashboardHandlers.StatsAsync);
    group.MapGet("/api/feed",    DashboardHandlers.LiveFeedAsync);
    group.MapGet("/api/trs",     DashboardHandlers.TrsStreamAsync);
    group.MapGet("/static/{file}", DashboardHandlers.StaticFileAsync);
    return group;
}
```

Caller wires it as `app.MapAISentinel("/ai-sentinel").RequireAuthorization(...)` instead of `app.UseAISentinel(...)`. This naturally composes with `MapFallbackToFile`, `RequireAuthorization`, rate-limit policies, and CORS — without a side branch.

The current `UseAISentinel(...)` extension can be retained as a thin wrapper that calls `app.MapAISentinel(...)` for backwards-compatible callers, with a doc note that it must be invoked **before** any `MapFallback*` call.

---

## Existing Test Results

```
$ dotnet test tests/AI.Sentinel.Tests/ --filter "FullyQualifiedName~AspNetCore"
Passed!  - Failed: 0, Passed: 10, Skipped: 0, Total: 10  (net8.0, 860 ms)
Passed!  - Failed: 0, Passed: 10, Skipped: 0, Total: 10  (net10.0, 862 ms)
```

The 10 passing tests cover authentication composition, authz blocking, static-file allowlisting, and audit feed projection. They prove the **handlers** are correct. The bug is in **how `UseAISentinel` integrates with the host's endpoint pipeline**, which the tests don't exercise.

---

## Recommendations (prioritised)

1. **Critical** — Refactor `UseAISentinel` to register on the host's endpoint route builder (`MapAISentinel`) rather than wrapping in `app.Map`. Add a regression test that builds a `WebApplication` with both `MapAISentinel` and `MapFallbackToFile`, then asserts `/ai-sentinel/api/stats` returns dashboard JSON, not the fallback file.
2. **Major** — Add an integration test sample covering Blazor WASM + dashboard composition (mirrors the ChatApp.Server scenario).
3. **Minor** — Document the `MapFallback*` ordering hazard in [website/docs/integrations/aspnetcore.md](../website/docs/integrations/aspnetcore.md) until the refactor lands.

---

## Status

- Background ChatApp.Server (PID 71156) **stopped**.
- Existing AspNetCore tests **green**.
- Visual regression at additional viewports **skipped** — there is nothing to render until the mount bug is fixed.
- Fix should follow as a separate change, scoped per recommendation 1.

---

## Verification — fix landed (2026-04-29 12:32)

The Critical finding above has been resolved.

**Code changes:**
- [src/AI.Sentinel.AspNetCore/ApplicationBuilderExtensions.cs](../src/AI.Sentinel.AspNetCore/ApplicationBuilderExtensions.cs) — added `MapAISentinel(this IEndpointRouteBuilder, string)` returning `RouteGroupBuilder`. `UseAISentinel` retained for back-compat with a doc note about the `MapFallback` ordering hazard.
- [tests/AI.Sentinel.Tests/AspNetCore/DashboardMapAISentinelTests.cs](../tests/AI.Sentinel.Tests/AspNetCore/DashboardMapAISentinelTests.cs) — 5 new tests proving dashboard endpoints win over `MapFallback` and unmapped paths under the prefix correctly fall through.
- [samples/ChatApp/ChatApp.Server/Program.cs:52](../samples/ChatApp/ChatApp.Server/Program.cs#L52) — switched from `app.UseAISentinel(...)` to `app.MapAISentinel(...)`.

**Test results:** 520 / 520 passing on `net8.0` and `net10.0`.

**Live verification:**

| Endpoint                          | Before fix              | After fix                                |
|-----------------------------------|-------------------------|------------------------------------------|
| `GET /ai-sentinel/`               | 200 (Blazor SPA shell)  | 200 (dashboard HTML — `AI.Sentinel` heading) |
| `GET /ai-sentinel/api/stats`      | 200 (Blazor SPA shell)  | 200 (5 `<div class="stat-card">` rows)   |
| `GET /` (root SPA)                | 200 (Blazor)            | 200 (Blazor — unchanged)                 |
| `GET /some-other-spa-route`       | 200 (Blazor fallback)   | 200 (Blazor fallback — unchanged)        |

**Visual regression — dashboard rendering at 3 viewports:**

| Viewport            | Result                                                                                                  |
|---------------------|---------------------------------------------------------------------------------------------------------|
| Desktop 1920×1080   | Pass — clean two-column layout: threat-risk gauge left, 5 stat cards + live event feed right.           |
| Tablet 768×1024     | Pass — gauge column narrows, stat cards stay in a single row above the feed.                            |
| Mobile 375×812      | Functional but cramped — "Detector" column header truncates to "Detecto"; the Authorization filter chip overflows the feed card. Worth a follow-up tweak (see below). |

**Console errors:** 1 — `404 /favicon.ico`. Benign; sample app simply doesn't ship a favicon.

**Follow-up (Minor):** Improve mobile layout under 400 px wide — the dual-column threat-risk + content arrangement wastes vertical space and clips the live-feed table headers. Consider stacking single-column on `< 480 px` and making the filter chip row scroll horizontally rather than overflowing.

---

## Final Status

- Critical bug **resolved**.
- Dashboard reachable, rendering, and serving live audit data on all three viewports.
- One Minor follow-up identified (mobile layout polish).

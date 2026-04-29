using System.ClientModel;
using Microsoft.Extensions.AI;
using OpenAI;
using AI.Sentinel;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using ChatApp.Server.Hubs;

var builder = WebApplication.CreateBuilder(args);

// ── OpenRouter config ────────────────────────────────────────────────────────
var apiKey  = builder.Configuration["OpenRouter:ApiKey"]
              ?? throw new InvalidOperationException("OpenRouter:ApiKey is required.");
var model   = builder.Configuration["OpenRouter:Model"]
              ?? "nvidia/llama-3.3-nemotron-super-49b-v1";
var baseUrl = builder.Configuration["OpenRouter:BaseUrl"]
              ?? "https://openrouter.ai/api/v1";

// ── AI.Sentinel config ───────────────────────────────────────────────────────
static SentinelAction ParseAction(string? value, SentinelAction fallback) =>
    Enum.TryParse<SentinelAction>(value, ignoreCase: true, out var a) ? a : fallback;

builder.Services.AddAISentinel(opts =>
{
    opts.OnCritical = ParseAction(builder.Configuration["AISentinel:OnCritical"], SentinelAction.Quarantine);
    opts.OnHigh     = ParseAction(builder.Configuration["AISentinel:OnHigh"],     SentinelAction.Alert);
    opts.OnMedium   = ParseAction(builder.Configuration["AISentinel:OnMedium"],   SentinelAction.Log);
    opts.OnLow      = ParseAction(builder.Configuration["AISentinel:OnLow"],      SentinelAction.Log);
    // To enable semantic (language-agnostic) detection, set an embedding provider:
    // opts.EmbeddingGenerator = new OpenAIEmbeddingGenerator(new OpenAIClient(...), "text-embedding-3-small");
});

builder.Services.AddChatClient(svp =>
    new ChatClientBuilder(
        new OpenAIClient(
            new ApiKeyCredential(apiKey),
            new OpenAIClientOptions { Endpoint = new Uri(baseUrl) })
        .GetChatClient(model)
        .AsIChatClient())
    .UseAISentinel()
    .Build(svp));

// ── SignalR ──────────────────────────────────────────────────────────────────
builder.Services.AddSignalR();

var app = builder.Build();

// ── Blazor WASM hosting ──────────────────────────────────────────────────────
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

// ── AI.Sentinel dashboard ────────────────────────────────────────────────────
app.MapAISentinel("/ai-sentinel");

// ── SignalR hub ──────────────────────────────────────────────────────────────
app.MapHub<ChatHub>("/hubs/chat");

// ── Fallback to Blazor WASM index.html for client-side routing ───────────────
app.MapFallbackToFile("index.html");

// ── Demo seeding ─────────────────────────────────────────────────────────────
// Set Demo__SeedDashboard=true (env) or "Demo:SeedDashboard": true (config) to
// pre-populate the audit store on startup with a curated set of detections.
// Useful for demos, screenshots, and getting a feel for the dashboard before
// wiring up a real chat client.
if (app.Configuration.GetValue("Demo:SeedDashboard", defaultValue: false))
{
    var store = app.Services.GetRequiredService<IAuditStore>();
    await DashboardDemoSeed.AppendAsync(store, CancellationToken.None);
}

app.Run();

internal static class DashboardDemoSeed
{
    public static async Task AppendAsync(IAuditStore store, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var seeds = new (Severity Sev, string Detector, string Summary, int SecondsAgo)[]
        {
            (Severity.Critical, "PROMPT-INJECTION", "User attempted to override system prompt with 'ignore previous instructions'", 12),
            (Severity.High,     "JAILBREAK",        "DAN-style role-play request detected — asking model to act without safety constraints", 34),
            (Severity.High,     "CRED-EXPOSURE",    "Model response contained a sequence resembling an OpenAI API key (sk-...)", 47),
            (Severity.Medium,   "DATA-EXFIL",       "Suspicious external URL in tool-call arguments (raw.githubusercontent.com)", 68),
            (Severity.Medium,   "TOOL-POISONING",   "Tool description metadata contained zero-width Unicode characters", 95),
            (Severity.Low,      "PHANTOM-CITATION", "Cited paper 'Smith et al. 2024' did not appear in retrieved context", 121),
            (Severity.High,     "AUTHZ-DENY",       "Tool call 'read_secrets' rejected — agent lacks required scope", 142),
            (Severity.Critical, "PRIV-ESCALATION",  "Model attempted to invoke admin-only tool from a guest session", 168),
            (Severity.Medium,   "INDIRECT-INJECT",  "Retrieved document contained instructions targeting the agent", 201),
            (Severity.Low,      "BLANK-RESPONSE",   "Empty assistant turn after non-trivial prompt — possible model failure", 245),
            (Severity.Medium,   "AUTHZ-DENY",       "Resource read on /etc/shadow blocked by policy", 290),
            (Severity.Low,      "REPETITION-LOOP",  "Same 4-token sequence repeated 8 times in streamed response", 340),
        };

        string? prevHash = null;
        for (int i = 0; i < seeds.Length; i++)
        {
            var s = seeds[i];
            var hash = $"{(uint)HashCode.Combine(s.Detector, s.Summary, i):x8}{i:x8}";
            await store.AppendAsync(new AuditEntry(
                Id:           Guid.NewGuid().ToString("N"),
                Timestamp:    now.AddSeconds(-s.SecondsAgo),
                Hash:         hash,
                PreviousHash: prevHash,
                Severity:     s.Sev,
                DetectorId:   s.Detector,
                Summary:      s.Summary), ct).ConfigureAwait(false);
            prevHash = hash;
        }
    }
}

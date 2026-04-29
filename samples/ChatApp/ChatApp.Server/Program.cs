using System.ClientModel;
using Microsoft.Extensions.AI;
using OpenAI;
using AI.Sentinel;
using AI.Sentinel.AspNetCore;
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

app.Run();

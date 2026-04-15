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

// ── CORS (for Blazor WASM dev server on a different port) ────────────────────
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins("https://localhost:7001", "http://localhost:5001")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials()));

var app = builder.Build();

app.UseCors();
app.UseStaticFiles();

// ── AI.Sentinel dashboard ────────────────────────────────────────────────────
app.UseAISentinel("/ai-sentinel");

// ── SignalR hub ──────────────────────────────────────────────────────────────
app.MapHub<ChatHub>("/hubs/chat");

app.Run();

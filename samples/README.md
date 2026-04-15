# AI.Sentinel Samples

Two runnable samples that demonstrate AI.Sentinel with [OpenRouter](https://openrouter.ai/)
using the `nvidia/llama-3.3-nemotron-super-49b-v1` model.

## Prerequisites

- .NET 10 SDK (`10.0.104` or later)
- An [OpenRouter](https://openrouter.ai/) API key

---

## ConsoleDemo

A terminal chat loop. Type a message, get a streaming response.
AI.Sentinel watches every turn; blocked prompts print a red `[BLOCKED]` banner.

### Run

```bash
cd samples/ConsoleDemo
cp appsettings.json appsettings.local.json   # create your local override (git-ignored)
# edit appsettings.local.json and fill in your API key
dotnet run
```

Or pass the key via environment variable (no file editing needed):

```bash
OpenRouter__ApiKey=sk-or-… dotnet run --project samples/ConsoleDemo
```

### Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `OpenRouter:ApiKey` | *(required)* | Your OpenRouter API key |
| `OpenRouter:Model` | `nvidia/llama-3.3-nemotron-super-49b-v1` | Model identifier |
| `OpenRouter:BaseUrl` | `https://openrouter.ai/api/v1` | API base URL |
| `AISentinel:OnCritical` | `Quarantine` | Action on Critical detections |
| `AISentinel:OnHigh` | `Alert` | Action on High detections |
| `AISentinel:OnMedium` | `Log` | Action on Medium detections |
| `AISentinel:OnLow` | `Log` | Action on Low detections |

---

## ChatApp

A Blazor WebAssembly chat app hosted by an ASP.NET Core server.
The server streams AI responses over a SignalR hub. The AI.Sentinel
dashboard is available at `/ai-sentinel`.

### Run

```bash
cd samples/ChatApp/ChatApp.Server
cp appsettings.json appsettings.local.json   # create your local override (git-ignored)
# edit appsettings.local.json and fill in your API key
dotnet run
```

Or via environment variable:

```bash
OpenRouter__ApiKey=sk-or-… dotnet run --project samples/ChatApp/ChatApp.Server
```

Then open the URL printed in the console (e.g. `https://localhost:7000`).

Visit `/ai-sentinel` on the same origin to see the live dashboard.

### Configuration

Same keys as ConsoleDemo above.

### Sentinel string protocol

The SignalR hub signals special conditions by prefixing a token with a NUL byte (`\0`):

| Token | Meaning |
|-------|---------|
| `\0BLOCKED:<reason>` | AI.Sentinel blocked the request |
| `\0ERROR` | An unexpected server-side error occurred |

The Blazor client renders these with distinct visual styles (red / amber).

---

## Customising sentinel behaviour

Edit the `AISentinel` section in `appsettings.json` (or your local override):

```json
"AISentinel": {
  "OnCritical": "Quarantine",
  "OnHigh":     "Alert",
  "OnMedium":   "Log",
  "OnLow":      "Log"
}
```

Available actions: `PassThrough`, `Log`, `Alert`, `Quarantine`.

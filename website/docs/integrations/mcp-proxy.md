---
sidebar_position: 3
title: MCP proxy
---

# MCP proxy

`AI.Sentinel.Mcp` + `AI.Sentinel.Mcp.Cli` is a stdio Model Context Protocol proxy. It scans `tools/call` and `prompts/get` for any MCP-speaking host (Cursor, Continue, Cline, Windsurf, Copilot's MCP mode).

```bash
dotnet tool install -g AI.Sentinel.Mcp.Cli
```

Wire your MCP host to the proxy instead of the upstream MCP server. The proxy handles transport (stdio / streamable-http / SSE) automatically.

```bash
ai-sentinel-mcp proxy --target=stdio:///path/to/upstream-mcp-server
```

The proxy preserves MCP semantics (initialize / capabilities / cancellation) while injecting AI.Sentinel scanning between client and server.

> Full MCP proxy guide — transport modes (`AutoDetect`, stdio, http, sse), graceful shutdown, audit destination, JSON-RPC error mapping — coming soon.

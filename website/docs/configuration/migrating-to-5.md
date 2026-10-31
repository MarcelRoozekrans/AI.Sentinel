---
sidebar_position: 5
title: Migrating to 5.0
---

# Migrating to 5.0

5.0 ships `sentinel-hook`, `sentinel-copilot-hook` and `sentinel-mcp` as Native AOT builds. Their tool packages are now .NET 10 RID-specific tools, so the install needs the .NET 10 SDK. The libraries and `AI.Sentinel.Cli` are unchanged and still target net8.0.

## The hook and MCP CLIs need the .NET 10 SDK

`AI.Sentinel.ClaudeCode.Cli`, `AI.Sentinel.Copilot.Cli` and `AI.Sentinel.Mcp.Cli` target net10.0 only. On linux-x64, linux-arm64, osx-arm64 and win-x64, `dotnet tool install` and `dotnet tool update` install the Native AOT build, which needs no .NET runtime at all. Other platforms get a framework-dependent build that runs on the .NET 10 runtime.

**What breaks:** on a machine with only the .NET 8 SDK, `dotnet tool install` and `dotnet tool update` fail for these three packages.

**What to do:** pick one of these.

- Install the .NET 10 SDK, then run `dotnet tool update -g` for each package as before.
- Use the release binary, which needs no .NET at all. See [Native binary without the .NET SDK](../integrations/claude-code#native-binary-without-the-net-sdk).

Hook commands in `settings.json` and `hooks.json` don't change: the command names are the same.

## A local AOT publish is no longer needed

If you published the hooks with `-p:PublishAot=true` yourself to get a fast start, switch to the tool package or the release binary. For other platforms, the `dotnet publish` recipe still works; drop `-f net10.0`, since the CLIs now have a single target framework.

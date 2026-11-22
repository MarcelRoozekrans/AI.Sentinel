# Spike: local Rego evaluation under Native AOT (#633) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove which route lets a Native AOT hook evaluate Rego locally, fast and offline, and that Rego compiles without separate OPA tooling, on Windows, Linux and macOS.

**Issue:** #633, milestone "Controlled from a central server". Depends on nothing.

**Spec:** Outline document `6888019f-3202-4ea3-93a7-213cc8811bf0` ("AI.Sentinel: be controlled from Themis.NET") and its approved design, Outline document `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91` ("AI.Sentinel: central server control, design", Status: approved). Read both with the Outline connector before writing code. Where they differ, the design wins. The decisions are also on GitHub in the closing comments of #653 and #657.

## Global Constraints

- Read `AGENTS.md` and the product-line standards it links before changing anything.
- A failing test first for every behaviour change; see it fail before writing the code.
- One commit per task, Conventional Commits. No `Co-Authored-By` trailer, no "Generated with" line, no session links, no nested parentheses in a commit body.
- Every new setting is optional and off by default. With none of the new settings, AI.Sentinel behaves exactly as before (Spec AC 8): the existing test suite passes unchanged.
- New public API is approved only when it is additive, optional, off by default and asked for by the Spec or the design. A breaking change, or API outside that scope, is a step to park.
- Native AOT: the hook CLIs and any new tool build and publish without trimming or AOT warnings. No runtime reflection.
- `TreatWarningsAsErrors` is on. Do not add or widen a suppression.
- New tests go in `tests/AI.Sentinel.Tests` under the test class names this plan gives, so the checks below find them.
- Run `dotnet format whitespace . --folder --verify-no-changes` before each push.
- The PR body says `Closes #633` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- Three routes are tried in one Native AOT console app against the same sample policy and inputs: an `opa build -t wasm` module run by a .NET WebAssembly runtime, OPA as a separate local process, and a Rego engine written in .NET if one is complete enough.
- Compiling Rego without separate OPA tooling is tried, for example with the interop compiler of OpaDotNet.
- For each route: AOT and trim warnings, decision time p50 and p95 cold and warm, added binary size, and missing Rego features.
- The chosen route, and the compiler if used, build and run on Windows, Linux and macOS, shown by CI.
- Builtins that reach outside the process (`http.send`, `net.lookup_ip_addr`, `opa.runtime`) are refused or absent on the chosen route.
- The outcome is written to `docs/plans/2026-11-22-rego-aot-spike.md`, naming the chosen route or stating that none works, with the cold p95 of the chosen route stated as a number of milliseconds.

## Tasks

### Task 1: Spike app skeleton

- [ ] Create `spikes/RegoAot/RegoAot.csproj`, a `net10.0` console app with `PublishAot=true`, outside `AI.Sentinel.slnx`, with its own `Directory.Build.props` if the repo one gets in the way.
- [ ] Add `spikes/RegoAot/policy/sample.rego` in package `sentinel` with a `deny` rule on tool name and an argument, `require_approval` and `severity_actions`, matching the contract in the design.
- [ ] Add `spikes/RegoAot/inputs/*.json` with at least six tool-call inputs and their expected decisions.
- [ ] Add a `--check` mode that evaluates every input on every available route and exits non-zero when a decision differs from the expected one.
- [ ] Commit.

### Task 2: WebAssembly route

- [ ] Build the module with `opa build -t wasm` and run it with a .NET WebAssembly runtime such as OpaDotNet.Wasm or Wasmtime.
- [ ] Measure p50 and p95, cold (new process) and warm, over at least 200 runs each; record binary size added.
- [ ] Commit.

### Task 3: OPA process route

- [ ] Run OPA as a local server process and query it from the app; measure the same numbers, counting OPA's own startup for cold.
- [ ] Commit.

### Task 4: Pure .NET route and the compiler

- [ ] Look for a Rego engine written in .NET; if one is complete enough for the sample policy, add it as a route and measure it, otherwise record why not.
- [ ] Try compiling `sample.rego` to the wasm module from .NET without the `opa` binary, for example OpaDotNet's interop compiler, and record whether it works under AOT and on which platforms.
- [ ] Commit.

### Task 5: Builtins that reach outside

- [ ] Add a policy that calls `http.send`, `net.lookup_ip_addr` and `opa.runtime`; show per route whether the call is refused, absent or allowed, and how to refuse it on the chosen route.
- [ ] Commit.

### Task 6: CI on three platforms

- [ ] Add `.github/workflows/rego-spike.yml`, triggered on pull requests that touch `spikes/RegoAot/**`, with a matrix of `ubuntu-latest`, `windows-latest` and `macos-latest` that AOT-publishes the app and runs `--check` with the chosen route and the compiler.
- [ ] Follow the repo's workflow conventions for action pinning and permissions.
- [ ] Commit as `ci`.

### Task 7: Write-up

- [ ] Write `docs/plans/2026-11-22-rego-aot-spike.md` with the table per route, the builtin results, the CI result per platform and the chosen route, or that none works.
- [ ] State the cold p95 of the chosen route in milliseconds. If it is above 100 ms, say so in the first paragraph: #654 then parks.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet publish spikes/RegoAot/RegoAot.csproj -c Release -r linux-x64 -warnaserror`
- test: `spikes/RegoAot/bin/Release/net10.0/linux-x64/publish/RegoAot --check`
- test: `test -s docs/plans/2026-11-22-rego-aot-spike.md`
- test: `dotnet test AI.Sentinel.slnx -c Release`

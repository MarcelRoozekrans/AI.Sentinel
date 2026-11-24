# Prove local Rego evaluation under Native AOT (#633) Implementation Plan

**Goal:** Find out how AI.Sentinel can evaluate Rego policy as one compiled module on the developer's PC, fast and offline, under Native AOT, before the rest of the milestone builds on it. Evaluating policy locally as one compiled module (ADR-236) is accepted on condition of this proof.

**Issue:** #633, milestone "Controlled from a central server".

**Spec:** Outline document `6888019f-3202-4ea3-93a7-213cc8811bf0` ("AI.Sentinel: be controlled from Themis.NET") and its approved design, Outline document `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91` ("AI.Sentinel: central server control, design", Status: approved). Read both with the Outline connector before writing code. Where they differ, the design wins; where the design and an accepted ADR differ, the ADR wins. #653 and #657 are replaced by the design and are not a source.

## Global Constraints

- Read `AGENTS.md` and the product-line standards it links before changing anything. Build sessions do not use superpowers.
- A failing test first for every behaviour change; see it fail before writing the code.
- One commit per task, Conventional Commits. No `Co-Authored-By` trailer, no "Generated with" line, no session links, no nested parentheses in a commit body.
- Every new setting is optional and off by default. With none of the new settings, AI.Sentinel behaves exactly as before (Spec AC 8): the existing test suite passes unchanged.
- New public API is approved only when it is additive, optional, off by default and asked for by the Spec or the design. A breaking change, or API outside that scope, is a step to park.
- Native AOT: the hook CLIs and any new tool build and publish without trimming or AOT warnings. No runtime reflection.
- `TreatWarningsAsErrors` is on. Do not add or widen a suppression.
- Nothing sent to the server or written to the audit carries a token, a command line, a path or tool input, except where the design allows it.
- Run `dotnet format whitespace . --folder --verify-no-changes` before each push.
- The PR body says `Closes #633` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- Three routes are tried in a small Native AOT console app that evaluates the same sample Rego policy against the same sample tool-call inputs:
  - a WebAssembly module built from Rego, run by a .NET WebAssembly runtime,
  - OPA as a separate local process,
  - a Rego engine written in .NET, if one is complete enough. `--check` and the write-up.
- Compiling Rego to the evaluated form without separate OPA tooling is tried, for example with the interop compiler of OpaDotNet, so a team can use Rego without installing OPA. The write-up.
- Several bundles are compiled into one module identified by its hash. `--check`.
- For each route: whether it builds and runs under Native AOT without trimming or AOT warnings, the decision time per call (p50 and p95) cold, cached-precompiled and warm, the binary size it adds, and which Rego features it misses. The write-up.
- A CI matrix job runs the measurement on Windows, Linux and macOS for the chosen route and the compiler. When no route or no compiler works, the job runs `--check` on the routes that build and reports that none was chosen, instead of failing. `rego-spike.yml`.
- Builtins that reach outside the process (such as `http.send`, `net.lookup_ip_addr`, `opa.runtime`) can be refused when a bundle is validated, and deny with a reason that names them when met at runtime. `--check`.
- The outcome is written up in `docs/plans/2026-11-22-rego-aot-spike.md`: the chosen route, or that none works, with its p95 per mode and OS. The whole decision must fit 50 ms per call (ADR-007). If no route does, #654 waits for review. The write-up check.

## Tasks

### Task 1: Spike app skeleton

- [x] Create `spikes/RegoAot/RegoAot.csproj`, a `net10.0` console app with `PublishAot=true`, outside `AI.Sentinel.slnx`, with its own `Directory.Build.props` if the repo one gets in the way.
- [x] Add `spikes/RegoAot/policy/` with at least two bundles in package `sentinel` that read an input shaped like the design's policy input and return the design's five outcomes: a deny on a `shell` command, an ask, a guidance, an allow.
- [x] Add `spikes/RegoAot/inputs/*.json` with at least six tool-call inputs and their expected outcomes.
- [x] Add a `--check` mode that evaluates every input on every available route and exits non-zero when an outcome differs from the expected one. With no route available it says so and exits zero, so the spike can still report that none works.
- [x] Commit.

### Task 2: WebAssembly route

- [x] Compile the bundles into one module, identified by its hash, and run it with a .NET WebAssembly runtime such as OpaDotNet.Wasm or Wasmtime.
- [x] Measure p50 and p95 over at least 200 runs each: cold (new process, no cache), cached-precompiled (new process, module precompiled to disk) and warm (same process). Record the binary size added.
- [x] Commit.

### Task 3: OPA process route

- [x] Run OPA as a local process and query it; measure the same three modes, counting OPA startup for cold.
- [x] Commit.

### Task 4: Pure .NET route and the compiler

- [x] Look for a Rego engine written in .NET; if one is complete enough for the sample bundles, add it as a route and measure it, otherwise record why not.
- [x] Compile the bundles from .NET without the `opa` binary, for example with OpaDotNet's interop compiler, and record whether it works under AOT and on which platforms.
- [x] Commit.

### Task 5: Builtins that reach outside

- [x] Add a bundle that calls `http.send`, `net.lookup_ip_addr` and `opa.runtime`. Show per route how validation refuses it before evaluation, and that a call met at runtime denies with a reason naming the builtin.
- [x] Commit.

### Task 6: CI matrix on three platforms

- [x] Add `.github/workflows/rego-spike.yml`, triggered on pull requests that touch `spikes/RegoAot/**`, with a matrix of `ubuntu-latest`, `windows-latest` and `macos-latest` that AOT-publishes the app, runs `--check`, and prints p50 and p95 per mode for the chosen route and the compiler. When no route or no compiler works, the job prints that and skips the measurement instead of invoking it.
- [x] Follow the repo's workflow conventions for action pinning and permissions.
- [x] Commit as `ci`.

### Task 7: Write-up

- [x] Write `docs/plans/2026-11-22-rego-aot-spike.md` with the table per route, mode and OS, the builtin results and the chosen route, or that none works.
- [x] The budget is 50 ms per call for the whole decision. If no route fits it, say so in the first paragraph: #654 then waits for review.
- [x] Add a short paragraph for ADR-236 naming the route; the maintainer copies it into the ADR.
- [x] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet publish spikes/RegoAot/RegoAot.csproj -c Release -r linux-x64 -warnaserror`
- test: `spikes/RegoAot/bin/Release/net10.0/linux-x64/publish/RegoAot --check`
- test: `test -s docs/plans/2026-11-22-rego-aot-spike.md`
- test: `dotnet test AI.Sentinel.slnx -c Release`

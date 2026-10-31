# Native AOT release binaries (#456) — design

## Intent

Every Claude Code / Copilot hook fires twice per tool call, and the framework-dependent `dotnet tool` pays ~190 ms of process start and JIT each time (measured in #456). The CLIs are already Native-AOT clean, and `aot-publish.yml` proves it on every PR, but releases ship only the slow tool package. The only route to the fast binary today is a local AOT publish with clang or MSVC on every agent host, repeated on every release.

Success: a user runs the same `dotnet tool install -g AI.Sentinel.ClaudeCode.Cli` as today and gets the native binary on the common platforms. A user without the .NET SDK downloads a verified native binary from the GitHub release.

Scope: `sentinel-hook` (AI.Sentinel.ClaudeCode.Cli), `sentinel-copilot-hook` (AI.Sentinel.Copilot.Cli), `sentinel-mcp` (AI.Sentinel.Mcp.Cli). `sentinel` (AI.Sentinel.Cli) is out of scope: it is an occasional forensics/dashboard tool, not on the per-tool-call path.

## Goals

- NuGet: the three tool packages become RID-specific .NET 10 tool packages. Native AOT for `linux-x64`, `linux-arm64`, `linux-musl-x64`, `linux-musl-arm64`, `osx-arm64`, `win-x64`, and a framework-dependent `any` fallback for every other platform. The glibc builds need glibc 2.28 at most, so they start on every glibc distribution .NET 10 supports. Same package IDs, same command names.
- GitHub release: per RID, a native binary archive for each CLI, a `SHA256SUMS` file covering every archive, and a GitHub artifact attestation (Sigstore build provenance) for each archive.
- Every release-side build step is exercised on PRs too, so a broken native leg fails a PR rather than a release.
- Docs show the native path as the default and explain how to verify a downloaded binary.

## Non-goals

- OS code signing (Authenticode, Apple notarization). Windows SmartScreen and macOS Gatekeeper still warn on downloaded binaries. The docs say so.
- More RIDs (win-arm64, osx-x64). They get the `any` fallback. musl is in scope: the RID graph sends `linux-musl-x64` to `linux-x64` before `any`, so without its own packages Alpine would get a glibc binary that cannot start (final review, Marcel chose native musl legs).
- Homebrew, winget, apt or container images.
- AOT for `AI.Sentinel.Cli`.

## Anti-goals

- A release where the pointer package is on NuGet but a RID package it names is missing. `dotnet tool install` would then fail for every user on that RID.
- A native binary that ships without having passed the same smoke test the PR check runs (hook decision exits 0/2, SQLite audit file created, NDJSON forwarding, MCP usage exit).
- Keeping the slow package as the documented default.

## Constraints (verified)

- RID-specific and AOT tools are a .NET SDK 10 feature. Installing such a tool needs the .NET 10 SDK. A machine with only the .NET 8 SDK can no longer install these three packages. .NET 8 reaches end of support on 2026-11-10.
- With `PublishAot=true`, `dotnet pack` produces only the pointer package. Each RID package is produced by `dotnet pack -r <rid>` on a runner whose OS matches the RID; cross-architecture on the same OS is allowed. The `any` fallback is `dotnet pack -r any -p:PublishAot=false`.
- The pointer and all RID packages must carry the exact same version. All RID packages must be on the feed before the pointer is pushed, or installs fail in the meantime.
- Source: learn.microsoft.com/dotnet/core/tools/rid-specific-tools, and the hybrid example richlander/dotnet10-hybrid-tool.
- `tests/AI.Sentinel.Tests` targets `net8.0;net10.0` and references the three CLI projects. 11 test files across `ClaudeCode/`, `Copilot/` and `Mcp/` use CLI types.
- Branch protection requires the `aot-publish.yml` check names. Changing the matrix changes those names.
- The repo is public, so `actions/attest-build-provenance` and `gh attestation verify` are available.
- The release pushes 15 new package IDs (`<Id>.<rid>` and `<Id>.any` for each CLI). The `NUGET_API_KEY` uses an `AI.Sentinel.*` glob, so it covers them (confirmed by Marcel).

- A Native AOT binary needs the glibc of the machine it was linked on or newer. ubuntu-24.04 has glibc 2.39, so the glibc legs link inside an AlmaLinux 8 container (glibc 2.28) and CI fails a binary that needs a newer `GLIBC_` symbol. The musl legs link inside the Alpine .NET SDK image. Both go through `eng/pack-native-linux.sh` (final review, Marcel chose the old-glibc container).
- nuget.org indexes packages asynchronously, so the release checks that every RID package a pointer names was built, and waits until NuGet serves each RID package before it pushes the pointers.

## Approaches

| | Approach | Trade-off |
|---|---|---|
| **A (picked)** | Same package IDs; the three CLIs target `net10.0` only; RID AOT packages plus `any` fallback | One install command, native by default. Breaks install for .NET 8-only SDKs, so it ships as `feat!` (major). |
| B | New `*.Native` package IDs next to the existing ones | No break, but the documented default stays slow and there are three more packages to keep. This keeps the known-slow path to avoid a version bump. |
| C | Same IDs, keep `net8.0` inside the `any` fallback only | Nothing lost, but mixed-TFM RID tools are undocumented; needs a spike that may fail back to A or B. |

Delivery channel: both NuGet RID packages and GitHub release binaries (picked over NuGet-only and binaries-only). Signing: attestations plus SHA256 (picked over adding OS signing, which needs paid certificates, and over checksums only). RIDs: the four above (picked over six RIDs or linux-x64 only).

## Design

### Project files

For each of the three CLI projects:

- `TargetFramework` `net10.0` replaces `TargetFrameworks` `net8.0;net10.0`. The libraries they reference keep `net8.0;net10.0`.
- `PackAsTool` is `true` unconditionally. The `Condition="'$(PublishAot)' != 'true'"` goes away.
- `PublishAot` `true` in the project, so AOT and trim analyzers run on every build, not only in the AOT workflow.
- `ToolPackageRuntimeIdentifiers` `linux-x64;linux-arm64;linux-musl-x64;linux-musl-arm64;osx-arm64;win-x64;any`, and `RollForward` `Major` so the `any` fallback also starts on a newer runtime.
- `InvariantGlobalization` keeps following `PublishAot`. It must stay false for the `any` package, which is packed with `PublishAot=false`, so the existing condition already gives the right result.
- The shared RID list lives in one place, a property in `Directory.Build.props` scoped to the three CLIs or a small `src/Cli.Native.props` imported by them. Builder's call.

### Tests

`tests/AI.Sentinel.Tests` keeps `net8.0;net10.0`. The three CLI `ProjectReference`s get `Condition="'$(TargetFramework)' == 'net10.0'"`, and the CLI test files are compiled only for net10.0, for example by putting them under a `Compile Remove` for net8.0. The net8.0 leg keeps testing the libraries.

### Shared smoke script

The smoke test in `aot-publish.yml` moves to `eng/smoke-native.ps1`, taking the binary path as an argument. PowerShell 7 is on every GitHub-hosted runner, so one script serves Linux, macOS and Windows. Its checks stay as today: MCP exits 1 with Usage; hooks exit 0 on a benign prompt and create the SQLite audit file, exit 2 on a blocking prompt, and write an NDJSON entry with SEC-01. On Linux/macOS the binary has no `.exe`; the script takes the path, not a glob.

### PR check — `aot-publish.yml`

- Matrix: 3 projects × 4 RIDs, runners `ubuntu-latest` (linux-x64), `ubuntu-24.04-arm` (linux-arm64), `macos-latest` (osx-arm64), `windows-latest` (win-x64). Each leg runs `dotnet publish -r <rid> -p:PublishAot=true`, the size check and `eng/smoke-native.ps1`.
- The MCP nested-JSON round-trip stays a PR-check step on the win-x64 MCP leg, as today. It is not part of the release gate: the release runs the same code that passed it on the PR. (My call.)
- Smoke and MCP detection key on the command name or an explicit matrix field, not on a `*Mcp*` file glob.
- One extra job, `tool-install` on `ubuntu-latest`: packs the pointer, the `any` package and `linux-x64` for one CLI into a local folder with a throwaway version, then `dotnet tool install --tool-path <tmp> --add-source <folder>` and checks that the installed command is the native binary and runs the smoke script against it. This proves the pointer resolves before any release depends on it.
- The required check names change. Marcel updates branch protection when the PR lands.

### Release — `release-please.yml`

The single `publish` job becomes three jobs:

1. **`native`** (needs `release-please`, runs only when a release was created). Matrix 3 CLIs × 4 RIDs, same runners as the PR check. Each leg:
   - `dotnet pack <cli> -c Release -r <rid> -p:PackageVersion=<v>`, producing the RID package.
   - Extract the native binary from that `.nupkg` and run `eng/smoke-native.ps1` on it. The archive is built from the same extracted binary, so NuGet and the GitHub release ship identical, smoke-tested bits. There is no separate `dotnet publish` in the release. (Builder check; my call.)
   - Archive the binary, renamed to its command name (`sentinel-hook`, `sentinel-copilot-hook`, `sentinel-mcp`, plus `.exe` on Windows), as `<command>-<version>-<rid>.tar.gz` for Linux/macOS or `.zip` for Windows. The AOT output is named after the assembly, so the rename happens in the archive step; `AssemblyName` stays. The archive holds the binary only, no `.pdb` or `.dbg`. (My call.)
   - `actions/attest-build-provenance` on the archive. The job needs `id-token: write` and `attestations: write`.
   - Upload the RID package and the archive as workflow artifacts.
2. **`publish`** (needs `native`). As today: build, test and pack the libraries and `AI.Sentinel.Cli`. In addition, for the three CLIs it packs the pointer (`dotnet pack`) and the fallback (`dotnet pack -r any -p:PublishAot=false`), and downloads the `native` artifacts. It pushes in two steps: first every RID package and every `any` package, then every other package, so the pointers land last. `--skip-duplicate` stays, so a rerun after a partial failure is safe.
3. Asset upload (in `publish`, after the push): write `SHA256SUMS` over the archives, attest it, and `gh release upload --clobber` the archives, `SHA256SUMS` and the `.nupkg` files. `--clobber` makes a rerun replace assets; a rerun attests the rebuilt archives again, which is harmless. (My call.)

If any `native` leg fails, nothing is pushed. The release tag and notes already exist at that point (release-please created them), so recovery is a workflow rerun, not a new release.

### Docs

- `website/docs/integrations/claude-code.md`, `copilot.md`, `mcp-proxy.md` and the README install sections: `dotnet tool install` needs the .NET 10 SDK and installs the native build on the four RIDs automatically. Replace the "Native binary (faster cold start)" local-publish section with "Native binary without the .NET SDK": download from the release, verify with `sha256sum -c SHA256SUMS` and `gh attestation verify <archive> --repo MarcelRoozekrans/AI.Sentinel`, point the hook `command` at the path. Mention the OS warnings and how to clear them (`xattr -d com.apple.quarantine` on macOS, Unblock-File on Windows).
- Keep the local `dotnet publish -p:PublishAot=true` recipe as a short note for other RIDs.
- A migration note for .NET 8-only users: install the .NET 10 SDK, or download the release binary, which needs no runtime.

### Release type

`feat!:` with a `BREAKING CHANGE:` footer: the three CLI tool packages need the .NET 10 SDK to install and no longer target net8.0. Closes #456. This makes the next release 5.0.0.

## Left to the builder

- Where the RID list lives (props file or the three csproj files).
- How the CLI test files are excluded on net8.0.
- Script details of `eng/smoke-native.ps1` and the archive step per OS.
- How `tool-install` tells the native binary from the framework-dependent one, for example by checking that the installed tool folder holds no `.dll` for the CLI's own assembly.

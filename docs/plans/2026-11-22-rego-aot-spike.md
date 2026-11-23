# Local Rego evaluation under Native AOT: spike result (#633)

**Result.** A route works and fits the budget. The whole decision must fit 50 ms per call (ADR-007). The chosen route is a WebAssembly module built from all bundles, run by Wasmtime .NET through a small host for the OPA wasm ABI that we own. It publishes with Native AOT and no AOT or trim warning. With the module precompiled to native code on disk, a new process decides in 2.9 ms at p50 and 3.6 ms at p95 on Linux, and a warm process in 0.01 ms. The cold case, where the hook has to compile Rego first, takes 42 ms at p50 and 60 ms at p95, which is over budget at p95. So the compile step must happen when a configuration arrives, never inside a hook call. #654 does not have to wait for review on account of speed. Two things it must plan for are in "What the next step must do". The Windows and macOS numbers come from the CI matrix job `rego-spike.yml` and are pending until that job has run.

Spike code: `spikes/RegoAot/`, outside `AI.Sentinel.slnx`, not shipped. Reproduce on Linux with `dotnet publish spikes/RegoAot/RegoAot.csproj -c Release -r linux-x64 -warnaserror`, then `RegoAot --check` and `RegoAot --measure --runs 200` from the publish directory, with `OPA_BIN` pointing at an `opa` binary.

## What was run

- Policy: three bundles in package `sentinel` (`_core` combines outcomes, strictest first, `org-baseline`, `team-guidance`), ten sample tool calls with expected outcome and expected reasons. All routes give the expected outcome and reasons for all ten.
- All bundles compile into one module. The module id is the sha256 of every source file and the entrypoint. It is stable across loads and changes when any bundle changes (`--check`).
- Machine: Linux x64 VM, 12 logical cores, shared with other sessions, so the tails carry noise. OPA v1.22.4 (sha256 checked against the release file), Wasmtime .NET 48.0.2, Rego 1.5.1 (rego-cpp), OpaDotNet.Compilation.Interop 2.3.4, .NET SDK 11.0.100 building `net10.0`.
- Modes. Cold: a new process with no cache, it compiles the Rego itself. Cached: a new process that loads a module precompiled on disk. Warm: the same process, module already loaded, 1000 calls over the ten inputs after 50 warm-up calls. Cold and cached use 200 new processes each, after 3 discarded. The time is measured inside the process from loading the bundles (which includes hashing them) to the decision, so it excludes runtime start. The wall time of the process is in the second table.

## Routes

| Route | Builds and runs under Native AOT with no warning | Notes |
|---|---|---|
| wasmtime (own host over Wasmtime .NET) | Yes, `-warnaserror` clean | Chosen. Uses the untyped Wasmtime API only. |
| OpaDotNet.Wasm 3.2.18 | No | 75 distinct warning lines: 38 in OpaDotNet.Wasm, 32 in YamlDotNet, 5 in Wasmtime.Dotnet. Codes IL2026, IL2055, IL2057, IL2060, IL2067, IL2070, IL2072, IL2075, IL3000 and 28 times IL3050. Creating an evaluator also throws at run time, `Reflection-based serialization has been disabled`, because it deserializes through `System.Text.Json` reflection. Not usable. |
| opa-eval (OPA as one process per call) | n/a, no .NET code of OPA is linked | Complete Rego, reference semantics. |
| opa-server (`opa run --server` on loopback) | n/a | Complete Rego. Needs a lifecycle for a daemon. |
| rego-cpp (the `Rego` package) | Yes, `-warnaserror` clean | In-process C++ interpreter behind P/Invoke. Not written in .NET. |
| A Rego engine written in .NET | None exists | NuGet searches for rego, regorus, rego interpreter, open policy agent and rego-cpp, and a GitHub repository search for C# Rego interpreters, found only OpaDotNet.* (a wasm host and compilers), the `Rego` binding of rego-cpp and unrelated packages. |

The generic wrappers of Wasmtime .NET (`GetFunction<...>`, `DefineFunction<...>`, `FromCallback<...>`) are the source of its warnings: `ReturnTypeFactory`, `ValueRaw.Converter` and `TypeExtensions` use `MakeGenericType` and `GetInterfaces`. The spike calls only `Linker.DefineFunction` with `UntypedCallbackDelegate`, `Function.Invoke` and `Memory`, which produce none.

## Decision time on Linux

In-process time per call in milliseconds, p50 / p95. 200 runs per spawned mode, 1000 calls warm.

| Route | Cold | Cached, wasm on disk | Cached, native code on disk | Warm | Windows | macOS |
|---|---|---|---|---|---|---|
| wasmtime, interop compiler | 42.10 / 60.30 | 21.22 / 29.18 | 2.87 / 3.61 | 0.01 / 0.01 | pending CI | pending CI |
| wasmtime, opa binary as compiler | 45.92 / 56.12 | 21.38 / 28.94 | 2.87 / 7.45 | 0.01 / 0.01 | pending CI | pending CI |
| opa-eval, per call process | 12.89 / 23.67 (from sources) | 13.88 / 22.94 (prebuilt bundle) | n/a | n/a | pending CI | pending CI |
| opa-server, loopback HTTP | 25.34 / 36.21 | 26.68 / 36.09 | n/a | 0.18 / 0.67 | pending CI | pending CI |
| rego-cpp | 8.59 / 10.42 | 5.03 / 12.25 (binary bundle) | n/a | 0.19 / 0.25 | pending CI | pending CI |

Wall time of the whole process in milliseconds, p50 / p95, which adds runtime start and exit: wasmtime with native code on disk 6.82 / 8.37, wasmtime cached wasm 28.05 / 38.76, wasmtime cold 50.14 / 73.06, opa-eval cached 17.93 / 27.44, opa-server cached 33.77 / 44.38, rego-cpp cached 9.41 / 21.50.

For wasmtime, cold is the Rego compile (about 11 ms with the interop compiler, 20 ms with the opa binary, see below) plus Wasmtime compiling the wasm (about 18 ms, the gap between cached and cached with native code) plus the evaluation. The native code is a Wasmtime serialization named by the module hash. It only loads into an engine of the same Wasmtime version and settings, so the cache key must carry the Wasmtime version too. Changing the Cranelift optimization level did not shorten the compile in a trial on this machine (about 21 ms either way). The Winch baseline compiler is not exposed by Wasmtime .NET 48.0.2.

Compiling Rego to wasm, in process, first call and repeated (200 calls):

| Compiler | First call | p50 | p95 | Works under Native AOT | Platforms of its native library |
|---|---|---|---|---|---|
| OpaDotNet.Compilation.Interop 2.3.4 | 12.34 ms | 10.68 ms | 14.65 ms | Yes, `-warnaserror` clean | linux-x64, win-x64 |
| opa binary (`opa build -t wasm`) | 20.52 ms | 20.17 ms | 29.73 ms | n/a, a separate process | every platform OPA ships for |

The interop compiler lets a team use Rego without installing OPA, on Linux and Windows x64. It has no macOS or ARM library, so there the compile needs the opa binary, or the module has to arrive precompiled. OpaDotNet.Compilation.Cli was not measured: it runs the same opa binary that the spike calls directly.

## Size added on Linux x64

The spike with no route is 2.52 MiB.

| Route | Managed code added to the executable | Native library added |
|---|---|---|
| wasmtime | 1.36 MiB | libwasmtime.so 29.84 MiB |
| interop compiler | about 0.09 MiB | Opa.Interop.so 23.51 MiB |
| rego-cpp | about 0.03 MiB | librego_shared.so 12.38 MiB |
| opa process routes | 2.83 MiB (HttpClient and Process) | none, but a separate opa binary of tens of MB |

## Rego features each route misses

- **wasmtime.** It evaluates what OPA compiles, so the language is complete. The OPA wasm library carries only some builtins itself; the others are imports that the host must implement. A probe module with 30 common builtins imports 11 from the host: `crypto.sha256`, `net.cidr_contains_matches`, `regex.find_n`, `regex.replace`, `semver.compare`, `sprintf`, `time.now_ns`, `units.parse_bytes`, `urlquery.decode`, `uuid.rfc4122` and `yaml.unmarshal`. The other 19 (among them `regex.match`, `glob.match`, `net.cidr_contains`, `json.unmarshal`, `startswith`, `lower`, `split`, `concat`, `to_number`, `base64.decode`, `replace`, `sort`) run inside the module. The spike host implements none of the 11, and a call of one denies with a reason naming it. The sample bundles avoid them: with `sprintf` in a rule, case 08 fails the reason comparison. The product host would have to implement the ones it wants to support. OpaDotNet.Wasm has such implementations but is not AOT safe.
- **opa-eval, opa-server.** None, this is the reference implementation.
- **rego-cpp.** The package says it is largely compatible with v1.8.0 of the language, while the spike compiled against OPA v1.22.4 syntax and all ten cases pass. `http.send` and `net.lookup_ip_addr` are not available. Without `StrictBuiltInErrors` a rule that calls an unavailable builtin is silently undefined, so the policy falls through to `defer`, which fails open. With it the query fails, but the error is an opaque node and does not name the builtin. It has no capabilities document, so it cannot refuse a builtin at validation. It implements `opa.runtime`.

## Builtins that reach outside the process

A bundle with `http.send`, `net.lookup_ip_addr` and `opa.runtime` (`policy-unsafe/`) is checked by `--check` on every available route.

| Route | Validation | A bundle that was not validated, at run time |
|---|---|---|
| wasmtime, either compiler | The compiler gets a capabilities document without the three, and reports each as an undefined function. Refused, all three named. | The module imports the builtin, the host refuses the call, the decision is `deny` with `builtin http.send reaches outside the process and is refused`, one name per call. |
| opa-eval, opa-server | `opa check --capabilities` refuses, all three named. | The same capabilities document makes the whole bundle fail to load, so every call denies, with all three names in the reason. A process cannot deny one call. Without the document OPA would run `http.send` for real, so the document has to be passed always. |
| rego-cpp | Lexical scan of the sources outside comments and strings. It refuses all three, and over-refuses a name that merely appears in code. | `http.send` and `net.lookup_ip_addr` deny under strict builtin errors, naming the builtins the sources use. `opa.runtime` is evaluated and returns a result, so only validation keeps it out. This is a known gap, printed by `--check` as `gap`. |

The capabilities document is `capabilities.json`, the output of `opa capabilities --current` for OPA v1.22.4 with the three builtins removed. It has to be regenerated when the OPA version moves.

## Chosen route

wasmtime: all bundles compiled to one wasm module named by its hash, run through Wasmtime .NET with our host for the OPA wasm ABI, native code cached on disk next to the module, compiled with the OpaDotNet interop compiler where its native library exists and with the opa binary otherwise.

Why not the others. OpaDotNet.Wasm is not AOT safe. OPA as a process has the right semantics but costs 13 to 24 ms in process (17 to 28 ms wall) for a short-lived call and needs an install, or a daemon with a lifecycle. rego-cpp is the fastest to start and needs no compile step, but it reimplements the language, so a policy can mean something else than under OPA, it fails open on a missing builtin unless told otherwise, it cannot refuse a builtin at validation, and its package has no linux-arm64, musl or win-arm64 library. It stays the fallback if implementing host builtins proves too costly.

## For ADR-236

Local evaluation as one compiled module is feasible under Native AOT, on condition of these choices. The bundles of a configuration are compiled to one WebAssembly module identified by the sha256 of its sources, and run by Wasmtime .NET through an OPA wasm ABI host owned by AI.Sentinel, since OpaDotNet.Wasm is not Native AOT compatible. The compile happens when the configuration arrives, with the OpaDotNet interop compiler or the opa binary, and the hook only loads the cached native code: 2.9 ms at p50 and 3.6 ms at p95 on Linux x64, against a budget of 50 ms. Bundles are validated with a capabilities document that leaves out the builtins that reach outside the process, and the host refuses any such import at run time with a deny that names it.

## What the next step must do

- Implement the host builtins the product wants to support (`sprintf` is already needed by any policy that formats a reason), and decide which of the 11 are in scope. The module denies, naming the builtin, for every one it lacks.
- Compile on a machine with a compiler. The interop compiler has no macOS or ARM library, so a Mac, an ARM machine or a musl image needs the opa binary, or the module compiled elsewhere. Wasmtime .NET has native libraries for linux-x64, linux-arm64, osx-x64, osx-arm64, win-x64 and win-arm64, not for musl, so the musl tool packages need a separate answer.
- Key the native code cache on the module hash, the Wasmtime version and the engine settings.
- Fill in the Windows and macOS rows from the first run of `rego-spike.yml`. The Linux column above is from a local run only.

using System.Text;
using System.Text.Json.Nodes;
using Wasmtime;

namespace RegoAot;

/// <summary>
/// The OPA WebAssembly ABI, driven directly through Wasmtime .NET. OpaDotNet.Wasm is not used:
/// it is not AOT compatible, see the write-up.
/// </summary>
internal sealed class WasmtimeRoute(ICompiler compiler) : IRoute
{
    public string Name => "wasmtime";

    public IReadOnlyList<string> Modes => ["cached", "cached-native", "cold", "warm"];

    public string? Unavailable() => compiler.Unavailable();

    public IEvaluator Create(BundleSet set, string mode, string cacheDir)
    {
        var engine = new Engine();
        Module module;
        switch (mode)
        {
            case "cold":
                module = Module.FromBytes(engine, "policy", compiler.CompileWasm(set));
                break;
            case "cached-native":
                module = Module.DeserializeFile(engine, "policy", Path.Combine(cacheDir, set.Hash + ".cwasm"));
                break;
            default:
                module = Module.FromFile(engine, Path.Combine(cacheDir, set.Hash + ".wasm"));
                break;
        }

        return new WasmEvaluator(engine, module);
    }

    /// <summary>Writes the precompiled artifacts, named by the module hash: the wasm and the native code of Wasmtime.</summary>
    public void Prepare(BundleSet set, string cacheDir)
    {
        Directory.CreateDirectory(cacheDir);
        var wasm = compiler.CompileWasm(set);
        File.WriteAllBytes(Path.Combine(cacheDir, set.Hash + ".wasm"), wasm);
        using var engine = new Engine();
        using var module = Module.FromBytes(engine, "policy", wasm);
        File.WriteAllBytes(Path.Combine(cacheDir, set.Hash + ".cwasm"), module.Serialize());
    }
}

internal sealed class WasmEvaluator : IEvaluator
{
    private readonly Engine _engine;
    private readonly Module _module;
    private readonly Store _store;
    private readonly Linker _linker;
    private readonly Instance _instance;
    private readonly Memory _memory;
    private readonly Function _malloc;
    private readonly Function _jsonParse;
    private readonly Function _jsonDump;
    private readonly Function _ctxNew;
    private readonly Function _ctxSetInput;
    private readonly Function _ctxSetData;
    private readonly Function _ctxSetEntrypoint;
    private readonly Function _ctxGetResult;
    private readonly Function _eval;
    private readonly Function _heapSet;
    private readonly int _data;
    private readonly int _entrypointId;
    private readonly long _heapBase;
    private readonly Dictionary<int, string> _builtinNames = [];
    private string? _refused;

    public WasmEvaluator(Engine engine, Module module)
    {
        _engine = engine;
        _module = module;
        _store = new Store(engine);
        _linker = new Linker(engine);

        var minPages = module.Imports.OfType<MemoryImport>().First().Minimum;
        _memory = new Memory(_store, minPages);
        _linker.Define("env", "memory", _memory);
        _linker.DefineFunction("env", "opa_abort", Abort, [ValueKind.Int32], []);
        _linker.DefineFunction("env", "opa_println", (Caller c, ReadOnlySpan<ValueBox> a, Span<ValueBox> r) => { }, [ValueKind.Int32], []);
        for (var arity = 0; arity <= 4; arity++)
        {
            var kinds = Enumerable.Repeat(ValueKind.Int32, arity + 2).ToArray();
            _linker.DefineFunction("env", "opa_builtin" + arity, Builtin, kinds, [ValueKind.Int32]);
        }

        _instance = _linker.Instantiate(_store, module);
        Function Get(string name) => _instance.GetFunction(name) ?? throw new InvalidOperationException($"export {name} is missing");
        _malloc = Get("opa_malloc");
        _jsonParse = Get("opa_json_parse");
        _jsonDump = Get("opa_json_dump");
        _ctxNew = Get("opa_eval_ctx_new");
        _ctxSetInput = Get("opa_eval_ctx_set_input");
        _ctxSetData = Get("opa_eval_ctx_set_data");
        _ctxSetEntrypoint = Get("opa_eval_ctx_set_entrypoint");
        _ctxGetResult = Get("opa_eval_ctx_get_result");
        _eval = Get("eval");
        _heapSet = Get("opa_heap_ptr_set");

        foreach (var (name, id) in JsonNode.Parse(DumpExport("builtins"))!.AsObject())
        {
            _builtinNames[id!.GetValue<int>()] = name;
        }

        var entrypoints = JsonNode.Parse(DumpExport("entrypoints"))!.AsObject();
        _entrypointId = entrypoints[BundleSet.Entrypoint]!.GetValue<int>();

        _data = Parse("{}");
        _heapBase = Convert.ToInt64(Get("opa_heap_ptr_get").Invoke());
    }

    public Decision Evaluate(string inputJson)
    {
        _refused = null;
        try
        {
            _heapSet.Invoke((int)_heapBase);
            var input = Parse(inputJson);
            var ctx = Call(_ctxNew);
            _ctxSetInput.Invoke(ctx, input);
            _ctxSetData.Invoke(ctx, _data);
            _ctxSetEntrypoint.Invoke(ctx, _entrypointId);
            _eval.Invoke(ctx);
            var result = Call(_jsonDump, Call(_ctxGetResult, ctx));
            var json = _memory.ReadNullTerminatedString(result);
            var first = JsonNode.Parse(json)!.AsArray().FirstOrDefault()?["result"];
            if (first is null)
            {
                return new Decision("defer", []);
            }

            var reasons = first["reasons"]!.AsArray().Select(n => n!.GetValue<string>()).ToList();
            return new Decision(first["outcome"]!.GetValue<string>(), reasons);
        }
        catch (Exception) when (_refused is not null)
        {
            // A builtin that reaches outside the process was met: the call is denied, and the reason names it.
            return new Decision("deny", [$"builtin {_refused} reaches outside the process and is refused"]);
        }
    }

    private string DumpExport(string name) =>
        _memory.ReadNullTerminatedString(Call(_jsonDump, Call(_instance.GetFunction(name)!)));

    private int Parse(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var ptr = Call(_malloc, bytes.Length);
        bytes.CopyTo(_memory.GetSpan<byte>(ptr, bytes.Length));
        return Call(_jsonParse, ptr, bytes.Length);
    }

    private static int Call(Function fn, params ValueBox[] args) => Convert.ToInt32(fn.Invoke(args));

    private void Abort(Caller caller, ReadOnlySpan<ValueBox> args, Span<ValueBox> results)
    {
        throw new InvalidOperationException("opa_abort: " + _memory.ReadNullTerminatedString(args[0].AsInt32()));
    }

    private void Builtin(Caller caller, ReadOnlySpan<ValueBox> args, Span<ValueBox> results)
    {
        var id = args[0].AsInt32();
        _refused = _builtinNames.TryGetValue(id, out var name) ? name : "builtin#" + id;
        throw new InvalidOperationException($"the host does not provide builtin {_refused}");
    }

    public void Dispose()
    {
        _store.Dispose();
        _linker.Dispose();
        _module.Dispose();
        _engine.Dispose();
    }
}

using System.Text;
using System.Text.Json;
using Wasmtime;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The OPA WebAssembly ABI, driven directly through Wasmtime .NET. OpaDotNet.Wasm is not used: it is not Native AOT
/// compatible. Only the untyped Wasmtime API is called, because its generic wrappers use reflection.
/// </summary>
internal sealed class WasmEvaluator : IDisposable
{
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

    private WasmEvaluator(Engine engine, Module module)
    {
        _module = module;
        _store = new Store(engine);
        _linker = new Linker(engine);

        var minPages = module.Imports.OfType<MemoryImport>().First().Minimum;
        _memory = new Memory(_store, minPages);
        _linker.Define("env", "memory", _memory);
        _linker.DefineFunction("env", "opa_abort", Abort, [ValueKind.Int32], []);
        _linker.DefineFunction("env", "opa_println", (_, _, _) => { }, [ValueKind.Int32], []);
        for (var arity = 0; arity <= 4; arity++)
        {
            var kinds = new ValueKind[arity + 2];
            Array.Fill(kinds, ValueKind.Int32);
            _linker.DefineFunction("env", "opa_builtin" + arity, Builtin, kinds, [ValueKind.Int32]);
        }

        _instance = _linker.Instantiate(_store, module);
        Function Get(string name) => _instance.GetFunction(name) ?? throw new InvalidOperationException($"the module has no export {name}");
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

        using (var builtins = JsonDocument.Parse(DumpExport(Get("builtins"))))
        {
            foreach (var property in builtins.RootElement.EnumerateObject())
            {
                _builtinNames[property.Value.GetInt32()] = property.Name;
            }
        }

        using (var entrypoints = JsonDocument.Parse(DumpExport(Get("entrypoints"))))
        {
            _entrypointId = entrypoints.RootElement.TryGetProperty(PolicySources.Entrypoint, out var id)
                ? id.GetInt32()
                : throw new InvalidOperationException($"the module has no entrypoint {PolicySources.Entrypoint}");
        }

        _data = Parse("{}");
        _heapBase = Convert.ToInt64(Get("opa_heap_ptr_get").Invoke(), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Loads a module compiled by <see cref="IRegoCompiler"/>: the Wasmtime engine compiles it to native code.</summary>
    public static WasmEvaluator FromWasm(byte[] wasm)
    {
        ArgumentNullException.ThrowIfNull(wasm);
        return Load(engine => Module.FromBytes(engine, "policy", wasm));
    }

    /// <summary>Loads the native code that <see cref="WasmEngine.Precompile"/> made. Wasmtime cannot validate it, so the caller
    /// has to have checked where it came from.</summary>
    public static WasmEvaluator FromNative(byte[] native)
    {
        ArgumentNullException.ThrowIfNull(native);
        return Load(engine => Module.Deserialize(engine, "policy", native));
    }

    private static WasmEvaluator Load(Func<Engine, Module> module)
    {
        var engine = WasmEngine.Create();
        return new WasmEvaluator(engine, module(engine));
    }

    /// <summary>Evaluates the policy for the input. A call of a builtin the host does not run is a deny that names it. Any
    /// other failure of the module throws, and the caller treats that as an internal error.</summary>
    public RegoDecision Evaluate(string inputJson)
    {
        ArgumentNullException.ThrowIfNull(inputJson);
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
            return ReadResult(_memory.ReadNullTerminatedString(Call(_jsonDump, Call(_ctxGetResult, ctx))));
        }
        catch (Exception) when (_refused is not null)
        {
            // The module met a builtin the host does not run, one that reaches outside the process or one it has not
            // implemented. The call is denied, and the reason names the builtin.
            var why = OutsideBuiltins.Names.Contains(_refused, StringComparer.Ordinal)
                ? "reaches outside the process and is refused"
                : "is not implemented by the host";
            return new RegoDecision(DecisionOutcome.Deny, [$"builtin {_refused} {why}"], _refused);
        }
    }

    private static RegoDecision ReadResult(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() == 0
            || !doc.RootElement[0].TryGetProperty("result", out var result))
        {
            // The host rules always define a decision, so no result means the policy was not what was compiled.
            throw new InvalidOperationException("the policy gave no decision");
        }

        var outcome = result.GetProperty("outcome").GetString() switch
        {
            "deny" => DecisionOutcome.Deny,
            "ask" => DecisionOutcome.Ask,
            "guidance" => DecisionOutcome.Guidance,
            "allow" => DecisionOutcome.Allow,
            "defer" => DecisionOutcome.Defer,
            var other => throw new InvalidOperationException($"the policy gave the unknown outcome '{other}'"),
        };
        var reasons = new List<string>();
        foreach (var reason in result.GetProperty("reasons").EnumerateArray())
        {
            reasons.Add(reason.GetString() ?? string.Empty);
        }

        var severities = new List<KeyValuePair<string, string>>();
        if (result.TryGetProperty("severity_actions", out var actions) && actions.ValueKind == JsonValueKind.Object)
        {
            foreach (var action in actions.EnumerateObject())
            {
                severities.Add(new(action.Name, action.Value.GetString() ?? string.Empty));
            }
        }

        return new RegoDecision(outcome, reasons, SeverityActions: SeverityActions.Parse(severities));
    }

    private string DumpExport(Function export) => _memory.ReadNullTerminatedString(Call(_jsonDump, Call(export)));

    private int Parse(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var ptr = Call(_malloc, bytes.Length);
        bytes.CopyTo(_memory.GetSpan<byte>(ptr, bytes.Length));
        return Call(_jsonParse, ptr, bytes.Length);
    }

    private static int Call(Function fn, params ValueBox[] args) =>
        Convert.ToInt32(fn.Invoke(args), System.Globalization.CultureInfo.InvariantCulture);

    private void Abort(Caller caller, ReadOnlySpan<ValueBox> args, Span<ValueBox> results) =>
        throw new InvalidOperationException("the policy aborted: " + _memory.ReadNullTerminatedString(args[0].AsInt32()));

    private void Builtin(Caller caller, ReadOnlySpan<ValueBox> args, Span<ValueBox> results)
    {
        var id = args[0].AsInt32();
        var name = _builtinNames.TryGetValue(id, out var known) ? known : "builtin#" + id;
        if (!HostBuiltins.IsImplemented(name) || OutsideBuiltins.Names.Contains(name, StringComparer.Ordinal))
        {
            _refused = name;
            throw new InvalidOperationException($"the host does not provide builtin {name}");
        }

        // The only implemented builtin is sprintf, with two arguments: the context and the two values follow the id.
        var result = HostBuiltins.Sprintf(DumpValue(args[2].AsInt32()), DumpValue(args[3].AsInt32()));
        results[0] = result is null ? 0 : Parse(result);
    }

    private string DumpValue(int address) => _memory.ReadNullTerminatedString(Call(_jsonDump, address));

    public void Dispose()
    {
        _store.Dispose();
        _linker.Dispose();
        _module.Dispose();
    }
}

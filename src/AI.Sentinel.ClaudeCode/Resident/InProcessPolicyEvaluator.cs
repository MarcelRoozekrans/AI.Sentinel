using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Evaluates in the hook process. The module loads on the first evaluation unless it was loaded already; a module that
/// cannot be loaded throws, on every evaluation.</summary>
internal sealed class InProcessPolicyEvaluator : IPolicyEvaluator, IDisposable
{
    private readonly Func<RegoPolicy> _load;
    private RegoPolicy? _policy;

    public InProcessPolicyEvaluator(Func<RegoPolicy> load) => _load = load;

    public InProcessPolicyEvaluator(RegoPolicy loaded)
    {
        _policy = loaded;
        _load = () => loaded;
    }

    public string Place => OutcomeDecision.InProcess;

    public RegoDecision? Evaluate(string inputJson)
    {
        _policy ??= _load();
        return _policy.Evaluate(inputJson);
    }

    public void Dispose() => _policy?.Dispose();
}

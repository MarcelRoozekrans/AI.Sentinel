using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>
/// The Rego policy of a folder, evaluated against each PreToolUse call and combined with what the other checks decided (#654).
/// It is the policy a PC uses without a server. It is read only when <see cref="FolderVariable"/> is set; without it the hook
/// does what it did before.
/// </summary>
internal sealed class LocalPolicy : IDisposable
{
    /// <summary>The environment variable that names the policy folder.</summary>
    public const string FolderVariable = "SENTINEL_HOOK_POLICY_DIR";

    /// <summary>The source an outcome of the other checks, the detectors, the approval rules and the placeholder guard, is named by.</summary>
    public const string ChecksSource = "sentinel-checks";

    /// <summary>The source the parser's answer for a command line it cannot read is named by.</summary>
    public const string ParserSource = "shell-parser";

    /// <summary>Why a command line that cannot be parsed asks, instead of leaving the call to the policy.</summary>
    public const string UnparseableReason = "AI.Sentinel could not parse this shell command line, so it cannot say what it does.";

    private readonly RegoPolicy _policy;
    private readonly string? _repositoryRoot;
    private readonly string _bundleSource;
    private readonly List<PolicyFinding> _findings = [];

    private LocalPolicy(RegoPolicy policy, string? repositoryRoot)
    {
        _policy = policy;
        _repositoryRoot = repositoryRoot;
        _bundleSource = "policy:" + string.Join(',', policy.Bundles);
    }

    /// <summary>The policy folder from the environment, or <see langword="null"/> when none is set.</summary>
    public static string? FolderFrom(IReadOnlyDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        return env.TryGetValue(FolderVariable, out var folder) && !string.IsNullOrWhiteSpace(folder) ? folder : null;
    }

    /// <summary>Loads the policy of <paramref name="folder"/>. Whatever fails here, the caller blocks the call.</summary>
    /// <param name="folder">The policy folder.</param>
    /// <param name="env">The settings; <c>SENTINEL_HOOK_POLICY_CACHE_DIR</c> moves the cache.</param>
    /// <param name="repositoryRoot">The root a path must lie under to count as inside the repository; the working directory
    /// of the hook when <see langword="null"/>.</param>
    /// <param name="compilers">The compilers to try; a hook passes <see cref="RegoPolicy.HookCompilers"/>, and
    /// <see cref="RegoPolicy.DefaultCompilers"/> is used when <see langword="null"/>.</param>
    public static LocalPolicy Load(
        string folder, IReadOnlyDictionary<string, string?> env, string? repositoryRoot = null, IReadOnlyList<IRegoCompiler>? compilers = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(folder);
        ArgumentNullException.ThrowIfNull(env);
        var policy = RegoPolicy.Load(folder, PolicyCache.DefaultDirectory(env), compilers);
        return new LocalPolicy(policy, repositoryRoot ?? Directory.GetCurrentDirectory());
    }

    /// <summary>Collects the findings of the scan, as detector id and severity name, for the policy to match on: set it as
    /// the <c>FindingSink</c> of the hook config before the scan runs.</summary>
    public Action<string, string> FindingSink => (detector, severity) => _findings.Add(new PolicyFinding(detector, severity));

    /// <summary>The version of the loaded policy, which an audit entry carries.</summary>
    public string Version => _policy.Version;

    /// <summary>
    /// Takes the decision for one tool call: builds the input, evaluates the policy and combines the outcome with
    /// <paramref name="existing"/>, the decision of the other checks, so the strictest wins. A shell command line the parser
    /// cannot read asks at least, whatever the policy says. When nobody has an opinion the existing output is returned as
    /// it is.
    /// </summary>
    /// <param name="existing">What the other checks decided.</param>
    /// <param name="cli">One of <see cref="PolicyClis"/>.</param>
    /// <param name="toolName">The tool the CLI is about to run.</param>
    /// <param name="toolInput">Its arguments.</param>
    /// <param name="session">The session id.</param>
    public HookOutput Decide(HookOutput existing, string cli, string toolName, JsonElement toolInput, string session)
    {
        ArgumentNullException.ThrowIfNull(existing);
        var input = PolicyInputBuilder.Build(cli, toolName, toolInput, session, _findings, _repositoryRoot);
        var policy = _policy.Evaluate(PolicyInputSerializer.Serialize(input));

        var decisions = new List<OutcomeDecision>(3)
        {
            existing.Outcome ?? OutcomeDecision.FromHook(existing.Decision, existing.Reason, ChecksSource),
        };
        if (policy.Outcome != DecisionOutcome.Defer)
        {
            decisions.Add(new OutcomeDecision(policy.Outcome, string.Join("; ", policy.Reasons), [SourceOf(policy)], _policy.Version));
        }

        var unparseable = input.Details.Shell is { Unparseable: true };
        if (unparseable)
        {
            decisions.Add(new OutcomeDecision(DecisionOutcome.Ask, UnparseableReason, [ParserSource], _policy.Version));
        }

        if (decisions.Count == 1 && decisions[0].Outcome == DecisionOutcome.Defer)
        {
            return existing;
        }

        var combined = OutcomeDecision.Strictest(decisions) with { PolicyVersion = _policy.Version };
        return combined.ToHookOutput(canAsk: true);
    }

    // A refused builtin is the host's doing, not a bundle's, so it names the builtin as its source.
    private string SourceOf(RegoDecision policy) => policy.Refused is { } builtin ? "builtin:" + builtin : _bundleSource;

    public void Dispose() => _policy.Dispose();
}

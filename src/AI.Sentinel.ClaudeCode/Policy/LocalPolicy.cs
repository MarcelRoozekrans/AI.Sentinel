using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;

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

    /// <summary>Why a patch whose target files cannot be read asks, instead of leaving the call to the policy.</summary>
    public const string PatchTargetsReason = "AI.Sentinel could not read which files this patch changes, so it cannot say what it touches.";

    /// <summary>Why a shell command line that cannot be parsed asks, instead of leaving the call to the policy.</summary>
    public const string UnparseableReason = "AI.Sentinel could not parse this shell command line, so it cannot say what it does.";

    private readonly EvaluationOrder _order;
    private readonly InProcessPolicyEvaluator? _inProcess;
    private readonly string? _repositoryRoot;
    private readonly string _bundleSource;
    private readonly string _bundleNames;
    private readonly FailModeContext? _failMode;
    private readonly List<PolicyFinding> _findings = [];
    private SeverityActions? _severities;
    private Repository.RepositoryPolicy? _repository;
    private bool _folderless;
    private bool _bundleFailed;

    private LocalPolicy(string version, IReadOnlyList<string> bundles, string? repositoryRoot, EvaluationOrder order, InProcessPolicyEvaluator? inProcess, FailModeContext? failMode)
    {
        _failMode = failMode;
        _bundleNames = string.Join(", ", bundles);
        Version = version;
        _order = order;
        _inProcess = inProcess;
        _repositoryRoot = repositoryRoot;
        _bundleSource = "policy:" + string.Join(',', bundles);
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
    /// <param name="failMode">What the hook knows about its profile (#673). When it is given, a call that no place could evaluate gets the
    /// fail mode, and a bundle that errors at runtime is denied by name; <see langword="null"/> keeps both as an internal error, which blocks.</param>
    /// <param name="resident">The resident process (#658), which is asked first for every evaluation and keeps the module warm; the
    /// module is then loaded in this process only when it does not answer in time. <see langword="null"/> when the resident
    /// process is not turned on, and then the module is loaded here, as before.</param>
    public static LocalPolicy Load(
        string folder, IReadOnlyDictionary<string, string?> env, string? repositoryRoot = null, IReadOnlyList<IRegoCompiler>? compilers = null,
        ResidentSession? resident = null, FailModeContext? failMode = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(folder);
        ArgumentNullException.ThrowIfNull(env);
        var cache = PolicyCache.DefaultDirectory(env);
        var root = repositoryRoot ?? Directory.GetCurrentDirectory();
        // A state folder that is not private is not used: the socket and the node map in it could be another user's. The hooks fail
        // closed, so the load fails and the caller blocks the call.
        if (resident?.Start == ResidentStart.Unusable)
        {
            throw new UnauthorizedAccessException(
                $"the resident state folder '{resident.Settings.StateDirectory}' and its .private sibling are open to other users, so the hook cannot use them; make the folder private to you");
        }

        var repository = Repository.RepositoryPolicy.Open(env, root);
        // Only a process that already ran is asked: a hook that started one, or failed to, does not wait for it and decides this call
        // in-process.
        if (resident is null || resident.Start != ResidentStart.AlreadyRunning)
        {
            var policy = RegoPolicy.Load(folder, cache, compilers);
            var only = new InProcessPolicyEvaluator(policy);
            return new LocalPolicy(policy.Version, policy.Bundles, root, new EvaluationOrder([only]), only, failMode) { _repository = repository };
        }

        // Reading the sources throws for a folder that cannot be read, as loading the module does. The module is not loaded here:
        // the resident process has it, and this process loads it only when that does not answer.
        var sources = PolicySources.Load(folder);
        var inProcess = new InProcessPolicyEvaluator(() => LoadRecorded(folder, cache, compilers, sources.Version));
        var residentEvaluator = new ResidentPolicyEvaluator(resident.Client, Path.GetFullPath(folder), sources.Version, Path.GetFullPath(cache));
        var local = new LocalPolicy(sources.Version, sources.Bundles, root, new EvaluationOrder([residentEvaluator, inProcess]), inProcess, failMode);
        local._repository = repository;
        try
        {
            // Evaluated now so that a policy that cannot run fails the load, which blocks the call with the policy as its reason.
            // With a fail mode the failure is kept instead, and Decide denies by name, as for any bundle that errors at runtime.
            local._severities = local.ReadSeverities();
        }
        catch
        {
            local.Dispose();
            throw;
        }

        return local;
    }

    /// <summary>What the block reason names for a repository policy that cannot be read, where a policy folder would be named.</summary>
    public const string RepositoryOnlyName = "repository policy";

    /// <summary>The policy of a PC that has a cached node map and no policy folder (#656): only the organisation's rules and the
    /// node's bundle of the repository judge a call, with no folder policy next to them. <see langword="null"/> when no node map is
    /// cached, and then the hook does what it did before. It evaluates no module, so it always has an answer and the fail mode
    /// never applies to it.</summary>
    /// <param name="env">The <c>SENTINEL_HOOK_</c> settings.</param>
    /// <param name="repositoryRoot">The working directory of the hook; the current directory when <see langword="null"/>.</param>
    /// <exception cref="InvalidDataException">The cached node map cannot be read; the caller blocks the call.</exception>
    public static LocalPolicy? LoadRepositoryOnly(IReadOnlyDictionary<string, string?> env, string? repositoryRoot = null)
    {
        ArgumentNullException.ThrowIfNull(env);
        var root = repositoryRoot ?? Directory.GetCurrentDirectory();
        return Repository.RepositoryPolicy.Open(env, root) is { } repository
            ? new LocalPolicy("repository", [], root, new EvaluationOrder([]), inProcess: null, failMode: null) { _repository = repository, _folderless = true }
            : null;
    }

    /// <summary>A policy over <paramref name="evaluators"/>, for a test that needs a place that is silent or fails.</summary>
    internal static LocalPolicy ForEvaluators(
        string version, IReadOnlyList<string> bundles, string? repositoryRoot, IReadOnlyList<IPolicyEvaluator> evaluators, FailModeContext? failMode) =>
        new(version, bundles, repositoryRoot, new EvaluationOrder(evaluators), new InProcessPolicyEvaluator(() => throw new InvalidOperationException("no module")), failMode);

    /// <summary>Collects the findings of the scan, as detector id and severity name, for the policy to match on: set it as
    /// the <c>FindingSink</c> of the hook config before the scan runs.</summary>
    public Action<string, string> FindingSink => (detector, severity) => _findings.Add(new PolicyFinding(detector, severity));

    /// <summary>The outcomes the policy sets per finding severity with <c>severity_actions</c>, read before the scan so the
    /// severity decision knows them. The rule is evaluated with an empty input, so it cannot depend on the tool call.</summary>
    /// <exception cref="FormatException">The policy names a severity or an outcome that does not exist; the caller blocks.</exception>
    public SeverityActions Severities() => _folderless ? SeverityActions.None : _severities ??= ReadSeverities();

    // With a fail mode a bundle that errors here is remembered and Decide denies by name; the severities are then none, which the
    // denial makes moot. Without one the error is thrown, as before. A place that stays silent is no error: the severities are
    // none and Decide leaves the call to the fail mode.
    private SeverityActions ReadSeverities()
    {
        try
        {
            return _order.TryEvaluate("{}")?.Decision.SeverityActions ?? SeverityActions.None;
        }
        catch (Exception) when (_failMode is not null)
        {
            _bundleFailed = true;
            return SeverityActions.None;
        }
    }

    /// <summary>The repository policy of the node that owns the repository (#656), or <see langword="null"/> when no node map is
    /// cached; the policy input then names no repository.</summary>
    internal Repository.RepositoryPolicy? RepositoryPolicy
    {
        get => _repository;
        set => _repository = value;
    }

    /// <summary>The version of the loaded policy, which an audit entry carries.</summary>
    public string Version { get; }

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
        var input = PolicyInputBuilder.Build(
            cli, toolName, toolInput, session, _findings, _repositoryRoot, _repository?.Scope.Repository ?? "", _repository?.Scope.Node ?? "");
        var json = PolicyInputSerializer.Serialize(input);
        var before = existing.Outcome ?? OutcomeDecision.FromHook(existing.Decision, existing.Reason, ChecksSource);
        if (_bundleFailed)
        {
            return OutcomeDecision.Strictest([before, BundleError()]).ToHookOutput(canAsk: true);
        }

        // The organisation's rules and the node's bundle (#656) are combined with the local folder strictest-wins, so the folder
        // can tighten what the profile sets and never loosen it.
        var repository = _repository?.Decisions(json) ?? [];
        PolicyAnswer? answer;
        try
        {
            // Without a folder there is no module of this process to ask; the repository's decisions are the whole policy.
            answer = _folderless
                ? new PolicyAnswer(new RegoDecision(DecisionOutcome.Defer, []), OutcomeDecision.InProcess)
                : _order.TryEvaluate(json);
        }
        catch (Exception) when (_failMode is not null)
        {
            // A place that failed ran the bundle and the bundle errored: that denies by name, whatever the fail mode. A bundle error of
            // the resident process ends the order before the in-process module is asked (#716), so its answer cannot stand in.
            return OutcomeDecision.Strictest([before, BundleError()]).ToHookOutput(canAsk: true);
        }

        if (answer is null)
        {
            // Nobody answered and nobody failed: the fail mode decides, and the repository's decisions still apply next to it. Without
            // one it is an internal error, as before.
            return _failMode is null
                ? throw new InvalidOperationException("no place could evaluate the policy: the resident process did not answer and the hook has no module to run")
                : OutcomeDecision.Strictest([before, .. repository, FailModeGate.Decide(_failMode, input, _repositoryRoot, Version)]).ToHookOutput(canAsk: true);
        }

        var (policy, place) = answer;
        var decisions = new List<OutcomeDecision>(3) { before };
        decisions.AddRange(repository);
        if (policy.Outcome != DecisionOutcome.Defer)
        {
            decisions.Add(new OutcomeDecision(policy.Outcome, string.Join("; ", policy.Reasons), [SourceOf(policy)], Version, place));
        }

        // The repository's rules read the same command line, so what the parser cannot read asks in every mode: an Allow from them
        // must not let it through.
        AddParserAsks(decisions, input);

        if (decisions.Count == 1 && decisions[0].Outcome == DecisionOutcome.Defer)
        {
            return existing;
        }

        var combined = OutcomeDecision.Strictest(decisions) with { PolicyVersion = Version };
        return combined.ToHookOutput(canAsk: true);
    }

    // A shell command line the parser cannot read, or a patch whose targets it cannot find, asks at least.
    private void AddParserAsks(List<OutcomeDecision> decisions, PolicyInput input)
    {
        if (input.Details.Shell is { Unparseable: true })
        {
            decisions.Add(new OutcomeDecision(DecisionOutcome.Ask, UnparseableReason, [ParserSource], Version));
        }

        if (input.Details.Paths is not { Count: > 0 } && PolicyInputBuilder.IsPatch(input))
        {
            decisions.Add(new OutcomeDecision(DecisionOutcome.Ask, PatchTargetsReason, [ParserSource], Version));
        }
    }

    // The message of the exception is left out: a module that aborts may echo what it was given, and that is the tool input.
    private OutcomeDecision BundleError() =>
        new(
            DecisionOutcome.Deny,
            $"The policy bundle {_bundleNames} failed while it ran, so this call is denied whatever the fail mode. Ask a policy owner to fix the bundle.",
            [_bundleSource], Version);

    // The decision, the severity actions and the audit entry carry the version read at load, so the module the fallback loads must be
    // that version. A folder that changed since does not answer: the call is blocked, as for any policy that cannot be evaluated.
    internal static RegoPolicy LoadRecorded(string folder, string cache, IReadOnlyList<IRegoCompiler>? compilers, string recorded)
    {
        var policy = RegoPolicy.Load(folder, cache, compilers);
        if (!string.Equals(policy.Version, recorded, StringComparison.Ordinal))
        {
            policy.Dispose();
            throw new InvalidOperationException($"the policy folder '{folder}' changed while the hook ran: it was version {recorded} when read and is {policy.Version} now");
        }

        return policy;
    }

    // A refused builtin is the host's doing, not a bundle's, so it names the builtin as its source.
    private string SourceOf(RegoDecision policy) => policy.Refused is { } builtin ? "builtin:" + builtin : _bundleSource;

    public void Dispose() => _inProcess?.Dispose();
}

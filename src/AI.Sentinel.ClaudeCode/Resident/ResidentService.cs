using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// What the resident process answers besides ping and shutdown: it keeps the compiled policy modules loaded, so a hook does not pay
/// for loading one. A module is kept per policy folder, and replaced when the hook names another version of that folder.
/// </summary>
internal sealed class ResidentService(
    IReadOnlyList<IRegoCompiler>? compilers, SignIn.TokenSession? tokens = null, PauseBoard? pauses = null, TimeProvider? time = null,
    ServerApprovals.IApprovalChannel? approvals = null) : IDisposable
{
    /// <summary>The most policy folders kept loaded; the least recently asked for goes first.</summary>
    private const int MaxLoaded = 8;

    private readonly Lock _gate = new();

    /// <summary>Test seam: called once the pause has been checked and the evaluation is about to start.</summary>
    internal Action? AfterPauseCheck { get; set; }

    private readonly List<(string Folder, RegoPolicy Policy)> _loaded = [];
    private readonly Dictionary<string, (RegoPolicy Policy, DateTimeOffset ExpiresAt)> _profiles = new(StringComparer.Ordinal);

    /// <summary>Loads the policy module of a profile, outside the gate, so a slow compile never holds up an answer. The module goes
    /// into a folder named by its hash, as <see cref="ProfileDecider"/> keeps it.</summary>
    public RegoPolicy LoadProfileModule(ResidentState state, string module) =>
        RegoPolicy.Load(ProfileDecider.ModuleFolder(state, module), Path.Combine(state.Directory, "compiled"), compilers);

    /// <summary>Puts <paramref name="policy"/> in place of the warm module of <paramref name="repository"/>; the next decision uses it,
    /// and a decision running now finishes on the module it started with. The profile answers until <paramref name="expiresAt"/>.</summary>
    public void InstallProfile(string repository, RegoPolicy policy, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(policy);
        lock (_gate)
        {
            if (_profiles.TryGetValue(repository, out var old))
            {
                old.Policy.Dispose();
            }

            _profiles[repository] = (policy, expiresAt);
        }
    }

    public ResidentResponse Answer(ResidentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Op is ResidentOps.SignIn or ResidentOps.SignInStatus)
        {
            return AnswerSignIn(request);
        }

        if (string.Equals(request.Op, ResidentOps.EvaluateProfile, StringComparison.Ordinal))
        {
            return AnswerProfile(request);
        }

        if (!string.Equals(request.Op, ResidentOps.Evaluate, StringComparison.Ordinal))
        {
            return new ResidentResponse { Error = $"unknown operation '{request.Op}'" };
        }

        if (string.IsNullOrEmpty(request.Folder) || string.IsNullOrEmpty(request.Version) || string.IsNullOrEmpty(request.CacheDirectory) || request.Input is null)
        {
            return new ResidentResponse { Error = "an evaluation names a folder, a version, a cache directory and an input" };
        }

        if (PausedAnswer(request) is { } paused)
        {
            return paused;
        }

        AfterPauseCheck?.Invoke();
        lock (_gate)
        {
            RegoPolicy policy;
            try
            {
                policy = Policy(request.Folder, request.Version, request.CacheDirectory);
            }
            // A module this process cannot load, or a folder that changed since the hook read it, is no answer: the hook loads the
            // version it read in-process, where a module that cannot load blocks the call.
#pragma warning disable CA1031 // Any load failure is no answer; see above.
            catch (Exception e)
#pragma warning restore CA1031
            {
                return new ResidentResponse { Error = e.GetType().Name };
            }

            return Evaluated(policy, request.Input);
        }
    }

    // The bundle ran here and failed: that is a bundle error, which the hook denies by name (ADR-237, #716), never no answer.
    private static ResidentResponse Evaluated(RegoPolicy policy, string input)
    {
        try
        {
            return ResidentDecisionWire.ToResponse(policy.Evaluate(input));
        }
#pragma warning disable CA1031 // Any failure of the run is the bundle's; the wire carries its type only.
        catch (Exception e)
#pragma warning restore CA1031
        {
            return ResidentDecisionWire.ToBundleError(e);
        }
    }

    /// <summary>Answers the approval operations by asking the server with the token of this process (#662); other operations are
    /// answered as <see cref="Answer"/> does.</summary>
    public async Task<ResidentResponse> AnswerAsync(ResidentRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Op is not (ResidentOps.ApprovalEnsure or ResidentOps.ApprovalGet))
        {
            return Answer(request);
        }

        var ensure = string.Equals(request.Op, ResidentOps.ApprovalEnsure, StringComparison.Ordinal);
        if (approvals is null)
        {
            return new ResidentResponse { Error = ServerApprovals.ResidentApprovalChannel.OffError };
        }

        if (ensure ? request.Approval is null : string.IsNullOrEmpty(request.RequestId))
        {
            return new ResidentResponse { Error = "an approval operation names its request" };
        }

        var reply = ensure
            ? await approvals.EnsureAsync(request.Approval!, ct).ConfigureAwait(false)
            : await approvals.GetAsync(request.RequestId!, ct).ConfigureAwait(false);
        return reply.Status switch
        {
            ServerApprovals.ApprovalChannelStatus.Ok when reply.State is not null => new ResidentResponse { Ok = true, Pid = Environment.ProcessId, Approval = reply.State },
            ServerApprovals.ApprovalChannelStatus.SignInNeeded => new ResidentResponse { Error = ResidentApprovalAnswer.SignInNeeded },
            ServerApprovals.ApprovalChannelStatus.Refused => new ResidentResponse { Error = ResidentApprovalAnswer.Refused },
            ServerApprovals.ApprovalChannelStatus.NotFound => new ResidentResponse { Error = ResidentApprovalAnswer.NotFound },
            _ => new ResidentResponse { Error = ResidentApprovalAnswer.Unreachable },
        };
    }

    // The pause is checked before the evaluation starts and never during it: a call that is running when the pause arrives completes.
    // A pause file that could not be read denies every call, as it does for a hook that reads the same file.
    private ResidentResponse? PausedAnswer(ResidentRequest request)
    {
        if (pauses?.Unreadable == true)
        {
            return ResidentDecisionWire.ToResponse(new RegoDecision(DecisionOutcome.Deny, ["AI.Sentinel: the pauses could not be read, so every session is treated as paused until the server sends them again."]));
        }

        return !string.IsNullOrEmpty(request.Session) && pauses?.Find(request.Session) is { } pause
            ? ResidentDecisionWire.ToResponse(new RegoDecision(DecisionOutcome.Deny, [pause.DenyReason()]))
            : null;
    }

    private ResidentResponse AnswerProfile(ResidentRequest request)
    {
        if (string.IsNullOrEmpty(request.Repository) || request.Input is null)
        {
            return new ResidentResponse { Error = "a profile evaluation names a repository and an input" };
        }

        if (PausedAnswer(request) is { } paused)
        {
            return paused;
        }

        lock (_gate)
        {
            if (!_profiles.TryGetValue(request.Repository, out var held))
            {
                return new ResidentResponse { Error = "no profile is held for the repository" };
            }

            // An expired profile is not used, as ProfileDecider and the cache do not use one; the caller falls back to its fail mode.
            return (time ?? TimeProvider.System).GetUtcNow() >= held.ExpiresAt
                ? new ResidentResponse { Error = "the profile held for the repository has expired" }
                : Evaluated(held.Policy, request.Input);
        }
    }

    private ResidentResponse AnswerSignIn(ResidentRequest request)
    {
        if (tokens is null)
        {
            return new ResidentResponse { Error = "sign-in is not configured", SignIn = "off" };
        }

        string? keychain = null;
        if (string.Equals(request.Op, ResidentOps.SignIn, StringComparison.Ordinal))
        {
            if (request.Tokens is null)
            {
                return new ResidentResponse { Error = "a sign-in carries tokens", SignIn = "sign_in_needed" };
            }

            // A refresh token goes to the token endpoint of the issuer the resident was started for, so tokens of another issuer are refused.
            if (!tokens.Accepts(request.Issuer, request.ClientId))
            {
                return new ResidentResponse
                {
                    Error = "the resident process is signed in at another identity provider; restart it to use this sign-in",
                    SignIn = "issuer_mismatch",
                };
            }

            keychain = tokens.Set(request.Tokens) switch
            {
                SignIn.KeychainState.Kept => "kept",
                SignIn.KeychainState.MemoryOnly => "memory_only",
                _ => "earlier_remains",
            };
        }

        return new ResidentResponse
        {
            Ok = true,
            Pid = Environment.ProcessId,
            SignIn = tokens.Status == SignIn.SignInStatus.SignedIn ? "signed_in" : "sign_in_needed",
            Keychain = keychain,
        };
    }

    // Called under the gate. A WasmEvaluator is not thread safe, so one evaluation runs at a time.
    private RegoPolicy Policy(string folder, string version, string cacheDirectory)
    {
        var index = _loaded.FindIndex(l => string.Equals(l.Folder, folder, StringComparison.Ordinal));
        if (index >= 0)
        {
            var held = _loaded[index].Policy;
            if (string.Equals(held.Version, version, StringComparison.Ordinal))
            {
                _loaded.RemoveAt(index);
                _loaded.Add((folder, held));
                return held;
            }

            held.Dispose();
            _loaded.RemoveAt(index);
        }

        var policy = RegoPolicy.Load(folder, cacheDirectory, compilers);
        if (!string.Equals(policy.Version, version, StringComparison.Ordinal))
        {
            // The folder changed between the hook's read and this one. The hook evaluates the version it read.
            policy.Dispose();
            throw new InvalidOperationException("the policy folder changed");
        }

        if (_loaded.Count >= MaxLoaded)
        {
            _loaded[0].Policy.Dispose();
            _loaded.RemoveAt(0);
        }

        _loaded.Add((folder, policy));
        return policy;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var (_, policy) in _loaded)
            {
                policy.Dispose();
            }

            _loaded.Clear();
            foreach (var (policy, _) in _profiles.Values)
            {
                policy.Dispose();
            }

            _profiles.Clear();
        }
    }
}

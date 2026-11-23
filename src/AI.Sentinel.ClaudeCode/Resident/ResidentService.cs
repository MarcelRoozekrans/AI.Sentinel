using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// What the resident process answers besides ping and shutdown: it keeps the compiled policy modules loaded, so a hook does not pay
/// for loading one. A module is kept per policy folder, and replaced when the hook names another version of that folder.
/// </summary>
internal sealed class ResidentService(IReadOnlyList<IRegoCompiler>? compilers, SignIn.TokenSession? tokens = null) : IDisposable
{
    /// <summary>The most policy folders kept loaded; the least recently asked for goes first.</summary>
    private const int MaxLoaded = 8;

    private readonly Lock _gate = new();
    private readonly List<(string Folder, RegoPolicy Policy)> _loaded = [];

    public ResidentResponse Answer(ResidentRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Op is ResidentOps.SignIn or ResidentOps.SignInStatus)
        {
            return AnswerSignIn(request);
        }

        if (!string.Equals(request.Op, ResidentOps.Evaluate, StringComparison.Ordinal))
        {
            return new ResidentResponse { Error = $"unknown operation '{request.Op}'" };
        }

        if (string.IsNullOrEmpty(request.Folder) || string.IsNullOrEmpty(request.Version) || string.IsNullOrEmpty(request.CacheDirectory) || request.Input is null)
        {
            return new ResidentResponse { Error = "an evaluation names a folder, a version, a cache directory and an input" };
        }

        try
        {
            lock (_gate)
            {
                var policy = Policy(request.Folder, request.Version, request.CacheDirectory);
                return ResidentDecisionWire.ToResponse(policy.Evaluate(request.Input));
            }
        }
#pragma warning disable CA1031 // The hook gets the failure as no answer, and evaluates in-process, where the same failure blocks the call.
        catch (Exception e)
#pragma warning restore CA1031
        {
            return new ResidentResponse { Error = e.GetType().Name };
        }
    }

    private ResidentResponse AnswerSignIn(ResidentRequest request)
    {
        if (tokens is null)
        {
            return new ResidentResponse { Error = "sign-in is not configured", SignIn = "off" };
        }

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

            tokens.Set(request.Tokens);
        }

        return new ResidentResponse
        {
            Ok = true,
            Pid = Environment.ProcessId,
            SignIn = tokens.Status == SignIn.SignInStatus.SignedIn ? "signed_in" : "sign_in_needed",
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
        }
    }
}

using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The verb a hook CLI signs in with: <c>sentinel-hook --sign-in</c> (#659). It runs the device code flow, pins the server keys, keeps
/// the refresh token in the keychain and hands the tokens to the resident process, which holds and refreshes them from then on. It is
/// off unless the server and the OIDC client are set. Nothing it prints holds a token.
/// </summary>
internal static class SignInCommand
{
    public const string Verb = "--sign-in";

    public static bool Matches(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Length > 0 && string.Equals(args[0], Verb, StringComparison.Ordinal);
    }

    /// <summary>The token session for the resident process, or <see langword="null"/> when sign-in is not configured.</summary>
    public static TokenSession? OpenSession(IReadOnlyDictionary<string, string?> env, HttpClient http, TextWriter log)
    {
        var settings = SignInSettings.FromEnvironment(env, out var problem);
        if (settings is null)
        {
            if (problem is not null)
            {
                log.WriteLine($"sign-in is off: {problem}");
            }

            return null;
        }

        return new TokenSession(new OidcDeviceClient(http, settings, TimeProvider.System), TokenStores.ForCurrentOs(settings, line => log.WriteLine(line)), TimeProvider.System, line => log.WriteLine(line));
    }

    /// <param name="env">The <c>SENTINEL_HOOK_</c> variables.</param>
    /// <param name="stdout">Where the code and the address for the developer go.</param>
    /// <param name="stderr">Where problems and the keychain log go; never a token.</param>
    /// <param name="handler">The HTTP handler, a fake in tests.</param>
    /// <param name="store">The keychain; the one of the operating system when <see langword="null"/>.</param>
    /// <param name="delay">The wait between polls; a real wait when <see langword="null"/>.</param>
    /// <param name="launch">What starts the resident process; this hook when <see langword="null"/>.</param>
    /// <param name="start">Starts it, a fake in tests.</param>
    public static async Task<int> RunAsync(
        IReadOnlyDictionary<string, string?> env, TextWriter stdout, TextWriter stderr, HttpMessageHandler? handler = null,
        ITokenStore? store = null, Func<TimeSpan, CancellationToken, Task>? delay = null, ResidentLaunch? launch = null,
        Func<ResidentLaunch, bool>? start = null, TimeProvider? time = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(env);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);
        var settings = SignInSettings.FromEnvironment(env, out var problem);
        if (settings is null)
        {
            await stderr.WriteLineAsync(problem is null
                ? $"sign-in is off: set {SignInSettings.ServerVariable}, {SignInSettings.IssuerVariable} and {SignInSettings.ClientIdVariable}"
                : $"sign-in is off: {problem}").ConfigureAwait(false);
            return 1;
        }

        time ??= TimeProvider.System;
        store ??= TokenStores.ForCurrentOs(settings, line => stderr.WriteLine(line));
        using var http = handler is null ? NoRedirects() : new HttpClient(handler, disposeHandler: false);
        SignInOutcome outcome;
        try
        {
            outcome = await new DeviceCodeSignIn(new OidcDeviceClient(http, settings, time, delay), http, settings)
                .RunAsync(a => Show(stdout, a), ct).ConfigureAwait(false);
        }
        catch (SignInException e)
        {
            await stderr.WriteLineAsync($"sign-in failed: {e.Message}").ConfigureAwait(false);
            return 1;
        }

        // The keys are pinned with the sign-in, whatever happens to the token below.
        var resident = ResidentSettings.Always(env);
        ResidentState.Open(resident).WritePinnedKeys(outcome.Organisation, outcome.Keys);

        var (kept, earlierRemains) = await KeepAsync(outcome.Tokens, store, stderr).ConfigureAwait(false);

        var handedOver = await HandOverAsync(env, resident, settings, outcome.Tokens, launch, start, ct).ConfigureAwait(false);
        if (!handedOver && !kept)
        {
            await stderr.WriteLineAsync(
                $"sign-in is not kept: there is no keychain and the resident process did not take it. Set {ResidentSettings.EnableVariable}=on and sign in again.").ConfigureAwait(false);
            return 1;
        }

        if (!handedOver)
        {
            await stdout.WriteLineAsync(
                $"The sign-in to {outcome.Organisation} is in the keychain, and {outcome.Keys.Count} server key(s) are pinned. The running resident process did not take it. It uses the sign-in only after it restarts with the same server, issuer and client settings as this command.").ConfigureAwait(false);
            return earlierRemains ? 1 : 0;
        }

        await stdout.WriteLineAsync($"Signed in to {outcome.Organisation}; {outcome.Keys.Count} server key(s) pinned.").ConfigureAwait(false);
        if (!kept && outcome.Tokens.RefreshToken is not null)
        {
            await stdout.WriteLineAsync("There is no keychain here: the sign-in lasts until the resident process ends.").ConfigureAwait(false);
        }

        return earlierRemains ? 1 : 0;
    }

    /// <summary>A client that does not follow a redirect: a token form is posted to the endpoint the provider advertised and to no other.</summary>
    internal static HttpClient NoRedirects() => new(new SocketsHttpHandler { AllowAutoRedirect = false });

    // The refresh token goes into the keychain. Without one to keep, the token of an earlier sign-in must go, or a restart would resume it.
    private static async Task<(bool Kept, bool EarlierRemains)> KeepAsync(TokenSet tokens, ITokenStore? store, TextWriter stderr)
    {
        var kept = tokens.RefreshToken is { } refresh && store is not null && store.Save(refresh);
        var earlierRemains = !kept && store is not null && !store.Delete();
        if (earlierRemains)
        {
            await stderr.WriteLineAsync($"the {store!.Name} still holds the refresh token of an earlier sign-in; it could not be removed. Remove it, or a restart of the resident process signs in as the earlier account.").ConfigureAwait(false);
        }

        return (kept, earlierRemains);
    }

    private static void Show(TextWriter stdout, DeviceAuthorization a)
    {
        stdout.WriteLine($"Open {a.VerificationUri} and enter the code {a.UserCode}");
        if (a.VerificationUriComplete is not null)
        {
            stdout.WriteLine($"or open {a.VerificationUriComplete}");
        }
    }

    // The tokens go over the private local socket, only to the resident process of this user.
    private static async Task<bool> HandOverAsync(
        IReadOnlyDictionary<string, string?> env, ResidentSettings resident, SignInSettings settings, TokenSet tokens, ResidentLaunch? launch,
        Func<ResidentLaunch, bool>? start, CancellationToken ct)
    {
        if (ResidentOff(env, resident))
        {
            return false;
        }

        _ = ResidentLauncher.EnsureStarted(resident, launch ?? ResidentLaunch.ForThisHook(), start);
        var client = new ResidentClient(resident);
        for (var attempt = 0; attempt < 50 && !ct.IsCancellationRequested; attempt++)
        {
            var response = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignIn, Tokens = tokens, Issuer = settings.Issuer.AbsoluteUri, ClientId = settings.ClientId }, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            if (response is not null)
            {
                return response.Ok;
            }

            await Task.Delay(100, ct).ConfigureAwait(false);
        }

        return false;
    }

    // The resident process is on only when the developer turned it on; sign-in does not start it on its own.
    private static bool ResidentOff(IReadOnlyDictionary<string, string?> env, ResidentSettings resident) =>
        ResidentSettings.FromEnvironment(env) is null && !ResidentLauncher.IsRunning(resident);
}

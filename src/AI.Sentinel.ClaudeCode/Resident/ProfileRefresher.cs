using System.Net;
using System.Text.Json;
using System.Threading.Channels;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Keeps the signed profiles of the resident process current. It fetches them at start, when the server announces a configuration, after
/// every reconnect, and before the cached one expires: a day before, or halfway through a shorter lifetime, and at once when that point
/// has passed. A failed fetch is tried again with bounded backoff while the last valid profile stays in force. A profile is checked as
/// a cached one is (#671), compiled, written to the cache and made the warm module, in that order, and only when it is newer than the
/// one in force by configuration version and issue time, so the cache and the warm module never disagree.
/// </summary>
internal sealed class ProfileRefresher(
    ResidentState state, HttpClient http, Uri server, ResidentService warm, ServerLinkTiming timing, TimeProvider time, Action<string>? log = null)
{
    /// <summary>Where the server serves a signed profile, as <c>MapAISentinelPolicyServer</c> maps it by default.</summary>
    public const string ProfilePath = "/ai-sentinel/policy/profile";

    /// <summary>Where the server serves the node map.</summary>
    public const string NodeMapPath = "/ai-sentinel/policy/node-map";

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, PolicyProfile> _held = new(StringComparer.Ordinal);
    private readonly Channel<byte> _signal = Channel.CreateBounded<byte>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });
    private volatile bool _forced;
    private DateTimeOffset? _retryAt;
    private DateTimeOffset? _lastSuccess;
    private int _failures;
    private long _fetches;
    private readonly Lock _sync = new();
    private long _announced;
    private bool _running;

    /// <summary>How many profile requests were sent to the server; a test counts them.</summary>
    public long Fetches => Interlocked.Read(ref _fetches);

    /// <summary>The newest configuration version held, or 0.</summary>
    public long HeldVersion
    {
        get
        {
            lock (_held)
            {
                return _held.Count == 0 ? 0 : _held.Values.Max(p => p.ConfigurationVersion);
            }
        }
    }

    /// <summary>The configuration version held for <paramref name="repository"/>, or <see langword="null"/>.</summary>
    public long? HeldVersionOf(string repository)
    {
        lock (_held)
        {
            return _held.TryGetValue(repository, out var p) ? p.ConfigurationVersion : null;
        }
    }

    /// <summary>Fetch now: the connection to the server was made again, or the process starts.</summary>
    public void Wake()
    {
        _forced = true;
        _signal.Writer.TryWrite(0);
    }

    /// <summary>The server announced that <paramref name="version"/> came into force. Nothing is fetched for a version that is not newer
    /// than the one held.</summary>
    public void Announce(long version)
    {
        lock (_sync)
        {
            _announced = Math.Max(_announced, version);
            // A round that is running now may fetch this version itself; when it ends it looks again.
            if (_running || version <= HeldVersion)
            {
                return;
            }
        }

        Wake();
    }

    /// <summary>Runs until <paramref name="ct"/> ends.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        try
        {
            LoadCached();
            Wake();
            while (!ct.IsCancellationRequested)
            {
                await WaitAsync(NextWait(), ct).ConfigureAwait(false);
                if (!_forced && NextWait() != TimeSpan.Zero)
                {
                    continue;
                }

                lock (_sync)
                {
                    _forced = false;
                    _running = true;
                }

                var ok = await RoundAsync(ct).ConfigureAwait(false);
                lock (_sync)
                {
                    _running = false;
                    // Announced while the round ran, and the round did not bring it: fetch again.
                    if (ok && _announced > HeldVersion)
                    {
                        _forced = true;
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The process is stopping.
        }
    }

    /// <summary>One fetch of the node map and of every profile it names, and of the organisation's. Returns whether it all worked.</summary>
    internal async Task<bool> RoundAsync(CancellationToken ct)
    {
        var ok = await TryRoundAsync(ct).ConfigureAwait(false);
        var now = time.GetUtcNow();
        if (ok)
        {
            _failures = 0;
            _retryAt = null;
            _lastSuccess = now;
        }
        else
        {
            var wait = timing.FetchBackoffInitial * Math.Pow(2, Math.Min(_failures, 20));
            _failures++;
            _retryAt = now + (wait > timing.FetchBackoffMax ? timing.FetchBackoffMax : wait);
        }

        return ok;
    }

    private async Task<bool> TryRoundAsync(CancellationToken ct)
    {
        try
        {
            if (state.ReadPinnedKeys() is null)
            {
                // Not signed in: there are no keys to check a profile against, and a sign-in reconnects the link, which wakes this.
                return true;
            }

            var map = await FetchNodeMapAsync(ct).ConfigureAwait(false);
            var allOk = map is not null;
            var repositories = new List<string> { CachedNodePolicies.OrganisationRepository };
            if (map is not null)
            {
                repositories.AddRange(map.Repositories);
            }

            foreach (var repository in repositories)
            {
                allOk &= await FetchProfileAsync(repository, ct).ConfigureAwait(false);
            }

            return allOk;
        }
        catch (Exception e) when (e is HttpRequestException or IOException or JsonException or InvalidDataException or SignIn.SignInRequiredException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            log?.Invoke($"the profiles could not be fetched ({e.GetType().Name}); the last valid profile stays in force");
            return false;
        }
    }

    private async Task<NodeMap?> FetchNodeMapAsync(CancellationToken ct)
    {
        using var response = await http.GetAsync(new Uri(server, NodeMapPath), ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            log?.Invoke($"the node map was refused: {(int)response.StatusCode}");
            return null;
        }

        var map = NodeMap.FromJson(await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false));
        state.WriteNodeMap(map);
        return map;
    }

    private async Task<bool> FetchProfileAsync(string repository, CancellationToken ct)
    {
        Interlocked.Increment(ref _fetches);
        using var response = await http.GetAsync(new Uri(server, $"{ProfilePath}?repository={Uri.EscapeDataString(repository)}"), ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            // No node owns the repository any more: nothing to fetch, and the cached profile ages out.
            return true;
        }

        if (!response.IsSuccessStatusCode)
        {
            log?.Invoke($"the profile of a repository was refused: {(int)response.StatusCode}");
            return false;
        }

        var signed = SignedProfile.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        return signed is not null && await OfferAsync(repository, signed, ct).ConfigureAwait(false) != ProfileOffer.Refused;
    }

    /// <summary>Checks <paramref name="signed"/> and, when it is valid and newer than the profile in force, writes it to the cache and
    /// makes it the warm module. Offers run one at a time, so a profile from an earlier fetch that finishes late cannot replace a newer one.</summary>
    public async Task<ProfileOffer> OfferAsync(string repository, SignedProfile signed, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (state.ReadPinnedKeys() is not { } pinned)
            {
                return ProfileOffer.Refused;
            }

            var now = time.GetUtcNow();
            var verification = ProfileVerifier.Verify(signed, pinned.Keys, pinned.Organisation, repository, now);
            if (!verification.IsAccepted)
            {
                log?.Invoke($"a profile was refused: {verification.Rejection}");
                return ProfileOffer.Refused;
            }

            var profile = verification.Profile!;
            PolicyProfile? held;
            lock (_held)
            {
                _held.TryGetValue(repository, out held);
            }

            if (held is not null && !IsNewer(profile, held))
            {
                return ProfileOffer.Stale;
            }

            return Install(repository, signed, profile, pinned, now) ? ProfileOffer.Installed : ProfileOffer.Refused;
        }
        finally
        {
            _gate.Release();
        }
    }

    // Compiled first: a module that does not load leaves the cache and the warm module as they were.
    private bool Install(string repository, SignedProfile signed, PolicyProfile profile, (string Organisation, PinnedProfileKeys Keys) pinned, DateTimeOffset now)
    {
        Policy.Rego.RegoPolicy policy;
        try
        {
            policy = warm.LoadProfileModule(state, profile.Module);
        }
#pragma warning disable CA1031 // A module that cannot be loaded, for whatever reason, is refused and the last valid profile stays.
        catch (Exception e)
#pragma warning restore CA1031
        {
            log?.Invoke($"the policy module of a profile did not load ({e.GetType().Name}); the last valid profile stays in force");
            return false;
        }

        if (!state.StoreProfile(signed, pinned.Keys, pinned.Organisation, repository, now, CachedNodePolicies.SlotOf(repository)).IsAccepted)
        {
            policy.Dispose();
            return false;
        }

        warm.InstallProfile(repository, policy);
        lock (_held)
        {
            _held[repository] = profile;
        }

        return true;
    }

    private static bool IsNewer(PolicyProfile candidate, PolicyProfile held) =>
        candidate.ConfigurationVersion > held.ConfigurationVersion
        || (candidate.ConfigurationVersion == held.ConfigurationVersion && candidate.IssuedAt > held.IssuedAt);

    // The cache outlives the process, so what it holds is in force from the start, and its expiry is what the schedule is planned from.
    private void LoadCached()
    {
        if (state.ReadPinnedKeys() is not { } pinned)
        {
            return;
        }

        var repositories = new List<string> { CachedNodePolicies.OrganisationRepository };
        try
        {
            if (state.ReadNodeMap() is { } map)
            {
                repositories.AddRange(map.Repositories);
            }
        }
        catch (InvalidDataException)
        {
            // An unreadable map names no repository here; the first fetch replaces it.
        }

        var now = time.GetUtcNow();
        foreach (var repository in repositories)
        {
            var verification = state.ReadProfile(pinned.Keys, pinned.Organisation, repository, now, CachedNodePolicies.SlotOf(repository));
            if (verification is not { IsAccepted: true })
            {
                continue;
            }

            try
            {
                warm.InstallProfile(repository, warm.LoadProfileModule(state, verification.Profile!.Module));
                lock (_held)
                {
                    _held[repository] = verification.Profile;
                }
            }
#pragma warning disable CA1031 // A cached module that does not load is as good as none: the first fetch replaces it.
            catch (Exception e)
#pragma warning restore CA1031
            {
                log?.Invoke($"a cached profile did not load ({e.GetType().Name})");
            }
        }
    }

    // How long until something is due; null when nothing is planned, and zero when it is due now.
    private TimeSpan? NextWait()
    {
        var now = time.GetUtcNow();
        DateTimeOffset? at = _retryAt;
        DateTimeOffset? timer = null;
        lock (_held)
        {
            foreach (var profile in _held.Values)
            {
                var due = timing.RefreshAt(profile.IssuedAt, profile.ExpiresAt);
                timer = timer is null || due < timer ? due : timer;
            }
        }

        if (timer is { } planned)
        {
            if (_lastSuccess is { } last && planned < last + timing.MinFetchGap)
            {
                planned = last + timing.MinFetchGap;
            }

            at = at is null || planned < at ? planned : at;
        }

        return at is null ? null : at.Value <= now ? TimeSpan.Zero : at.Value - now;
    }

    private async Task WaitAsync(TimeSpan? wait, CancellationToken ct)
    {
        if (_forced || wait == TimeSpan.Zero)
        {
            return;
        }

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var delay = Task.Delay(wait ?? Timeout.InfiniteTimeSpan, time, stop.Token);
        var signalled = _signal.Reader.WaitToReadAsync(stop.Token).AsTask();
        _ = await Task.WhenAny(delay, signalled).ConfigureAwait(false);
        await stop.CancelAsync().ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        while (_signal.Reader.TryRead(out _))
        {
        }

        // Observed, so a cancelled wait never surfaces as an unobserved exception.
        try
        {
            await Task.WhenAll(delay, signalled).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The loser of the race was cancelled above.
        }
    }
}

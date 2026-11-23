using System.Threading.Channels;
using AI.Sentinel.AspNetCore.AdminAudit;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>
/// Keeps the newest complete, valid version of a policy folder in force (ADR-107, ADR-236). A pass resolves the folder's real path
/// once, reads every file into memory, compiles from that copy, reads the folder again and publishes only when the second read equals
/// the copy and the folder still resolves to the same place. A failed read or a change during the pass publishes nothing and is retried
/// with bounded backoff. Passes run one at a time, so a version read earlier never replaces one read later.
/// </summary>
internal sealed class PolicyFolderLoader
{
    private readonly string _folder;
    private readonly ConfigurationCompiler _compiler;
    private readonly Func<string, AdminAuditAction, string, CancellationToken, ValueTask> _audit;
    private readonly string _fallbackOrganisation;
    private readonly TimeProvider _time;
    private readonly PolicyFolderTiming _timing;
    private readonly ILogger _log;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Channel<byte> _signal = Channel.CreateBounded<byte>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });
    private PublishedConfiguration? _current;
    private long _sequence;
    private string? _lastRejected;

    /// <param name="folder">The policy folder; it may be a link, as git-sync's is.</param>
    /// <param name="compiler">Checks and compiles one read.</param>
    /// <param name="audit">Records a publish or a rejected publish: organisation, action, target.</param>
    /// <param name="fallbackOrganisation">The organisation a rejection is recorded under when the node configuration is not readable.</param>
    public PolicyFolderLoader(
        string folder, ConfigurationCompiler compiler, Func<string, AdminAuditAction, string, CancellationToken, ValueTask> audit,
        string fallbackOrganisation, TimeProvider time, PolicyFolderTiming timing, ILogger log)
    {
        _folder = folder;
        _compiler = compiler;
        _audit = audit;
        _fallbackOrganisation = fallbackOrganisation;
        _time = time;
        _timing = timing;
        _log = log;
    }

    /// <summary>The configuration in force, or <see langword="null"/> before the first one was published.</summary>
    public PublishedConfiguration? Current => Volatile.Read(ref _current);

    /// <summary>Test seam: called after each file a pass reads from the folder, with the pass number counting from 1 for the first read
    /// and 2 for the second.</summary>
    internal Action<int, string>? AfterFileRead { get; set; }

    /// <summary>Raised after a configuration has come into force, with that configuration. A handler must not throw and must not block.</summary>
    public event EventHandler<ConfigurationPublishedEventArgs>? Published;

    /// <summary>Tells the loader that the folder may have changed.</summary>
    public void Notify() => _signal.Writer.TryWrite(0);

    /// <summary>Runs one pass. Passes started together run one after the other.</summary>
    public async Task<PassResult> ReloadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await PassAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Runs passes until <paramref name="ct"/> ends: at start, after changes have settled, and at every poll interval.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        Notify();
        while (!ct.IsCancellationRequested)
        {
            await WaitForSignalAsync(ct).ConfigureAwait(false);
            await SettleAsync(ct).ConfigureAwait(false);
            await PassWithRetriesAsync(ct).ConfigureAwait(false);
        }
    }

    private async Task PassWithRetriesAsync(CancellationToken ct)
    {
        for (var attempt = 0; attempt < _timing.MaxAttempts && !ct.IsCancellationRequested; attempt++)
        {
            if (await ReloadAsync(ct).ConfigureAwait(false) != PassResult.Retry)
            {
                return;
            }

            await Task.Delay(_timing.Backoff(attempt), _time, ct).ConfigureAwait(false);
        }
    }

    private async Task WaitForSignalAsync(CancellationToken ct)
    {
        using var poll = CancellationTokenSource.CreateLinkedTokenSource(ct);
        poll.CancelAfter(_timing.PollInterval);
        try
        {
            await _signal.Reader.WaitToReadAsync(poll.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The poll interval is up: look again, a link swap raises no event.
        }
    }

    private async Task SettleAsync(CancellationToken ct)
    {
        do
        {
            while (_signal.Reader.TryRead(out _))
            {
            }

            await Task.Delay(_timing.Settle, _time, ct).ConfigureAwait(false);
        }
        while (_signal.Reader.TryRead(out _));
    }

    private async Task<PassResult> PassAsync(CancellationToken ct)
    {
        ConfigurationFiles first;
        string real;
        try
        {
            real = ConfigurationFiles.Resolve(_folder);
            first = ConfigurationFiles.Read(real, name => AfterFileRead?.Invoke(1, name));
        }
        catch (InvalidDataException e)
        {
            return await RejectUnreadableAsync(e, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _log.LogWarning("The policy folder could not be read ({Error}); trying again.", e.GetType().Name);
            return PassResult.Retry;
        }

        if (Current is { } now && string.Equals(now.Fingerprint, first.Fingerprint, StringComparison.Ordinal))
        {
            return PassResult.Unchanged;
        }

        if (string.Equals(_lastRejected, first.Fingerprint, StringComparison.Ordinal))
        {
            return PassResult.Rejected;
        }

        ConfigurationVerdict verdict;
        try
        {
            verdict = await Task.Run(() => _compiler.Check(first), ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // The compiler could not run or timed out: that says nothing about the policy, so it is not a rejection.
            _log.LogError("The policy could not be compiled ({Error}); the last good configuration stays in force.", e.GetType().Name);
            return PassResult.Retry;
        }

        if (!StillTheSame(real, first))
        {
            _log.LogInformation("The policy folder changed while it was compiled; nothing was published.");
            return PassResult.Retry;
        }

        return verdict.IsAccepted
            ? await PublishAsync(first, verdict, ct).ConfigureAwait(false)
            : await RejectAsync(first, verdict, ct).ConfigureAwait(false);
    }

    private bool StillTheSame(string real, ConfigurationFiles first)
    {
        try
        {
            if (!string.Equals(ConfigurationFiles.Resolve(_folder), real, StringComparison.Ordinal))
            {
                return false;
            }

            var second = ConfigurationFiles.Read(real, name => AfterFileRead?.Invoke(2, name));
            return first.SameAs(second);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return false;
        }
    }

    private async Task<PassResult> PublishAsync(ConfigurationFiles files, ConfigurationVerdict verdict, CancellationToken ct)
    {
        var version = verdict.Nodes!.Version ?? Interlocked.Increment(ref _sequence);
        var configuration = new PublishedConfiguration(
            verdict.Organisation!, version, files.Fingerprint, verdict.Module!, verdict.ModuleHash!, verdict.Modules!, verdict.Nodes!);
        try
        {
            // Recorded first: a configuration whose publish is not in the audit log does not come into force.
            await _audit(configuration.Organisation, AdminAuditAction.Publish, $"configuration {version} module {configuration.ModuleHash[..16]}", ct)
                .ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            _log.LogError("The publish could not be written to the audit log ({Error}); not published.", e.GetType().Name);
            return PassResult.Retry;
        }

        Volatile.Write(ref _current, configuration);
        _lastRejected = null;
        _log.LogInformation("Published configuration {Version} of {Organisation}.", version, configuration.Organisation);
        Published?.Invoke(this, new ConfigurationPublishedEventArgs(configuration));
        return PassResult.Published;
    }

    private async Task<PassResult> RejectAsync(ConfigurationFiles files, ConfigurationVerdict verdict, CancellationToken ct)
    {
        if (!string.Equals(_lastRejected, files.Fingerprint, StringComparison.Ordinal))
        {
            var organisation = verdict.Organisation ?? Current?.Organisation ?? _fallbackOrganisation;
            try
            {
                await _audit(organisation, AdminAuditAction.RejectedPublish, $"{files.Fingerprint[..16]} {verdict.Reason}", ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                _log.LogError("The rejected publish could not be written to the audit log ({Error}).", e.GetType().Name);
                return PassResult.Retry;
            }

            _lastRejected = files.Fingerprint;
            _log.LogWarning("The policy folder was refused: {Reason}. {Detail}. The last good configuration stays in force.", verdict.Reason, verdict.Detail);
        }

        return PassResult.Rejected;
    }

    private async Task<PassResult> RejectUnreadableAsync(InvalidDataException e, CancellationToken ct)
    {
        var key = "unreadable:" + e.Message;
        if (!string.Equals(_lastRejected, key, StringComparison.Ordinal))
        {
            try
            {
                await _audit(Current?.Organisation ?? _fallbackOrganisation, AdminAuditAction.RejectedPublish,
                    $"folder {RejectionReasons.InvalidFolder}", ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return PassResult.Retry;
            }

            _lastRejected = key;
            _log.LogWarning("The policy folder was refused: {Message}. The last good configuration stays in force.", e.Message);
        }

        return PassResult.Rejected;
    }
}

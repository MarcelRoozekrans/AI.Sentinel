using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>
/// Sends the events of the local audit to the server (#661, ADR-240, ADR-247). The hooks send nothing: they write the audit, and the
/// resident process reads it from a stored cursor, in order, and posts it in batches. The cursor moves after the server took a batch,
/// so an outage loses nothing and a batch that is sent again carries the same event ids. A failed send is logged and retried, and never
/// reaches a decision, because no decision waits for it.
/// </summary>
/// <param name="source">The local audit.</param>
/// <param name="cursor">Where the last accepted entry is kept.</param>
/// <param name="http">The client; its handler adds the token for the server.</param>
/// <param name="endpoint">The ingest address.</param>
/// <param name="organisation">The organisation signed in to; <see langword="null"/> until the developer has signed in.</param>
/// <param name="detailedLogging">Whether a node turned on detailed logging.</param>
/// <param name="log">Where problems go; never a token or an event.</param>
/// <param name="batchSize">The most events in one request.</param>
internal sealed class EventForwarder(
    IAuditSource source, EventCursor cursor, HttpClient http, Uri endpoint, Func<string?> organisation, Func<string?, bool> detailedLogging,
    Action<string>? log = null, int batchSize = 200)
{
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(5);

    /// <summary>Sends what the server has not taken yet.</summary>
    public async Task<ForwardResult> ForwardAsync(CancellationToken ct)
    {
        if (await StartAsync(ct).ConfigureAwait(false) is not var (after, hasCursor))
        {
            return new ForwardResult(0, 0, Failed: true);
        }

        var (sent, prunedTotal) = (0, 0);
        while (true)
        {
            var page = await source.ReadAfterAsync(after, batchSize, ct).ConfigureAwait(false);
            if (page.ReadFailed)
            {
                // Not a replaced audit: keep the cursor. With nothing stored or sent yet there is nothing to lose, so no failure.
                return new ForwardResult(sent, prunedTotal, Failed: hasCursor);
            }

            if (page.Last > 0 && page.Last < after)
            {
                // A replaced audit file starts its sequences again; nothing was pruned. An empty one says nothing, so it keeps the cursor.
                (after, hasCursor) = (0, false);
                if (!TryStore(0, hash: null))
                {
                    return new ForwardResult(sent, prunedTotal, Failed: true);
                }

                continue;
            }

            if (page.Rows.Count == 0)
            {
                return new ForwardResult(sent, prunedTotal, Failed: false);
            }

            if (!hasCursor)
            {
                // Store where this audit starts before the first send, so entries pruned while it keeps failing are still counted.
                hasCursor = true;
                if (!TryStore(after = page.Rows[0].Sequence - 1, page.Rows[0].Entry.PreviousHash))
                {
                    return new ForwardResult(sent, prunedTotal, Failed: true);
                }
            }

            var lastSequence = page.Rows[^1].Sequence;
            var pruned = (int)Math.Clamp(page.Rows[0].Sequence - after - 1, 0, int.MaxValue);
            var events = MapEvents(page);
            if ((events.Count > 0 || pruned > 0) && !await SendAsync(events, pruned, ct).ConfigureAwait(false))
            {
                return new ForwardResult(sent, prunedTotal, Failed: true);
            }

            sent += events.Count;
            prunedTotal += pruned;
            after = lastSequence;
            hasCursor = true;
            if (!TryStore(after, page.Rows[^1].Entry.Hash))
            {
                return new ForwardResult(sent, prunedTotal, Failed: true);
            }
        }
    }

    /// <summary>A pass that reports what goes wrong instead of throwing: forwarding is a side channel, and whatever fails in it must not
    /// stop the process that answers the hooks.</summary>
    public async Task<ForwardResult> TryForwardAsync(CancellationToken ct)
    {
        try
        {
            return await ForwardAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new ForwardResult(0, 0, Failed: true);
        }
#pragma warning disable CA1031 // See the summary: nothing here may reach a decision.
        catch (Exception e)
#pragma warning restore CA1031
        {
            log?.Invoke($"forwarding events failed: {e.GetType().Name}");
            return new ForwardResult(0, 0, Failed: true);
        }
    }

    /// <summary>Forwards every <paramref name="interval"/>, and backs off while the server cannot be reached.</summary>
    public async Task RunAsync(TimeSpan interval, CancellationToken ct)
    {
        var wait = interval;
        while (!ct.IsCancellationRequested)
        {
            var result = await TryForwardAsync(ct).ConfigureAwait(false);
            wait = result.Failed ? TimeSpan.FromTicks(Math.Min(MaxBackoff.Ticks, wait.Ticks * 2)) : interval;
            try
            {
                await Task.Delay(wait, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private List<ForwardedEvent> MapEvents(AuditPage page)
    {
        var events = new List<ForwardedEvent>();
        foreach (var (_, entry) in page.Rows)
        {
            if (AuditEventMapper.Map(entry, detailedLogging) is { } mapped)
            {
                events.Add(mapped);
            }
        }

        return events;
    }

    /// <summary>Where this pass starts: the stored cursor, or the top of the audit when the file was replaced; <see langword="null"/>
    /// when the restart could not be stored.</summary>
    private async Task<(long After, bool HasCursor)?> StartAsync(CancellationToken ct)
    {
        var stored = cursor.ReadContent();
        if (stored is not { Hash: { Length: > 0 } hash } || !await IsReplacedAsync(stored.Sequence, hash, ct).ConfigureAwait(false))
        {
            return (stored?.Sequence ?? 0, stored is not null);
        }

        // A new audit file that already holds the old cursor's sequence: its entries at and below it were never sent.
        log?.Invoke("the audit file was replaced; forwarding starts again from its first entry");
        return TryStore(0, hash: null) ? (0, false) : null;
    }

    /// <summary>True when the audit is not the one the cursor was stored for: the entry at the cursor has another hash, or, with that
    /// entry pruned, the next one does not link to it. With neither entry left there is nothing to compare, and pruned entries are a gap.</summary>
    private async Task<bool> IsReplacedAsync(long after, string hash, CancellationToken ct)
    {
        var probe = await source.ReadAfterAsync(after - 1, 1, ct).ConfigureAwait(false);
        if (probe.ReadFailed || probe.Rows.Count == 0)
        {
            return false;
        }

        var (sequence, entry) = probe.Rows[0];
        return sequence == after
            ? !string.Equals(entry.Hash, hash, StringComparison.Ordinal)
            : sequence == after + 1 && !string.Equals(entry.PreviousHash, hash, StringComparison.Ordinal);
    }

    private bool TryStore(long sequence, string? hash)
    {
        try
        {
            cursor.Write(sequence, hash);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The batch was taken but the cursor stayed: the next pass sends it again with the same ids, and the server stores each once.
            log?.Invoke($"the event cursor could not be stored: {e.GetType().Name}");
            return false;
        }
    }

    private async Task<bool> SendAsync(List<ForwardedEvent> events, int pruned, CancellationToken ct)
    {
        if (organisation() is not { Length: > 0 } org)
        {
            return false;
        }

        var batch = new EventBatch
        {
            Organisation = org,
            Events = events,
            Gap = pruned > 0 ? new EventGap { Pruned = pruned, Node = events.Count > 0 ? events[0].Node : null } : null,
        };
        try
        {
            using var body = new StringContent(JsonSerializer.Serialize(batch, EventsJsonContext.Default.EventBatch), Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
            using var response = await http.PostAsync(endpoint, body, ct).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            log?.Invoke($"the server refused the events with status {(int)response.StatusCode}; they stay queued");
            return false;
        }
        catch (Exception e) when (e is HttpRequestException or SignIn.SignInRequiredException or InvalidOperationException
            || (e is OperationCanceledException && !ct.IsCancellationRequested))
        {
            log?.Invoke($"the server cannot be reached for events: {e.GetType().Name}; they stay queued");
            return false;
        }
    }
}

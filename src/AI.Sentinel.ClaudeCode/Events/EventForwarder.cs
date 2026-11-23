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
        var stored = cursor.Read();
        var hasCursor = stored is not null;
        var after = stored ?? 0;
        var sent = 0;
        var prunedTotal = 0;
        while (true)
        {
            var page = await source.ReadAfterAsync(after, batchSize, ct).ConfigureAwait(false);
            if (page.Last < after)
            {
                // The audit file was replaced by a newer one, so its sequences start again. Nothing was pruned: start from the top.
                after = 0;
                hasCursor = false;
                if (!TryStore(0))
                {
                    return new ForwardResult(sent, prunedTotal, Failed: true);
                }

                continue;
            }

            if (page.Rows.Count == 0)
            {
                return new ForwardResult(sent, prunedTotal, Failed: false);
            }

            var lastSequence = page.Rows[^1].Sequence;
            var pruned = hasCursor ? (int)Math.Clamp(page.Rows[0].Sequence - after - 1, 0, int.MaxValue) : 0;
            var events = new List<ForwardedEvent>();
            foreach (var (_, entry) in page.Rows)
            {
                if (AuditEventMapper.Map(entry, detailedLogging) is { } mapped)
                {
                    events.Add(mapped);
                }
            }

            if ((events.Count > 0 || pruned > 0) && !await SendAsync(events, pruned, ct).ConfigureAwait(false))
            {
                return new ForwardResult(sent, prunedTotal, Failed: true);
            }

            sent += events.Count;
            prunedTotal += pruned;
            after = lastSequence;
            hasCursor = true;
            if (!TryStore(after))
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

    private bool TryStore(long sequence)
    {
        try
        {
            cursor.Write(sequence);
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

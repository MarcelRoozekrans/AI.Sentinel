using System.Globalization;
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

    // The server the cursor is bound to: the ingest address without its query.
    private readonly string _server = endpoint.GetLeftPart(UriPartial.Path);

    /// <summary>Sends what the server has not taken yet. A sign-in to another organisation during the pass ends it before the next
    /// page, and the next pass applies the binding rule to what is left.</summary>
    public async Task<ForwardResult> ForwardAsync(CancellationToken ct)
    {
        // Before the sign-in there is no organisation to send to, and none to bind the cursor to.
        if (organisation() is not { Length: > 0 } org)
        {
            return new ForwardResult(0, 0, Failed: true);
        }

        var start = await StartAsync(org, ct).ConfigureAwait(false);
        if (start is not { Stop: null })
        {
            return start?.Stop ?? new ForwardResult(0, 0, Failed: true);
        }

        var (after, hasCursor, file) = (start.After, start.HasCursor, start.FileId!);
        var (sent, prunedTotal) = (0, await SendPendingAsync(org, start, ct).ConfigureAwait(false));
        if (prunedTotal < 0)
        {
            return new ForwardResult(0, 0, Failed: true);
        }

        while (true)
        {
            if (!string.Equals(organisation(), org, StringComparison.Ordinal))
            {
                return new ForwardResult(sent, prunedTotal, Failed: false);
            }

            var page = await source.ReadAfterAsync(after, batchSize, ct).ConfigureAwait(false);
            if (page.ReadFailed || !string.Equals(page.FileId, file, StringComparison.Ordinal))
            {
                // Keep the cursor; with nothing stored there is nothing to lose. A file replaced during the pass is the next pass's to find.
                return new ForwardResult(sent, prunedTotal, Failed: page.ReadFailed && hasCursor);
            }

            if (page.Rows.Count == 0)
            {
                var emptied = hasCursor ? await ReportEmptiedAsync(org, page, after, ct).ConfigureAwait(false) : 0;
                return new ForwardResult(sent, prunedTotal + Math.Max(emptied, 0), Failed: emptied < 0);
            }

            // Store where this audit starts before the first send, so entries pruned while it keeps failing are still counted.
            if (!hasCursor && !TryStore(new(after = page.Rows[0].Sequence - 1, page.Rows[0].Entry.PreviousHash, file), org, gap: null))
            {
                return new ForwardResult(sent, prunedTotal, Failed: true);
            }

            hasCursor = true;

            var events = MapEvents(page);
            var (reported, pruned, gapEnd) = await ReportPrunedAsync(org, page, events, after, file, ct).ConfigureAwait(false);
            (prunedTotal, after) = (prunedTotal + pruned, gapEnd);
            if (!reported
                || (events.Count > 0 && !await SendAsync(org, events, gap: null, ct).ConfigureAwait(false))
                || !TryStore(new(after = page.Rows[^1].Sequence, page.Rows[^1].Entry.Hash, file), org, gap: null))
            {
                return new ForwardResult(sent, prunedTotal, Failed: true);
            }

            sent += events.Count;
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

    /// <summary>The entries pruned between the cursor and the first entry of <paramref name="page"/>, named by the range it covers.</summary>
    private static EventGap? PrunedGap(AuditPage page, List<ForwardedEvent> events, long after, string file)
    {
        var first = page.Rows[0].Sequence;
        var pruned = (int)Math.Clamp(first - after - 1, 0, int.MaxValue);
        return pruned == 0
            ? null
            : new EventGap
            {
                Id = string.Create(CultureInfo.InvariantCulture, $"{file}:{after + 1}-{first - 1}"),
                Pruned = pruned,
                Cause = EventGap.PrunedCause,
                Node = events.Count > 0 ? events[0].Node : null,
            };
    }

    /// <summary>Sends the gap the cursor keeps, first and alone, under the id it was stored with, so a resend is stored once. The number
    /// of entries it reports, or -1 when that failed.</summary>
    private async Task<int> SendPendingAsync(string org, Start start, CancellationToken ct)
    {
        if (start.Gap is not { } pending)
        {
            return 0;
        }

        return await SendAsync(org, [], pending, ct).ConfigureAwait(false) && TryStore(new(start.After, start.Hash, start.FileId!), org, gap: null)
            ? pending.Pruned ?? 0
            : -1;
    }

    /// <summary>Retention deleted every entry after the cursor before it was sent; the counter of the file still says how many (#713).
    /// The number reported, or -1 when that failed.</summary>
    private async Task<int> ReportEmptiedAsync(string org, AuditPage page, long after, CancellationToken ct)
    {
        if (page.LastAssigned <= after)
        {
            return 0;
        }

        var gap = new EventGap
        {
            Id = string.Create(CultureInfo.InvariantCulture, $"{page.FileId}:{after + 1}-{page.LastAssigned}"),
            Pruned = (int)Math.Min(page.LastAssigned - after, int.MaxValue),
            Cause = EventGap.PrunedCause,
        };
        return await ReportGapAsync(org, new Position(page.LastAssigned, null, page.FileId!), gap, ct).ConfigureAwait(false)
            ? gap.Pruned.Value
            : -1;
    }

    /// <summary>Reports the entries pruned before the first entry of <paramref name="page"/>, if any. Whether that worked, how many
    /// entries it reported, and the sequence the cursor stands at after it.</summary>
    private async Task<(bool Reported, int Pruned, long After)> ReportPrunedAsync(
        string org, AuditPage page, List<ForwardedEvent> events, long after, string file, CancellationToken ct)
    {
        if (PrunedGap(page, events, after, file) is not { } gap)
        {
            return (true, 0, after);
        }

        var end = new Position(page.Rows[0].Sequence - 1, page.Rows[0].Entry.PreviousHash, file);
        return await ReportGapAsync(org, end, gap, ct).ConfigureAwait(false) ? (true, gap.Pruned ?? 0, end.Sequence) : (false, 0, after);
    }

    /// <summary>Reports <paramref name="gap"/>, which ends at <paramref name="end"/>. It is stored in the cursor before it is sent, so a
    /// gap whose cursor write is lost after the server took it is sent again unchanged, under the same id, and counted once; with the
    /// send failing, the next pass sends the stored gap before anything else.</summary>
    private async Task<bool> ReportGapAsync(string org, Position end, EventGap gap, CancellationToken ct) =>
        TryStore(end, org, gap)
        && await SendAsync(org, [], gap, ct).ConfigureAwait(false)
        && TryStore(end, org, gap: null);

    /// <summary>Where this pass starts. With no cursor yet it starts at the top of the audit. A cursor bound to another server or
    /// organisation, or to no server as one written before the binding was kept, skips the entries it has not sent: they were routed
    /// for that server, and no entry may reach another one (#723). A cursor of another audit file starts again from the oldest entry
    /// of this one, and reports the old file as a gap of unknown size (#713). <see langword="null"/> when that could not be stored.</summary>
    private async Task<Start?> StartAsync(string org, CancellationToken ct)
    {
        var stored = cursor.ReadContent();
        var probe = await source.ReadAfterAsync(Math.Max(0, (stored?.Sequence ?? 0) - 1), 1, ct).ConfigureAwait(false);
        if (probe.ReadFailed || probe.FileId is not { } file)
        {
            // Not a replaced audit: keep the cursor. With nothing stored yet there is nothing to lose, so no failure.
            return new Start(0, false, null, null, null) { Stop = new ForwardResult(0, 0, Failed: stored is not null) };
        }

        if (stored is null)
        {
            return new Start(0, false, file, null, null);
        }

        var sameFile = IsSameFile(stored, probe, file);
        if (sameFile && IsBoundHere(stored, org))
        {
            return new Start(stored.Sequence, true, file, stored.Gap, stored.Hash);
        }

        var skipped = sameFile ? await CountUnsentAsync(stored.Sequence, probe.LastAssigned, ct).ConfigureAwait(false) : null;
        if (sameFile && skipped is null)
        {
            return new Start(0, false, null, null, null) { Stop = new ForwardResult(0, 0, Failed: true) };
        }

        var (position, gap) = IsBoundHere(stored, org) ? Replaced(probe, file) : Skipped(probe, file, skipped ?? 0, known: skipped is not null, stored.Gap);
        return TryStore(position, org, gap) ? new Start(position.Sequence, true, file, gap, position.Hash) : null;
    }

    /// <summary>The entries after <paramref name="after"/> up to <paramref name="until"/> that would have been sent: those the hook
    /// routed, and those retention deleted, whose route is not known any more. <see langword="null"/> when the audit cannot be read.</summary>
    private async Task<long?> CountUnsentAsync(long after, long until, CancellationToken ct)
    {
        var (count, at) = (0L, after);
        while (at < until)
        {
            var page = await source.ReadAfterAsync(at, batchSize, ct).ConfigureAwait(false);
            if (page.ReadFailed)
            {
                return null;
            }

            var moved = false;
            foreach (var (sequence, entry) in page.Rows)
            {
                if (sequence > until)
                {
                    break;
                }

                count += sequence - at - 1 + (string.IsNullOrEmpty(entry.ToolKind) ? 0 : 1);
                (at, moved) = (sequence, true);
            }

            if (!moved)
            {
                return count + (until - at);
            }
        }

        return count;
    }

    private bool IsBoundHere(EventCursorContent stored, string org) =>
        string.Equals(stored.Server, _server, StringComparison.Ordinal) && string.Equals(stored.Organisation, org, StringComparison.Ordinal);

    private (Position, EventGap) Replaced(AuditPage probe, string file)
    {
        log?.Invoke("the audit file was replaced; forwarding starts again from its first entry, and the old file is reported as a gap of unknown size");
        var gap = new EventGap { Id = Guid.NewGuid().ToString("N"), Unknown = true, Cause = EventGap.AuditReplacedCause };
        return (new Position(probe.First > 0 ? probe.First - 1 : probe.LastAssigned, null, file), gap);
    }

    /// <summary>Skips what the cursor has not sent: <paramref name="skipped"/> entries, or, not <paramref name="known"/>, an unknown number
    /// in another audit file. A gap the cursor still keeps was taken by no server yet and is the only record of its entries, so it is
    /// carried into the gap of the skip instead of dropped.</summary>
    private (Position, EventGap?) Skipped(AuditPage probe, string file, long skipped, bool known, EventGap? pending)
    {
        if (pending is not null)
        {
            (skipped, known) = (skipped + (pending.Pruned ?? 0), known && pending.Pruned is not null);
        }

        var position = new Position(probe.LastAssigned, null, file);
        if (known && skipped == 0)
        {
            return (position, null);
        }

        log?.Invoke(known
            ? string.Create(CultureInfo.InvariantCulture, $"the server or organisation changed; {skipped} unsent entries were skipped and are reported to it as a gap")
            : "the server or organisation changed; the unsent entries were skipped and are reported to it as a gap of unknown size");
        var gap = new EventGap
        {
            Id = Guid.NewGuid().ToString("N"),
            Pruned = known ? (int)Math.Min(skipped, int.MaxValue) : null,
            Unknown = known ? null : true,
            Cause = EventGap.ServerChangeCause,
        };
        return (position, gap);
    }

    /// <summary>True when the audit is the one the cursor was stored for: the same file id, a counter that reached the cursor, and the
    /// entry at the cursor with its hash, or with that entry pruned, a next one that links to it. With neither entry left there is
    /// nothing to compare, and pruned entries are a gap.</summary>
    private static bool IsSameFile(EventCursorContent stored, AuditPage probe, string file)
    {
        if ((stored.File is { } id && !string.Equals(id, file, StringComparison.Ordinal)) || probe.LastAssigned < stored.Sequence)
        {
            return false;
        }

        if (stored.Hash is not { Length: > 0 } hash || probe.Rows.Count == 0)
        {
            return true;
        }

        var (sequence, entry) = probe.Rows[0];
        return sequence == stored.Sequence
            ? string.Equals(entry.Hash, hash, StringComparison.Ordinal)
            : sequence != stored.Sequence + 1 || string.Equals(entry.PreviousHash, hash, StringComparison.Ordinal);
    }

    private bool TryStore(Position position, string org, EventGap? gap)
    {
        try
        {
            cursor.Write(new EventCursorContent
            {
                Sequence = position.Sequence,
                Hash = string.IsNullOrEmpty(position.Hash) ? null : position.Hash,
                File = position.FileId,
                Server = _server,
                Organisation = org,
                Gap = gap,
            });
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The batch was taken but the cursor stayed: the next pass sends it again with the same ids, and the server stores each once.
            log?.Invoke($"the event cursor could not be stored: {e.GetType().Name}");
            return false;
        }
    }

    private async Task<bool> SendAsync(string org, List<ForwardedEvent> events, EventGap? gap, CancellationToken ct)
    {
        var batch = new EventBatch { Organisation = org, Events = events, Gap = gap };
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

    /// <summary>A place in an audit file.</summary>
    private sealed record Position(long Sequence, string? Hash, string FileId);

    /// <summary>Where a pass starts, and the gap it has to report first. <see cref="Stop"/> ends the pass before it reads further.</summary>
    private sealed record Start(long After, bool HasCursor, string? FileId, EventGap? Gap, string? Hash)
    {
        public ForwardResult? Stop { get; init; }
    }
}

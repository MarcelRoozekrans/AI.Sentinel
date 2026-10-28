using System.Text;
using Microsoft.Extensions.AI;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;
using AI.Sentinel.Screening;

namespace AI.Sentinel;

public sealed partial class SentinelPipeline
{
    /// <summary>
    /// Screens one text without a chat call: masks the values the redacting detectors find, scans the masked text and
    /// returns the verdict, the masked text, every detection and every redaction. Never calls the inner client.
    /// </summary>
    /// <remarks>
    /// The text is judged as a new user message, with the same detectors, options, verdict rule, alerts, intervention
    /// and audit entries as a prompt on the chat path. The rate limit is checked first, on
    /// <see cref="ScreeningOptions.Session"/> when one is given and otherwise on the shared <c>__global__</c> key. The
    /// <c>REDACTED</c> audit entries are written whenever anything was masked, also when the text is quarantined: the
    /// masked text is returned either way. When redaction fails the outcome is <see cref="ScreeningOutcome.Failed"/>;
    /// the text is never scanned or returned unmasked. When the scan or its audit throws, the outcome is also
    /// <see cref="ScreeningOutcome.Failed"/>, with the exception as <see cref="ScreeningOutcome.Failed.Inner"/>. A
    /// <see cref="ScreeningOptions.Placeholder"/> formatter runs after the scan and the audit, so it cannot change the
    /// verdict; an exception it throws reaches the caller as it is.
    /// </remarks>
    /// <param name="text">The text to screen.</param>
    /// <param name="options">The session and placeholder formatter; <see langword="null"/> for the defaults.</param>
    /// <param name="ct">Cancellation token; cancellation surfaces as <see cref="OperationCanceledException"/>.</param>
    /// <returns>The outcome: <see cref="ScreeningOutcome.Passed"/>, <see cref="ScreeningOutcome.Quarantined"/>,
    /// <see cref="ScreeningOutcome.RateLimited"/> or <see cref="ScreeningOutcome.Failed"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="text"/> is <see langword="null"/>.</exception>
    public async ValueTask<ScreeningOutcome> ScreenAsync(
        string text, ScreeningOptions? options = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        ct.ThrowIfCancellationRequested();

        // A session minted for the call is never a rate-limit key: every call would get its own bucket.
        var callerSession = options?.Session;
        if (CheckRateLimit(callerSession) is SentinelError.RateLimitExceeded limited)
            return new ScreeningOutcome.RateLimited(limited.SessionKey);

        var sessionId = callerSession ?? SessionId.New();
        var redactors = pipeline.Redactors;
        var session = redactors.Count > 0 ? new RedactionSession(redactors) : null;
        var replaced = new List<ReplacedSpan>();
        string masked;
        try
        {
            masked = session is null ? text : session.Redact(text, replaced);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Not chained: a regex or detector exception can carry the text being masked.
            return new ScreeningOutcome.Failed(
                $"AI.Sentinel could not mask the text ({ex.GetType().Name}); it was not scanned or returned.");
        }

        var findings = new List<ScanFinding>();
        SentinelError? error;
        try
        {
            error = await ScanCollectingAsync([new ChatMessage(ChatRole.User, masked)], sessionId, findings,
                RedactionScope.ExemptPlaceholders(session, parent: null), newMessagesFrom: 0, ct).ConfigureAwait(false);

            // The masked text is returned on both verdicts, so its redactions are recorded on both.
            await AppendRedactionsAsync(session, sessionId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // In practice the audit store; its entries hold reasons and counts, never the text, so the exception is kept.
            return new ScreeningOutcome.Failed($"AI.Sentinel could not screen the text ({ex.GetType().Name}).", ex);
        }

        var (redactedText, redactions) = Placeholders(text, masked, replaced, options?.Placeholder);
        var detections = findings.ConvertAll(f => f.Detection);
        return error is SentinelError.ThreatDetected threat
            ? new ScreeningOutcome.Quarantined(threat.Action, redactedText, detections, redactions, sessionId)
            : new ScreeningOutcome.Passed(
                SentinelActionRanking.MostRestrictive(findings.Select(f => f.Action)),
                redactedText, detections, redactions, sessionId);
    }

    /// <summary>
    /// One finding per replaced span, in input order. Without a formatter the placeholders are the library tokens and
    /// the text is the session's output. With one, each finding's placeholder is the formatter's output for it, and the
    /// text is rebuilt from the input with those placeholders, so a token shared by repeated values gets the
    /// formatter's output at every occurrence.
    /// </summary>
    private static (string Text, IReadOnlyList<RedactionFinding> Findings) Placeholders(
        string input, string masked, List<ReplacedSpan> replaced, Func<RedactionFinding, string>? format)
    {
        var findings = new List<RedactionFinding>(replaced.Count);
        foreach (var span in replaced)
        {
            var finding = new RedactionFinding(new DetectorId(span.DetectorId), span.EntityType, span.Start, span.Length, span.Token)
            {
                Severity = span.Severity,
            };
            if (format is not null)
            {
                var placeholder = format(finding)
                    ?? throw new InvalidOperationException("The placeholder formatter returned null.");
                finding = finding with { Placeholder = placeholder };
            }
            findings.Add(finding);
        }

        if (format is null)
            return (masked, findings);

        var text = new StringBuilder(input.Length);
        var at = 0;
        foreach (var finding in findings)
        {
            text.Append(input, at, finding.Start - at).Append(finding.Placeholder);
            at = finding.Start + finding.Length;
        }
        text.Append(input, at, input.Length - at);
        return (text.ToString(), findings);
    }
}

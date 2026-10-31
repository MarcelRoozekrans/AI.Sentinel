using System.Text.Json;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Redaction;

namespace AI.Sentinel.Approvals.Notifications;

/// <summary>The JSON body posted when an approval request is created.</summary>
/// <param name="Text">A one-line message, which makes a Slack incoming webhook work as is.</param>
/// <param name="RequestId">The approval request.</param>
/// <param name="Tool">The gated tool.</param>
/// <param name="CallerId">The caller the request is for.</param>
/// <param name="Policy">The approval policy.</param>
/// <param name="RequestedAt">When the request was created.</param>
/// <param name="ApprovalUrl">The store's approval URL, as is.</param>
/// <param name="DashboardUrl">The configured dashboard base URL, or <see langword="null"/>.</param>
/// <param name="Args">The redacted tool arguments, or <see langword="null"/> when they are not sent.</param>
internal sealed record ApprovalNotification(
    string Text,
    string RequestId,
    string Tool,
    string CallerId,
    string Policy,
    DateTimeOffset RequestedAt,
    string ApprovalUrl,
    string? DashboardUrl,
    JsonElement? Args)
{
    /// <summary>Builds the payload for a request the store just created.</summary>
    /// <param name="pending">The new request.</param>
    /// <param name="callerId">The caller the request is for.</param>
    /// <param name="policy">The approval policy.</param>
    /// <param name="context">The tool and its arguments.</param>
    /// <param name="settings">The notifier settings.</param>
    internal static ApprovalNotification Create(
        ApprovalState.Pending pending, string callerId, string policy, ApprovalContext context, ApprovalNotifierSettings settings)
    {
        var link = settings.DashboardUrl?.ToString() ?? (IsHttp(pending.ApprovalUrl) ? pending.ApprovalUrl : null);
        var text = $"Approval needed: {context.ToolName} for {callerId} ({policy}).";
        if (link is not null)
        {
            text += " " + link;
        }

        JsonElement? args = null;
        if (settings.IncludeArgs && context.Args.ValueKind != JsonValueKind.Undefined)
        {
            // Always both detectors, whatever the host's other redaction settings are.
            var session = new RedactionSession([new CredentialExposureDetector(), new PiiLeakageDetector()]);
            args = session.RedactJsonValues(context.Args);
        }

        return new ApprovalNotification(
            text, pending.RequestId, context.ToolName, callerId, policy, pending.RequestedAt,
            pending.ApprovalUrl, settings.DashboardUrl?.ToString(), args);
    }

    private static bool IsHttp(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri)
        && (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.Ordinal)
            || uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.Ordinal));
}

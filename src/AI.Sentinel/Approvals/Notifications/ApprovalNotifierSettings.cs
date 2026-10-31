using AI.Sentinel.Approvals.Configuration;

namespace AI.Sentinel.Approvals.Notifications;

/// <summary>What <see cref="NotifyingApprovalStore"/> needs to post a webhook.</summary>
/// <param name="Url">The endpoint that receives the POST.</param>
/// <param name="Headers">Extra request headers, such as <c>Authorization</c>.</param>
/// <param name="IncludeArgs">Whether the redacted tool arguments are part of the payload.</param>
/// <param name="DashboardUrl">The dashboard base URL the message text links to, or <see langword="null"/>.</param>
internal sealed record ApprovalNotifierSettings(
    Uri Url,
    IReadOnlyDictionary<string, string> Headers,
    bool IncludeArgs,
    Uri? DashboardUrl)
{
    /// <summary>The settings of <paramref name="config"/>, or <see langword="null"/> when it has no <c>notifyUrl</c>.</summary>
    /// <param name="config">The loaded approval config.</param>
    internal static ApprovalNotifierSettings? FromConfig(ApprovalConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return config.NotifyUrl is null
            ? null
            : new ApprovalNotifierSettings(config.NotifyUrl, config.NotifyHeaders, config.NotifyIncludeArgs, config.DashboardUrl);
    }
}

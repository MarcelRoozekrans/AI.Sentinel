namespace AI.Sentinel.AspNetCore;

/// <summary>Settings of the server's events endpoints (ADR-240, ADR-247). Nothing is registered or mapped unless the host calls
/// <see cref="ServerEventExtensions.AddAISentinelServerEvents"/> and <see cref="ServerEventExtensions.MapAISentinelServerEvents"/>.
/// Needs the policy folder: the roles per node and the organisation come from there.</summary>
public sealed class ServerEventOptions
{
    /// <summary>The name of the ASP.NET Core authorization policy the ingest and read endpoints require. The organisation is passed
    /// as the resource, as a string. The host defines the policy. Defaults to <c>AISentinelEvents</c>.</summary>
    public string PolicyName { get; set; } = "AISentinelEvents";

    /// <summary>The key that turns an identity into a code: the base64 of at least 16 random bytes. It reaches the server through the
    /// deployment at startup and is kept apart from the event store; the store holds codes only. Required. Changing it changes every
    /// code, so events received before and after cannot be linked.</summary>
    public string? PseudonymKey { get; set; }

    /// <summary>The claim of the validated token that names the organisation of the sender. Optional. Defaults to <c>organisation</c>;
    /// when the token has none, the organisation of the published node configuration is the sender's. A claim that names any other
    /// organisation than the published one is refused with 403, because the read endpoints serve only the published organisation.</summary>
    public string OrganisationClaim { get; set; } = "organisation";

    /// <summary>The largest batch the ingest endpoint reads, in bytes. A larger body is refused with 413. Defaults to 1 MiB.</summary>
    public int MaxBatchBytes { get; set; } = 1024 * 1024;

    /// <summary>The retention of an organisation that has no entry in <see cref="Retention"/>: 90 days for events and 13 months for
    /// daily counts.</summary>
    public ServerEventRetention DefaultRetention { get; set; } = new();

    /// <summary>Retention per organisation, keyed by the organisation name.</summary>
    public IDictionary<string, ServerEventRetention> Retention { get; } = new Dictionary<string, ServerEventRetention>(StringComparer.Ordinal);

    /// <summary>How many people a team needs before it is shown on its own (ADR-239). Fixed at 3; the tests lower it.</summary>
    internal int MinimumTeamPeople { get; set; } = 3;

    internal ServerEventRetention RetentionOf(string organisation) =>
        Retention.TryGetValue(organisation, out var own) ? own : DefaultRetention;
}

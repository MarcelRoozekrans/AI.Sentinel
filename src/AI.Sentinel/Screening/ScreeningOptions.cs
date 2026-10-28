using AI.Sentinel.Domain;

namespace AI.Sentinel.Screening;

/// <summary>Options for one <see cref="SentinelPipeline.ScreenAsync"/> call.</summary>
public sealed record ScreeningOptions
{
    /// <summary>
    /// The session the audit entries and the outcome belong to, and the rate-limit key. <see langword="null"/> mints
    /// a session for the call, which is never a rate-limit key: the call is then limited on the shared global key.
    /// </summary>
    public SessionId? Session { get; init; }

    /// <summary>
    /// Formats the placeholder that replaces a masked value in the returned text, such as <c>[TELEFOON]</c>. It is
    /// called once per finding, with <see cref="RedactionFinding.Placeholder"/> set to the library token, and never
    /// sees the value. <see langword="null"/> keeps the library tokens such as <c>[PHONE_1_k3f9x2]</c>. The scan always
    /// judges the library tokens, so the formatter cannot change the verdict.
    /// </summary>
    public Func<RedactionFinding, string>? Placeholder { get; init; }
}

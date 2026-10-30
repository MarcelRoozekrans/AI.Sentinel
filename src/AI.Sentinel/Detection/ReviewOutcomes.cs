namespace AI.Sentinel.Detection;

/// <summary>The values of the <c>outcome</c> tag on the <c>sentinel.reviews</c> counter: how each review candidate
/// of a scan ended.</summary>
internal static class ReviewOutcomes
{
    /// <summary>The verdict set the proposed severity, which lifts the semantic cap.</summary>
    public const string Confirmed = "confirmed";

    /// <summary>The verdict set a severity above the proposed one.</summary>
    public const string Raised = "raised";

    /// <summary>The verdict set a severity below the proposed one, but above None.</summary>
    public const string Lowered = "lowered";

    /// <summary>The verdict was None, which clears the detection.</summary>
    public const string Cleared = "cleared";

    /// <summary>The reviewer answered without a severity; the detection keeps its shown result.</summary>
    public const string NoVerdict = "no_verdict";

    /// <summary>The reviewer threw; the detection keeps its shown result.</summary>
    public const string Failed = "failed";

    /// <summary>The review did not finish within the review timeout; the detection keeps its shown result.</summary>
    public const string TimedOut = "timed_out";

    /// <summary>The candidate ranked below the per-scan review budget and was not sent; it keeps its shown result.</summary>
    public const string OverBudget = "over_budget";

    /// <summary>Every outcome, in the order reports list them.</summary>
    public static readonly string[] All = [Confirmed, Raised, Lowered, Cleared, NoVerdict, Failed, TimedOut, OverBudget];
}

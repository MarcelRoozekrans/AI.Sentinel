namespace AI.Sentinel.Detection;

/// <summary>Why a detector did not run to completion in one scan. A gate reads these from
/// <see cref="PipelineResult.Failures"/> to fail closed on a scan it cannot trust.</summary>
/// <remarks>A detector gets one entry per scan. When it hits more than one kind, the earliest stage wins
/// (embedding, then analysis, then review), because that is the one that limited what ran.</remarks>
public enum DetectorFailureKind
{
    /// <summary>The detector threw, other than the caller's own cancellation and a regex timeout, including an
    /// embedding failure when the pipeline was built without an embedding scope. Its result is Clean.</summary>
    Threw,

    /// <summary>The detector raised a <see cref="System.Text.RegularExpressions.RegexMatchTimeoutException"/>. The
    /// content can provoke this, so it is flagged Critical; a configured <c>SeverityCap</c> still applies.</summary>
    RegexTimeout,

    /// <summary>A semantic detector needed a text that could not be embedded, or its text selection threw. It is
    /// scored on the texts that did embed, or on its rule layer only.</summary>
    TextsNotEmbedded,

    /// <summary>A semantic detector's example phrases could not be embedded. Only its rule layer ran.</summary>
    ExamplesNotEmbedded,

    /// <summary>The reviewer failed or timed out on one of the detector's results, which keeps the result it had
    /// before review. A review skipped because <c>MaxReviewsPerScan</c> ran out is not a failure.</summary>
    ReviewFailed,
}

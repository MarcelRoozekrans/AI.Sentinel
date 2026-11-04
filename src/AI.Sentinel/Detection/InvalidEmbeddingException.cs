namespace AI.Sentinel.Detection;

/// <summary>A provider returned vectors that cannot be compared: empty, zero-norm or non-finite, or of mixed lengths.</summary>
internal sealed class InvalidEmbeddingException(string kind)
    : InvalidOperationException($"The embedding generator returned an unusable vector: {kind}.")
{
    public const string EmptyVector = "empty vector";
    public const string InvalidVector = "invalid vector";
    public const string DimensionMismatch = "dimension mismatch";

    /// <summary>One of <see cref="EmptyVector"/>, <see cref="InvalidVector"/> or <see cref="DimensionMismatch"/>.</summary>
    public string Kind { get; } = kind;

    /// <summary>Why <paramref name="vector"/> cannot be scored, or <see langword="null"/> when it can.</summary>
    /// <remarks>A zero-norm vector has no direction, and a NaN or infinity poisons every cosine it takes part in.</remarks>
    public static string? Problem(ReadOnlySpan<float> vector)
    {
        if (vector.IsEmpty)
            return EmptyVector;

        // In double: a float sum of squares overflows near 1e19 and underflows near 1e-23, which would reject
        // valid vectors with extreme components.
        var norm = 0d;
        foreach (var v in vector)
        {
            if (!float.IsFinite(v))
                return InvalidVector;
            norm += (double)v * v;
        }

        return norm > 0d ? null : InvalidVector;
    }
}

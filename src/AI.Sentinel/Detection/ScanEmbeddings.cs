namespace AI.Sentinel.Detection;

/// <summary>The vectors of one scan's texts, plus how many could not be embedded.</summary>
internal sealed class ScanEmbeddings
{
    private readonly Dictionary<string, ReadOnlyMemory<float>> _vectors;

    public ScanEmbeddings(Dictionary<string, ReadOnlyMemory<float>> vectors, int totalCount, int failedCount, Exception? firstFailure)
    {
        _vectors = vectors;
        TotalCount = totalCount;
        FailedCount = failedCount;
        FirstFailure = firstFailure;
    }

    public static ScanEmbeddings Empty { get; } = new([], 0, 0, null);

    /// <summary>The number of distinct texts the scan asked for.</summary>
    public int TotalCount { get; }

    /// <summary>The number of texts with no vector because embedding them failed.</summary>
    public int FailedCount { get; }

    /// <summary>The batch exception, or the first single-input exception when the batch succeeded in part.</summary>
    public Exception? FirstFailure { get; }

    public bool TryGet(string text, out ReadOnlyMemory<float> vector) => _vectors.TryGetValue(text, out vector);
}

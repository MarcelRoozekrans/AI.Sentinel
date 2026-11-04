namespace AI.Sentinel.Approvals.Semantic;

/// <summary>Global settings shared by every semantic approval binding.</summary>
public sealed class SemanticApprovalSettings
{
    private readonly List<string> _examples = new();

    /// <summary>Similarity needed for a match when a binding sets none. Null uses the built-in default.</summary>
    public float? Threshold { get; set; }

    /// <summary>When true, the built-in examples are dropped and only the added ones are used.</summary>
    public bool ReplaceExamples { get; set; }

    /// <summary>The examples added with <see cref="AddExamples"/>.</summary>
    internal IReadOnlyList<string> AddedExamples => _examples;

    /// <summary>Adds examples of calls that need approval.</summary>
    /// <param name="examples">Example texts; none may be blank.</param>
    /// <returns>The same <see cref="SemanticApprovalSettings"/> for fluent chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="examples"/> or one of its elements is null.</exception>
    /// <exception cref="ArgumentException">An example is blank.</exception>
    public SemanticApprovalSettings AddExamples(params string[] examples)
    {
        ArgumentNullException.ThrowIfNull(examples);
        foreach (var e in examples)
            ArgumentException.ThrowIfNullOrWhiteSpace(e, nameof(examples));
        _examples.AddRange(examples);
        return this;
    }

    /// <summary>Returns an independent copy of these settings.</summary>
    internal SemanticApprovalSettings Clone()
    {
        var copy = new SemanticApprovalSettings();
        copy.CopyFrom(this);
        return copy;
    }

    /// <summary>Replaces this instance's values with those of <paramref name="other"/>.</summary>
    internal void CopyFrom(SemanticApprovalSettings other)
    {
        Threshold = other.Threshold;
        ReplaceExamples = other.ReplaceExamples;
        _examples.Clear();
        _examples.AddRange(other._examples);
    }
}

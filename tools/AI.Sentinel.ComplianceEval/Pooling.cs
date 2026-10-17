namespace AI.Sentinel.ComplianceEval;

/// <summary>How a model turns its per-token hidden states into one sentence vector.</summary>
internal enum Pooling
{
    /// <summary>Average of the token vectors, weighted by the attention mask (sentence-transformers' default).</summary>
    Mean,

    /// <summary>The <c>[CLS]</c> token's vector (the BGE family).</summary>
    Cls,
}

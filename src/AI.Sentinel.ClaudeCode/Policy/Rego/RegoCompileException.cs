namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>The policy does not compile. The message is the compiler's, and names a refused builtin when that is why.</summary>
internal sealed class RegoCompileException : Exception
{
    public RegoCompileException(string message)
        : base(message)
    {
    }

    public RegoCompileException()
    {
    }

    public RegoCompileException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The message for a compiler that refused <paramref name="output"/>: the refused builtins when it names any.</summary>
    internal static RegoCompileException From(string output)
    {
        var outside = OutsideBuiltins.NamedIn(output);
        return outside.Count > 0
            ? new RegoCompileException($"the policy uses {string.Join(", ", outside)}, which reaches outside the process and is refused: {output.Trim()}")
            : new RegoCompileException(output.Trim());
    }
}

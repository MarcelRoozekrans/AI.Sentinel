namespace AI.Sentinel.Redaction;

/// <summary>
/// One placeholder a <see cref="RedactionSession"/> minted and the value it stands for, exported so a host such as
/// the MCP proxy can restore it outside the session. <see cref="ToString"/> prints the token only, never the value.
/// </summary>
/// <param name="Token">The placeholder, such as <c>[EMAIL_1_k3f9x2]</c>.</param>
/// <param name="Value">The original value. Never logged, audited or printed.</param>
/// <param name="RestoreIntoToolArguments">Whether the value may go back into a tool call's arguments; false for a
/// secret, see <see cref="Detection.IRedactingDetector.RestoreIntoToolArguments"/>.</param>
internal readonly record struct MintedPlaceholder(string Token, string Value, bool RestoreIntoToolArguments)
{
    /// <summary>The token only.</summary>
    public override string ToString() => Token;
}

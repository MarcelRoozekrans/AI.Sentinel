namespace AI.Sentinel.Authorization;

/// <summary>Behaviour when a tool-call has no matching <c>RequireToolPolicy(...)</c> binding.</summary>
public enum ToolPolicyDefault
{
    /// <summary>Allow the call (default — drop-in safety for existing AI.Sentinel users).</summary>
    Allow,
    /// <summary>Deny the call. Combined with explicit bindings, gives strict deny-by-default semantics.</summary>
    Deny,
}

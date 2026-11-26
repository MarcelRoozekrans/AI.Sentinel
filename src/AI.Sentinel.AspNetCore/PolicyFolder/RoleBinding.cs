namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>An identity-provider group bound to a role on a node (ADR-109). Enforcing it is the roles item, not this one.</summary>
internal sealed record RoleBinding(string Group, string Role, string Node);

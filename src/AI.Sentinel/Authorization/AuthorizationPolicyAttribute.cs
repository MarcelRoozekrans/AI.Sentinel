namespace AI.Sentinel.Authorization;

/// <summary>Names a policy so it can be referenced from the [Authorize] attribute and RequireToolPolicy(...).</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class AuthorizationPolicyAttribute(string name) : Attribute
{
    /// <summary>The name used to reference this policy.</summary>
    public string Name { get; } = name;
}

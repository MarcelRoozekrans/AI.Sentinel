using System.Security.Claims;
using AI.Sentinel.Authorization;

namespace AI.Sentinel.AspNetCore.Authorization;

/// <summary>Adapts <see cref="ClaimsPrincipal"/> to <see cref="ISecurityContext"/>. Roles come from <see cref="ClaimTypes.Role"/>; Id from <see cref="ClaimTypes.NameIdentifier"/>; remaining claims (excluding role + name) go to <c>Claims</c>.</summary>
public sealed class ClaimsPrincipalSecurityContext : ISecurityContext
{
    /// <summary>Creates a security context from the supplied <see cref="ClaimsPrincipal"/>.</summary>
    /// <param name="principal">Authenticated principal whose claims describe the caller.</param>
    public ClaimsPrincipalSecurityContext(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        string? id = null;
        var roles = new HashSet<string>(StringComparer.Ordinal);
        var claims = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var claim in principal.Claims)
        {
            if (string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal))
            {
                id ??= claim.Value;
                continue;
            }

            if (string.Equals(claim.Type, ClaimTypes.Role, StringComparison.Ordinal))
            {
                roles.Add(claim.Value);
                continue;
            }

            // Last-wins for repeated non-role/non-name claim types.
            claims[claim.Type] = claim.Value;
        }

        Id = id ?? "anonymous";
        Roles = roles;
        Claims = claims;
    }

    /// <inheritdoc />
    public string Id { get; }

    /// <inheritdoc />
    public IReadOnlySet<string> Roles { get; }

    /// <inheritdoc />
    public IReadOnlyDictionary<string, string> Claims { get; }
}

using AI.Sentinel.Authorization;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Helpers;

internal sealed class TestSecurityContext(string id, params string[] roles) : ISecurityContext
{
    public string Id { get; } = id;

#pragma warning disable HLQ001 // Boxing on init is fine for a test helper
    public IReadOnlySet<string> Roles { get; } = new HashSet<string>(roles, StringComparer.Ordinal);
    public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
#pragma warning restore HLQ001
}

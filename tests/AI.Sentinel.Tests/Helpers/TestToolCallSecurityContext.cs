using System.Text.Json;
using AI.Sentinel.Authorization;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Helpers;

internal sealed class TestToolCallSecurityContext(ISecurityContext inner, string toolName, JsonElement args)
    : IToolCallSecurityContext
{
    public string Id => inner.Id;
    public IReadOnlySet<string> Roles => inner.Roles;
    public IReadOnlyDictionary<string, string> Claims => inner.Claims;
    public string ToolName { get; } = toolName;
    public JsonElement Args { get; } = args;
}

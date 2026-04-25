using System.Text.Json;

namespace AI.Sentinel.Authorization;

/// <summary>Tool-call-specific extension of <see cref="ISecurityContext"/>. Adds tool name + args for arg-aware policies.</summary>
public interface IToolCallSecurityContext : ISecurityContext
{
    /// <summary>Name of the tool being invoked.</summary>
    string ToolName { get; }

    /// <summary>Tool arguments as a JSON element.</summary>
    JsonElement Args { get; }
}

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>The outcome of checking one read of the folder: a module to publish, or a refusal.</summary>
internal sealed record ConfigurationVerdict(
    string? Organisation, string? Module, string? ModuleHash, IReadOnlyDictionary<string, NodeModule>? Modules, NodeConfiguration? Nodes,
    string? Reason, string? Detail)
{
    public bool IsAccepted => Reason is null;

    public static ConfigurationVerdict Accept(NodeConfiguration nodes, string module, string moduleHash, IReadOnlyDictionary<string, NodeModule> modules) =>
        new(nodes.Organisation, module, moduleHash, modules, nodes, null, null);

    public static ConfigurationVerdict Reject(string reason, string detail, string? organisation = null) =>
        new(organisation, null, null, null, null, reason, detail);
}

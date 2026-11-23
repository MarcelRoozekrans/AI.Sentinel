namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>One validated version of the policy folder, ready to be signed into profiles.</summary>
/// <param name="Organisation">The organisation the node configuration names.</param>
/// <param name="Version">The configuration version carried by every profile.</param>
/// <param name="Fingerprint">The hash of every file of the folder that was read.</param>
/// <param name="Module">The one Rego module of every bundle together. It identifies the configuration; a profile carries the module of its node.</param>
/// <param name="ModuleHash">The sha256 of <paramref name="Module"/>, lower case hex.</param>
/// <param name="Modules">The module of each node id: the organisation's top-level rules for the organisation node, the node's own
/// bundle for a team. That is what a profile carries, so a PC combines the two as it reads them from their slots.</param>
/// <param name="Nodes">The node configuration.</param>
internal sealed record PublishedConfiguration(
    string Organisation, long Version, string Fingerprint, string Module, string ModuleHash,
    IReadOnlyDictionary<string, NodeModule> Modules, NodeConfiguration Nodes);

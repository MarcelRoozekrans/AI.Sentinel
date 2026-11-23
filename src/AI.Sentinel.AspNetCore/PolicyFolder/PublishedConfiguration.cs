namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>One validated version of the policy folder, ready to be signed into profiles.</summary>
/// <param name="Organisation">The organisation the node configuration names.</param>
/// <param name="Version">The configuration version carried by every profile.</param>
/// <param name="Fingerprint">The hash of every file of the folder that was read.</param>
/// <param name="Module">The one Rego module of every bundle, as the plugin compiles it.</param>
/// <param name="ModuleHash">The sha256 of <paramref name="Module"/>, lower case hex.</param>
/// <param name="Nodes">The node configuration.</param>
internal sealed record PublishedConfiguration(
    string Organisation, long Version, string Fingerprint, string Module, string ModuleHash, NodeConfiguration Nodes);

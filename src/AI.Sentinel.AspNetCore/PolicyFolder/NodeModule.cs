namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>The Rego module of one node: its own bundle, merged into one text, and the sha256 of that text.</summary>
internal sealed record NodeModule(string Module, string ModuleHash);

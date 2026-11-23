namespace AI.Sentinel.AspNetCore;

/// <summary>
/// Settings of the policy folder the server part reads (ADR-107). Nothing is registered or mapped unless the host calls
/// <see cref="PolicyFolderExtensions.AddAISentinelPolicyFolder"/> and <see cref="PolicyFolderExtensions.MapAISentinelPolicyServer"/>.
/// Policy and node configuration only ever come from the folder; no endpoint accepts them.
/// </summary>
public sealed class PolicyFolderOptions
{
    /// <summary>The folder: Rego bundles, one folder or file per node, and <c>nodes.json</c>. Required. A central product fills it
    /// from the protected branch of a git repository; a standalone deployment keeps a git checkout there, for example with a
    /// git-sync sidecar. Whatever fills it has to swap it atomically, as git-sync does with a link.</summary>
    public string? Path { get; set; }

    /// <summary>The Ed25519 key that signs profiles: the base64 of a 32 byte seed. It reaches the server through the deployment at
    /// startup and is never stored or fetched. Required.</summary>
    public string? SigningKey { get; set; }

    /// <summary>The key that signed before <see cref="SigningKey"/>, during a rotation. Profiles then carry its endorsement of the new key.</summary>
    public string? PreviousSigningKey { get; set; }

    /// <summary>The <c>opa</c> executable that compiles policy in a child process, so a crash of the compiler cannot end the host.
    /// When unset, <c>opa</c> is looked up on the PATH.</summary>
    public string? OpaPath { get; set; }

    /// <summary>The name of the ASP.NET Core authorization policy a signed-in developer of the organisation has to satisfy. The
    /// organisation is passed as the resource, as a string. The host defines the policy. Defaults to <c>AISentinelDeveloper</c>.</summary>
    public string PolicyName { get; set; } = "AISentinelDeveloper";

    /// <summary>How long the folder has to stay unchanged before it is read. Defaults to half a second.</summary>
    public TimeSpan SettleDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>How often the folder is looked at when no change was seen, because swapping a link raises no file event. Defaults to 30 seconds.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(30);
}

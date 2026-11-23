using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Profiles;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore.PolicyFolder;

/// <summary>A temp folder that plays the policy folder, a loader on it, and the audit log it writes to.</summary>
internal sealed class PolicyFolderFixture : IDisposable
{
    public const string Organisation = "acme";
    public const string Repository = "github.com/acme/widgets";

    public const string OrgRules = "package sentinel\n\nimport rego.v1\n\ndeny contains \"recursive delete\" if input.kind == \"shell\"\n";
    public const string TeamRules = "package sentinel\n\nimport rego.v1\n\nask contains \"team asks\" if input.kind == \"fetch\"\n";

    public static readonly string Nodes = """
        {
          "organisation": "acme",
          "nodes": [
            {"id": "acme", "kind": "organisation", "settings": {"fail_mode": "closed"}},
            {"id": "team-a", "kind": "team", "settings": {"profile_lifetime_hours": 24, "detailed_logging": true}}
          ],
          "repositories": {"github.com/acme/widgets": "team-a", "github.com/acme/other": "acme"},
          "roles": [{"group": "sec", "role": "administrator", "node": "acme"}, {"group": "leads", "role": "team_lead", "node": "team-a"}]
        }
        """;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "sentinel-policy-folder-" + Guid.NewGuid().ToString("N"));

    public PolicyFolderFixture(ScriptedCompiler? compiler = null, IRegoCompiler? real = null)
    {
        Directory.CreateDirectory(_root);
        Compiler = compiler ?? new ScriptedCompiler();
        Store = new InMemoryAdminAuditStore();
        Key = ProfileSigningKey.Generate();
        Log = new AdminAuditLog(Store, new ProfileSigningKeys(Key), TimeProvider.System);
        Loader = new PolicyFolderLoader(
            Folder,
            new ConfigurationCompiler([real ?? Compiler]),
            async (organisation, action, target, ct) => await Log.RecordAsync(organisation, action, "policy-folder", target, AdminAuditChannel.Git, ct),
            "fallback-org",
            TimeProvider.System,
            new PolicyFolderTiming(TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(40), 12),
            NullLogger.Instance);
    }

    public ScriptedCompiler Compiler { get; }

    public InMemoryAdminAuditStore Store { get; }

    public ProfileSigningKey Key { get; }

    public AdminAuditLog Log { get; }

    public PolicyFolderLoader Loader { get; }

    /// <summary>The path the loader is given. A plain folder, or a link once <see cref="LinkTo"/> was called.</summary>
    public string Folder => Path.Combine(_root, "current");

    public string Version(string name) => Path.Combine(_root, name);

    /// <summary>Writes a complete folder named <paramref name="name"/> next to the link.</summary>
    public string Write(string name, string orgRules = OrgRules, string? teamRules = TeamRules, string? nodes = null)
    {
        var dir = Version(name);
        Directory.CreateDirectory(Path.Combine(dir, "team-a"));
        File.WriteAllText(Path.Combine(dir, "acme.rego"), orgRules);
        if (teamRules is not null)
        {
            File.WriteAllText(Path.Combine(dir, "team-a", "rules.rego"), teamRules);
        }

        File.WriteAllText(Path.Combine(dir, "nodes.json"), nodes ?? Nodes);
        return dir;
    }

    /// <summary>Makes the folder the loader reads a link to <paramref name="name"/>, swapped in atomically as git-sync does.</summary>
    public void LinkTo(string name)
    {
        if (OperatingSystem.IsWindows())
        {
            // No atomic swap of a link here; the tests that swap during a read are about the loader, not the filesystem.
            if (Directory.Exists(Folder))
            {
                Directory.Delete(Folder);
            }

            Directory.CreateSymbolicLink(Folder, Version(name));
            return;
        }

        var staging = Path.Combine(_root, $"swap-{Guid.NewGuid():N}");
        Directory.CreateSymbolicLink(staging, Version(name));
        // rename(2) through mv -T replaces the old link in one step, as git-sync does.
        var psi = new System.Diagnostics.ProcessStartInfo("mv") { UseShellExecute = false };
        psi.ArgumentList.Add("-T");
        psi.ArgumentList.Add(staging);
        psi.ArgumentList.Add(Folder);
        using var process = System.Diagnostics.Process.Start(psi)!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }

    public async Task<IReadOnlyList<AdminAuditEntry>> AuditAsync(string organisation = Organisation) =>
        await Store.ReadAsync(organisation, TestContext.Current.CancellationToken);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A temp folder that stays behind is cleaned up with the temp folder.
        }
    }
}

using System.Security.Cryptography;
using System.Text;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// Every Rego file of a policy folder, read once, plus the host's own combining rules. All of it compiles into one module,
/// which is identified by the sha256 of every file and the entrypoint, so a cache entry cannot outlive a policy change.
/// </summary>
/// <param name="Files">The files in ordinal path order, the host file included. The compiler is given these texts, not the
/// folder, so what is hashed is what is compiled.</param>
/// <param name="Bundles">The names of the folder's bundles: a subfolder is one, and a file at the top is one named after it.</param>
/// <param name="Hash">The module id, lowercase hex.</param>
internal sealed record PolicySources(IReadOnlyList<PolicyFile> Files, IReadOnlyList<string> Bundles, string Hash)
{
    /// <summary>The rule a policy is queried through: <c>data.sentinel.decision</c>.</summary>
    public const string Entrypoint = "sentinel/decision";

    /// <summary>Where the host's combining rules sit. A folder with a file there is refused, so a policy cannot replace them.</summary>
    public const string HostBundle = "_sentinel_host";

    /// <summary>The policy version carried by a decision: the start of <see cref="Hash"/>.</summary>
    public string Version => Hash[..16];

    public static PolicySources Load(string root)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);
        var found = new List<PolicyFile>();
        foreach (var path in Directory.EnumerateFiles(root, "*.rego", SearchOption.AllDirectories))
        {
            var relative = System.IO.Path.GetRelativePath(root, path).Replace('\\', '/');
            if (ClimbsOut(relative))
            {
                throw new InvalidDataException($"{relative}: a file name must not climb out of the folder");
            }

            if (relative.StartsWith(HostBundle + "/", StringComparison.Ordinal))
            {
                throw new InvalidDataException($"{relative}: the folder name {HostBundle} is reserved for the host");
            }

            // Line endings are normalised so a Windows checkout hashes like a Linux one.
            found.Add(new PolicyFile(relative, File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal)));
        }

        if (found.Count == 0)
        {
            throw new InvalidDataException("the folder holds no .rego file");
        }

        var bundles = found.Select(f => BundleOf(f.Path)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        found.Add(new PolicyFile($"{HostBundle}/decision.rego", HostRules.Text));
        found.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        return new PolicySources(found, bundles, ComputeHash(found));
    }

    private static bool ClimbsOut(string relative)
    {
        foreach (var segment in relative.Split('/'))
        {
            if (segment is ".." or ".")
            {
                return true;
            }
        }

        return false;
    }

    private static string BundleOf(string path)
    {
        var slash = path.IndexOf('/', StringComparison.Ordinal);
        return slash < 0 ? System.IO.Path.GetFileNameWithoutExtension(path) : path[..slash];
    }

    private static string ComputeHash(List<PolicyFile> files)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(Encoding.UTF8.GetBytes(Entrypoint + "\n"));
        foreach (var file in files)
        {
            sha.AppendData(Encoding.UTF8.GetBytes($"{file.Path}\n{file.Text.Length}\n{file.Text}\n"));
        }

        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }
}

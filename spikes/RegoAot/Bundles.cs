using System.Security.Cryptography;
using System.Text;

namespace RegoAot;

/// <summary>
/// Every bundle of a configuration (one directory each) compiled into one module. The module is
/// identified by the hash of every source file, so a cache entry cannot outlive a policy change.
/// </summary>
internal sealed record BundleSet(string Root, IReadOnlyList<string> Bundles, IReadOnlyList<string> Files, string Hash)
{
    public const string Entrypoint = "sentinel/decision";

    public static BundleSet Load(string root)
    {
        var files = Directory.EnumerateFiles(root, "*.rego", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToList();
        if (files.Count == 0)
        {
            throw new InvalidDataException($"no .rego file under {root}");
        }

        var bundles = files.Select(f => f.Split('/')[0]).Distinct(StringComparer.Ordinal).ToList();
        return new BundleSet(root, bundles, files, ComputeHash(root, files));
    }

    private static string ComputeHash(string root, List<string> files)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(Encoding.UTF8.GetBytes(Entrypoint + "\n"));
        foreach (var file in files)
        {
            // Line endings are normalised so a Windows checkout hashes like a Linux one.
            var text = File.ReadAllText(Path.Combine(root, file)).Replace("\r\n", "\n", StringComparison.Ordinal);
            sha.AppendData(Encoding.UTF8.GetBytes($"{file}\n{text.Length}\n{text}\n"));
        }

        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }
}

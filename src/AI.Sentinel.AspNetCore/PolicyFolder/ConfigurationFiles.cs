using System.Security.Cryptography;
using System.Text;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>
/// One complete read of a policy folder, held in memory: every <c>.rego</c> file and <c>nodes.json</c>. What is compiled is this copy,
/// never the folder, and a second read has to equal it before anything is published.
/// </summary>
internal sealed class ConfigurationFiles
{
    private const int MaxFiles = 2000;
    private const long MaxFileBytes = 2 * 1024 * 1024;
    private const long MaxTotalBytes = 32 * 1024 * 1024;

    private ConfigurationFiles(string realPath, SortedDictionary<string, byte[]> files)
    {
        RealPath = realPath;
        Files = files;
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var (path, bytes) in files)
        {
            sha.AppendData(Encoding.UTF8.GetBytes($"{path}\n{bytes.Length}\n"));
            sha.AppendData(bytes);
        }

        Fingerprint = Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    /// <summary>The folder that was read, with every link resolved once.</summary>
    public string RealPath { get; }

    /// <summary>Path below the folder, forward slashes, to the bytes of the file, in ordinal order.</summary>
    public IReadOnlyDictionary<string, byte[]> Files { get; }

    /// <summary>A hash of every path and content, so two reads compare by one value.</summary>
    public string Fingerprint { get; }

    public IEnumerable<KeyValuePair<string, byte[]>> RegoFiles => Files.Where(f => f.Key.EndsWith(".rego", StringComparison.Ordinal));

    public byte[]? NodesJson => Files.TryGetValue(NodeConfiguration.FileName, out var bytes) ? bytes : null;

    /// <summary>The real path of <paramref name="folder"/>: the target of every link in the path, the last one included.</summary>
    /// <exception cref="DirectoryNotFoundException">There is no such folder, or a link of the path leads nowhere.</exception>
    public static string Resolve(string folder)
    {
        var full = Path.GetFullPath(folder);
        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException("the policy folder does not exist");
        }

        var resolved = RealPathOf(full, budget: 40);
        return Directory.Exists(resolved) ? resolved : throw new DirectoryNotFoundException("the policy folder is a link that leads nowhere");
    }

    // Walks the path from its root and replaces each component that is a link by its target, so a link anywhere in the path is
    // followed here and never again when a file is opened through the result.
    private static string RealPathOf(string full, int budget)
    {
        var root = Path.GetPathRoot(full) ?? "";
        var current = root;
        foreach (var part in full[root.Length..].Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if (new DirectoryInfo(current).LinkTarget is null)
            {
                continue;
            }

            if (--budget < 0 || new DirectoryInfo(current).ResolveLinkTarget(returnFinalTarget: true) is not { } target)
            {
                throw new DirectoryNotFoundException("the policy folder path holds more links than the server follows");
            }

            // The target of a link can itself lie below a link.
            current = RealPathOf(Path.GetFullPath(target.FullName), budget);
        }

        return Path.TrimEndingDirectorySeparator(current);
    }

    /// <summary>Reads every file of <paramref name="realPath"/> into memory.</summary>
    /// <param name="realPath">The folder, already resolved.</param>
    /// <param name="afterFile">Called after each file is read; lets a test change the folder in the middle of the read.</param>
    /// <exception cref="IOException">A file or folder vanished or cannot be read: the pass is discarded.</exception>
    /// <exception cref="InvalidDataException">The folder holds a link or is larger than the limits: the configuration is refused.</exception>
    public static ConfigurationFiles Read(string realPath, Action<string>? afterFile = null)
    {
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        long total = 0;
        foreach (var path in Enumerate(realPath))
        {
            var relative = Path.GetRelativePath(realPath, path).Replace('\\', '/');
            if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidDataException($"{relative}: a link inside the policy folder is not followed");
            }

            var bytes = ReadFile(path, relative);
            total += bytes.Length;
            if (files.Count >= MaxFiles || total > MaxTotalBytes)
            {
                throw new InvalidDataException("the policy folder holds more than the server reads");
            }

            files[relative] = bytes;
            afterFile?.Invoke(relative);
        }

        return new ConfigurationFiles(realPath, files);
    }

    /// <summary>Whether <paramref name="other"/> holds exactly the same files with exactly the same content.</summary>
    public bool SameAs(ConfigurationFiles other) =>
        string.Equals(Fingerprint, other.Fingerprint, StringComparison.Ordinal);

    private static byte[] ReadFile(string path, string relative)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > MaxFileBytes)
        {
            throw new InvalidDataException($"{relative}: larger than the server reads");
        }

        var bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    // Only what the server uses: Rego files below the folder and nodes.json at its top. A dot folder such as .git is not read.
    private static IEnumerable<string> Enumerate(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(dir).Order(StringComparer.Ordinal))
            {
                var name = Path.GetFileName(entry);
                if (name.StartsWith('.'))
                {
                    continue;
                }

                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        throw new InvalidDataException($"{Path.GetRelativePath(root, entry)}: a link inside the policy folder is not followed");
                    }

                    pending.Push(entry);
                }
                else if (name.EndsWith(".rego", StringComparison.Ordinal) || (string.Equals(dir, root, StringComparison.Ordinal) && string.Equals(name, NodeConfiguration.FileName, StringComparison.Ordinal)))
                {
                    yield return entry;
                }
            }
        }
    }
}

using System.Security.Cryptography;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The compiled forms of a policy on disk: the WebAssembly module and the native code Wasmtime made from it. The native code
/// is loaded and run, so the directory is per user and owner-only, never the shared temp directory, and every file starts
/// with the sha256 digest of the rest. A reader checks the digest on the bytes it read, so the checked bytes are the loaded
/// bytes, and a file that is missing, short, damaged or half written reads as absent. A file is written whole under another
/// name and then moved, so a hook process that starts while another one writes sees the old file or the new one.
/// </summary>
/// <remarks>
/// The digest guards against damage and against a partly written file. It does not stop someone who can write to the
/// directory, because that person can write the digest too. The owner-only directory is what keeps other users out.
/// </remarks>
internal static class PolicyCache
{
    private const int DigestLength = 32;

    /// <summary>The cache directory: <c>SENTINEL_HOOK_POLICY_CACHE_DIR</c> when set, otherwise one under the user's local
    /// application data.</summary>
    public static string DefaultDirectory(IReadOnlyDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (env.TryGetValue("SENTINEL_HOOK_POLICY_CACHE_DIR", out var configured) && !string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(baseDir))
        {
            baseDir = Path.Combine(Path.GetTempPath(), "ai-sentinel-" + Environment.UserName);
        }

        return Path.Combine(baseDir, "ai-sentinel", "policy-cache");
    }

    /// <summary>Creates the directory, owner-only on Unix. A directory that is not ours to restrict throws.</summary>
    public static void Prepare(string dir)
    {
        ArgumentException.ThrowIfNullOrEmpty(dir);
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dir);
            return;
        }

        const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(dir, OwnerOnly);
        if ((File.GetUnixFileMode(dir) & ~OwnerOnly) != UnixFileMode.None)
        {
            File.SetUnixFileMode(dir, OwnerOnly);
        }
    }

    /// <summary>Writes <paramref name="payload"/> with its digest in front, whole, under a temporary name first.</summary>
    public static void Write(string path, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var bytes = new byte[DigestLength + payload.Length];
        SHA256.HashData(payload, bytes);
        payload.CopyTo(bytes, DigestLength);
        var temp = $"{path}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllBytes(temp, bytes);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    /// <summary>The payload of the file, or <see langword="null"/> when the file is missing or does not match its digest.</summary>
    public static byte[]? TryRead(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }

        if (bytes.Length < DigestLength)
        {
            return null;
        }

        var payload = bytes.AsSpan(DigestLength);
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), bytes.AsSpan(0, DigestLength))
            ? payload.ToArray()
            : null;
    }
}

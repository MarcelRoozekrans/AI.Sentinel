using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

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
/// directory, because that person can write the digest too. The owner-only directory is what keeps other users out. A
/// directory that already exists and is open to others is not trusted: its entries could have been written by them, so they
/// are removed before the permissions are tightened, and the policy is compiled again.
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

    /// <summary>Creates the directory, private to the user: mode 700 on Unix, a protected ACL on Windows. A directory that is
    /// not ours to restrict throws. A directory that already existed and was open to others loses its entries, which could
    /// have been planted.</summary>
    public static void Prepare(string dir)
    {
        ArgumentException.ThrowIfNullOrEmpty(dir);
        if (OperatingSystem.IsWindows())
        {
            PrepareWindows(dir);
            return;
        }

        const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(dir, OwnerOnly);
        if ((File.GetUnixFileMode(dir) & ~OwnerOnly) != UnixFileMode.None)
        {
            File.SetUnixFileMode(dir, OwnerOnly);
            Purge(dir); // after the mode change, so nobody can plant a file while the old ones are removed
        }
    }

    [SupportedOSPlatform("windows")]
    private static void PrepareWindows(string dir)
    {
        var user = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("the current Windows user has no SID");
        var info = new DirectoryInfo(dir);
        if (!info.Exists)
        {
            if (info.Parent is { Exists: false } parent)
            {
                Directory.CreateDirectory(parent.FullName);
            }

            info.Create(PrivateSecurity(user));
            return;
        }

        if (!IsPrivate(info.GetAccessControl(), user))
        {
            info.SetAccessControl(PrivateSecurity(user));
            Purge(dir);
        }
    }

    // Full control for the user alone, inherited by what is created inside, and nothing inherited from the parent.
    [SupportedOSPlatform("windows")]
    private static DirectorySecurity PrivateSecurity(SecurityIdentifier user)
    {
        var security = new DirectorySecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    // Owned by the user, and no one but the user, the system and the administrators may be allowed anything.
    [SupportedOSPlatform("windows")]
    internal static bool IsPrivate(DirectorySecurity security, SecurityIdentifier user)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !owner.Equals(user))
        {
            return false;
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || rule.IdentityReference is not SecurityIdentifier who)
            {
                continue;
            }

            if (!who.Equals(user) && !who.IsWellKnown(WellKnownSidType.LocalSystemSid) && !who.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                return false;
            }
        }

        return true;
    }

    private static void Purge(string dir)
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
        {
            if (Directory.Exists(entry) && (File.GetAttributes(entry) & FileAttributes.ReparsePoint) != FileAttributes.ReparsePoint)
            {
                Directory.Delete(entry, recursive: true);
            }
            else
            {
                File.Delete(entry);
            }
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

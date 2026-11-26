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
/// directory that already exists and is open to others is not trusted: its entries could have been written by them. It is left
/// alone and a private sibling is used instead, where the policy is compiled again. The entries are never deleted, because
/// removing them in place would leave a window in which another hook could load one.
/// </remarks>
internal static class PolicyCache
{
    private const int DigestLength = 32;
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

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

    /// <summary>The directory the cache uses, private to the user: mode 700 on Unix, a protected ACL on Windows. A
    /// directory that is missing is created private, in one step. One that exists and is private is used. One that exists and
    /// is open to others is never used, changed or emptied: its entries could have been written by them, and tightening it
    /// would leave them there. The cache moves to a sibling named <c>&lt;dir&gt;.private</c>, created private in one step, and
    /// stays there, also after the open directory is later made private. A sibling that exists and is not private throws.</summary>
    /// <remarks>Every step is an atomic creation or a check of a directory that only its owner can change, so processes that
    /// start together reach the same directory and none of them reads an entry from a directory that was ever open. No lock
    /// and no purge are needed.</remarks>
    public static string Prepare(string dir)
    {
        ArgumentException.ThrowIfNullOrEmpty(dir);
        var sibling = Path.TrimEndingDirectorySeparator(dir) + ".private";
        if (!Directory.Exists(sibling))
        {
            CreatePrivate(dir);
            if (IsPrivate(dir))
            {
                return dir;
            }
        }

        CreatePrivate(sibling);
        return IsPrivate(sibling)
            ? sibling
            : throw new UnauthorizedAccessException($"the policy cache directory '{sibling}' exists and is open to other users");
    }

    private static void CreatePrivate(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            CreatePrivateWindows(dir);
            return;
        }

        Directory.CreateDirectory(dir, OwnerOnly);
    }

    private static bool IsPrivate(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            return IsPrivateWindows(dir);
        }

        return (File.GetUnixFileMode(dir) & ~OwnerOnly) == UnixFileMode.None;
    }

    [SupportedOSPlatform("windows")]
    private static void CreatePrivateWindows(string dir)
    {
        var user = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("the current Windows user has no SID");
        var info = new DirectoryInfo(dir);
        if (info.Exists)
        {
            return;
        }

        if (info.Parent is { Exists: false } parent)
        {
            Directory.CreateDirectory(parent.FullName);
        }

        try
        {
            info.Create(PrivateSecurity(user));
        }
        catch (IOException) when (Directory.Exists(dir))
        {
            // Another hook created it first, with the same private ACL or another one, which IsPrivate checks.
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsPrivateWindows(string dir)
    {
        var user = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("the current Windows user has no SID");
        var security = new DirectoryInfo(dir).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Select(rule => new AccessRule(rule.AccessControlType == AccessControlType.Allow, (rule.IdentityReference as SecurityIdentifier)?.Value));
        return IsPrivate(owner?.Value, user.Value, rules);
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

    /// <summary>One access rule of a Windows ACL: whether it allows, and the SID it is for, <see langword="null"/> when the
    /// identity is not a SID.</summary>
    internal readonly record struct AccessRule(bool Allows, string? Sid);

    private const string LocalSystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";

    /// <summary>Whether a Windows ACL is private to <paramref name="userSid"/>: owned by the user, and no one but the user,
    /// the system and the administrators is allowed anything. A deny rule never opens a directory.</summary>
    internal static bool IsPrivate(string? ownerSid, string userSid, IEnumerable<AccessRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        return string.Equals(ownerSid, userSid, StringComparison.OrdinalIgnoreCase)
            && rules.All(rule => !rule.Allows || rule.Sid is null
                || string.Equals(rule.Sid, userSid, StringComparison.OrdinalIgnoreCase)
                || string.Equals(rule.Sid, LocalSystemSid, StringComparison.OrdinalIgnoreCase)
                || string.Equals(rule.Sid, AdministratorsSid, StringComparison.OrdinalIgnoreCase));
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
    public static byte[]? TryRead(string path) => ReadFile(path) is { } bytes ? Verify(bytes) : null;

    /// <summary>The bytes of the file, or <see langword="null"/> when the file is missing. Any other failure to read it throws, so a
    /// caller can tell a file that is not there from one it cannot read.</summary>
    public static byte[]? ReadFile(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>The payload of <paramref name="bytes"/>, or <see langword="null"/> when they do not match their digest.</summary>
    public static byte[]? Verify(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
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

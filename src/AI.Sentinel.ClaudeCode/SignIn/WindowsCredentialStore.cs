using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The Windows Credential Manager. <c>CredWriteW</c>, <c>CredReadW</c> and <c>CredDeleteW</c> are bound at build time with
/// <c>LibraryImport</c>, so they are safe under Native AOT. The secret is the credential blob of a generic credential of the current
/// user; the Credential Manager limits a blob to 2560 bytes, and a longer refresh token is not taken (the store says so and the
/// token stays in memory).
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed partial class WindowsCredentialStore(string account, Action<string>? log = null) : ITokenStore
{
    private const uint CredTypeGeneric = 1;
    private const uint PersistLocalMachine = 2;
    private const int MaxBlobBytes = 2560;

    public string Name => "Windows Credential Manager";

    private string Target => "ai-sentinel/oidc/" + account;

    public bool Save(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var blob = Encoding.UTF8.GetBytes(secret);
        if (blob.Length > MaxBlobBytes)
        {
            log?.Invoke($"the {Name} takes a secret of {MaxBlobBytes} bytes at most; the refresh token is kept in memory only");
            return false;
        }

        var targetPtr = Marshal.StringToCoTaskMemUni(Target);
        var userPtr = Marshal.StringToCoTaskMemUni(Environment.UserName);
        var blobPtr = Marshal.AllocCoTaskMem(Math.Max(blob.Length, 1));
        try
        {
            Marshal.Copy(blob, 0, blobPtr, blob.Length);
            var credential = new Credential
            {
                Type = CredTypeGeneric,
                TargetName = targetPtr,
                CredentialBlobSize = (uint)blob.Length,
                CredentialBlob = blobPtr,
                Persist = PersistLocalMachine,
                UserName = userPtr,
            };
            var ok = CredWrite(ref credential, 0);
            log?.Invoke(ok ? $"the refresh token is kept in the {Name}" : $"the {Name} refused the refresh token (error {Marshal.GetLastPInvokeError()})");
            return ok;
        }
        finally
        {
            Marshal.Copy(new byte[blob.Length], 0, blobPtr, blob.Length);
            Marshal.FreeCoTaskMem(blobPtr);
            Marshal.FreeCoTaskMem(targetPtr);
            Marshal.FreeCoTaskMem(userPtr);
        }
    }

    public string? Load()
    {
        if (!CredRead(Target, CredTypeGeneric, 0, out var ptr))
        {
            return null;
        }

        try
        {
            var credential = Marshal.PtrToStructure<Credential>(ptr);
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
            {
                return null;
            }

            var bytes = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            CredFree(ptr);
        }
    }

    public bool Delete() => CredDelete(Target, CredTypeGeneric, 0) || Marshal.GetLastPInvokeError() == ErrorNotFound;

    private const int ErrorNotFound = 1168;

    [StructLayout(LayoutKind.Sequential)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredWrite(ref Credential credential, uint flags);

    [LibraryImport("advapi32.dll", EntryPoint = "CredReadW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredRead(string target, uint type, uint flags, out IntPtr credential);

    [LibraryImport("advapi32.dll", EntryPoint = "CredDeleteW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredDelete(string target, uint type, uint flags);

    [LibraryImport("advapi32.dll", EntryPoint = "CredFree")]
    private static partial void CredFree(IntPtr buffer);
}

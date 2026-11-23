using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The macOS Keychain, through the Security framework: the generic password calls are bound at build time with
/// <c>LibraryImport</c>, so they are safe under Native AOT. The <c>security</c> command is not used: it takes the secret as an argument,
/// which every process of the user can read in the process list.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed partial class MacKeychainStore(string account, Action<string>? log = null) : ITokenStore
{
    private const string Service = "ai-sentinel";
    private const int ErrSecSuccess = 0;
    private const int ErrSecDuplicateItem = -25299;
    private const int ErrSecItemNotFound = -25300;

    public string Name => "macOS Keychain";

    public bool Save(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var service = Encoding.UTF8.GetBytes(Service);
        var name = Encoding.UTF8.GetBytes(account);
        var data = Encoding.UTF8.GetBytes(secret);
        try
        {
            var status = SecKeychainAddGenericPassword(IntPtr.Zero, (uint)service.Length, service, (uint)name.Length, name, (uint)data.Length, data, out var item);
            if (status == ErrSecDuplicateItem)
            {
                status = Replace(service, name, data);
            }
            else if (item != IntPtr.Zero)
            {
                CFRelease(item);
            }

            log?.Invoke(status == ErrSecSuccess ? $"the refresh token is kept in the {Name}" : $"the {Name} refused the refresh token (status {status})");
            return status == ErrSecSuccess;
        }
        finally
        {
            Array.Clear(data);
        }
    }

    public string? Load()
    {
        var service = Encoding.UTF8.GetBytes(Service);
        var name = Encoding.UTF8.GetBytes(account);
        if (SecKeychainFindGenericPassword(IntPtr.Zero, (uint)service.Length, service, (uint)name.Length, name, out var length, out var data, out var item) != ErrSecSuccess)
        {
            return null;
        }

        try
        {
            var bytes = new byte[length];
            Marshal.Copy(data, bytes, 0, bytes.Length);
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            _ = SecKeychainItemFreeContent(IntPtr.Zero, data);
            if (item != IntPtr.Zero)
            {
                CFRelease(item);
            }
        }
    }

    public bool Delete()
    {
        var service = Encoding.UTF8.GetBytes(Service);
        var name = Encoding.UTF8.GetBytes(account);
        var status = SecKeychainFindGenericPassword(IntPtr.Zero, (uint)service.Length, service, (uint)name.Length, name, out _, out var data, out var item);
        if (status == ErrSecItemNotFound)
        {
            return true;
        }

        if (status != ErrSecSuccess)
        {
            return false;
        }

        _ = SecKeychainItemFreeContent(IntPtr.Zero, data);
        try
        {
            return SecKeychainItemDelete(item) == ErrSecSuccess;
        }
        finally
        {
            CFRelease(item);
        }
    }

    private static int Replace(byte[] service, byte[] name, byte[] data)
    {
        var status = SecKeychainFindGenericPassword(IntPtr.Zero, (uint)service.Length, service, (uint)name.Length, name, out _, out var old, out var item);
        if (status != ErrSecSuccess)
        {
            return status;
        }

        _ = SecKeychainItemFreeContent(IntPtr.Zero, old);
        try
        {
            return SecKeychainItemModifyAttributesAndData(item, IntPtr.Zero, (uint)data.Length, data);
        }
        finally
        {
            CFRelease(item);
        }
    }

    private const string Security = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    [LibraryImport(Security)]
    private static partial int SecKeychainAddGenericPassword(
        IntPtr keychain, uint serviceNameLength, byte[] serviceName, uint accountNameLength, byte[] accountName,
        uint passwordLength, byte[] passwordData, out IntPtr itemRef);

    [LibraryImport(Security)]
    private static partial int SecKeychainFindGenericPassword(
        IntPtr keychainOrArray, uint serviceNameLength, byte[] serviceName, uint accountNameLength, byte[] accountName,
        out uint passwordLength, out IntPtr passwordData, out IntPtr itemRef);

    [LibraryImport(Security)]
    private static partial int SecKeychainItemModifyAttributesAndData(IntPtr itemRef, IntPtr attrList, uint length, byte[] data);

    [LibraryImport(Security)]
    private static partial int SecKeychainItemFreeContent(IntPtr attrList, IntPtr data);

    [LibraryImport(Security)]
    private static partial int SecKeychainItemDelete(IntPtr itemRef);

    [LibraryImport(CoreFoundation)]
    private static partial void CFRelease(IntPtr cf);
}

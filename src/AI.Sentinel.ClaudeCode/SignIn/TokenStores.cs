using System.Security.Cryptography;
using System.Text;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>Picks the keychain of the operating system.</summary>
internal static class TokenStores
{
    /// <summary>The keychain of this operating system for the refresh token of <paramref name="settings"/>, or <see langword="null"/>
    /// on a platform that has none. A Linux without <c>secret-tool</c> or a keyring still gets a store; its calls fail, and the
    /// refresh token is then kept in memory only.</summary>
    public static ITokenStore? ForCurrentOs(SignInSettings settings, Action<string>? log = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var account = Account(settings);
        if (OperatingSystem.IsWindows())
        {
            return new WindowsCredentialStore(account, log);
        }

        if (OperatingSystem.IsMacOS())
        {
            return new MacKeychainStore(account, log);
        }

        return OperatingSystem.IsLinux() ? new SecretToolStore(account, log) : null;
    }

    /// <summary>The name of the secret: one per identity provider, client and server, so two sign-ins do not overwrite each other. A
    /// hash, so no address ends up in the name of a keychain item.</summary>
    internal static string Account(SignInSettings settings)
    {
        var text = $"{settings.Issuer.AbsoluteUri}|{settings.ClientId}|{settings.ServerUrl.AbsoluteUri}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..24];
    }
}

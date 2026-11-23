namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// Turns the url of a git remote into the name a node owns a repository by: host and path, lower case, without the scheme, the
/// credentials, the port or the <c>.git</c> suffix, so the ssh and https forms of one repository are the same name. Nothing of the
/// userinfo is kept, so a token embedded in a url never reaches the policy input or the audit.
/// </summary>
internal static class RepositoryUrl
{
    /// <summary>The name of the repository <paramref name="url"/> points at, or <see langword="null"/> for a url that names no host and
    /// path, such as a local path.</summary>
    public static string? Normalize(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        var text = url.Trim();
        string authority;
        string path;
        var scheme = text.IndexOf("://", StringComparison.Ordinal);
        if (scheme > 0)
        {
            if (text[..scheme].Equals("file", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var rest = text[(scheme + 3)..];
            var slash = rest.IndexOf('/', StringComparison.Ordinal);
            if (slash < 0)
            {
                return null;
            }

            authority = rest[..slash];
            path = rest[(slash + 1)..];
        }
        else
        {
            var firstSlash = text.IndexOf('/', StringComparison.Ordinal);
            var open = text.IndexOf('[', StringComparison.Ordinal);
            var close = open >= 0 ? text.IndexOf(']', open) : -1;
            var bracketed = open >= 0 && close > open && (firstSlash < 0 || open < firstSlash);
            if (bracketed && close + 1 < text.Length && text[close + 1] == '/')
            {
                // The name this returns, [ipv6]/path, so a name that was normalised once is normalised to itself.
                authority = text[..(close + 1)];
                path = text[(close + 2)..];
                return Join(authority, path);
            }

            // The scp form: [user@]host:path. A colon after a slash, or a drive letter, is a local path. The colons inside the
            // brackets of an ipv6 literal are part of the host.
            var colon = text.IndexOf(':', bracketed ? close : 0);
            if (colon <= 1 || (firstSlash >= 0 && firstSlash < colon))
            {
                return null;
            }

            authority = text[..colon];
            path = text[(colon + 1)..];
        }

        return Join(authority, path);
    }

    private static string? Join(string authority, string path)
    {
        // The userinfo ends at the last at sign of the authority; it is dropped whole, the password with it.
        var at = authority.LastIndexOf('@');
        var host = at >= 0 ? authority[(at + 1)..] : authority;
        if (host.StartsWith('['))
        {
            // The literal keeps its colons; whatever follows the closing bracket is the port.
            if (host.IndexOf(']', StringComparison.Ordinal) is var close and > 0)
            {
                host = host[..(close + 1)];
            }
        }
        else if (host.IndexOf(':', StringComparison.Ordinal) is var port and >= 0)
        {
            host = host[..port];
        }

        var name = path.Replace('\\', '/').Trim('/');
        if (name.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
        {
            name = name[..^4];
        }

        name = name.TrimEnd('/');
        return host.Length == 0 || name.Length == 0 ? null : (host + "/" + name).ToLowerInvariant();
    }
}

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// Reads the remote of the repository a folder belongs to straight from the git files, so a hook starts no <c>git</c> process.
/// A worktree has a <c>.git</c> file that points at its own folder, which names the common folder that holds the config; a submodule
/// has one that points at its folder under the superproject, whose config holds the submodule's own remote.
/// </summary>
internal static class GitRemote
{
    private const string Origin = "origin";

    /// <summary>The url of the remote of the repository that contains <paramref name="folder"/>: <c>origin</c> when there is one,
    /// else the first remote with a url. <see langword="null"/> for a folder outside git or a repository without a remote.</summary>
    public static string? UrlOf(string folder)
    {
        ArgumentException.ThrowIfNullOrEmpty(folder);
        try
        {
            return FindGitDirectory(Path.GetFullPath(folder)) is { } gitDir ? ReadUrl(ConfigFolder(gitDir)) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // What cannot be read names no repository, which strict repository mode treats as one no node owns.
            return null;
        }
    }

    private static string? FindGitDirectory(string start)
    {
        for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
        {
            var dot = Path.Combine(dir.FullName, ".git");
            if (Directory.Exists(dot))
            {
                return dot;
            }

            if (File.Exists(dot))
            {
                return ReadPointer(dot, dir.FullName);
            }
        }

        return null;
    }

    private static string? ReadPointer(string file, string owner)
    {
        const string Prefix = "gitdir:";
        foreach (var line in File.ReadLines(file))
        {
            if (line.StartsWith(Prefix, StringComparison.Ordinal))
            {
                var target = line[Prefix.Length..].Trim();
                var full = Path.GetFullPath(Path.IsPathRooted(target) ? target : Path.Combine(owner, target));
                return Directory.Exists(full) ? full : null;
            }
        }

        return null;
    }

    // A worktree's folder holds a commondir file that names the folder with the shared config.
    private static string ConfigFolder(string gitDir)
    {
        var common = Path.Combine(gitDir, "commondir");
        if (File.Exists(common) && File.ReadAllText(common).Trim() is { Length: > 0 } relative)
        {
            var full = Path.GetFullPath(Path.IsPathRooted(relative) ? relative : Path.Combine(gitDir, relative));
            if (Directory.Exists(full))
            {
                return full;
            }
        }

        return gitDir;
    }

    private static string? ReadUrl(string folder)
    {
        var config = Path.Combine(folder, "config");
        if (!File.Exists(config))
        {
            return null;
        }

        var found = new Found();
        Scan(config, depth: 0, found);
        return found.Origin ?? found.First;
    }

    // Git stops following includes at this depth.
    private const int MaxIncludeDepth = 10;

    /// <summary>Reads the remote urls of one config file, and of the files it includes where the include stands, so the order is the
    /// one git reads them in. An include that cannot be read, or that nests deeper than git follows, is skipped as git skips it.
    /// <c>includeIf</c> is not followed: its condition is for git to judge.</summary>
    private static void Scan(string file, int depth, Found found)
    {
        string? remote = null;
        var include = false;
        foreach (var raw in File.ReadLines(file))
        {
            var line = raw.Trim();
            if (line.StartsWith('['))
            {
                remote = RemoteName(line);
                include = string.Equals(SectionOf(line), "include", StringComparison.OrdinalIgnoreCase);
                // git reads [remote "origin"] url = ... on one line: what follows the closing bracket is an assignment of the section.
                line = AfterHeader(line);
            }

            if (!TryKeyValue(line, out var key, out var value))
            {
                continue;
            }

            if (include && string.Equals(key, "path", StringComparison.OrdinalIgnoreCase))
            {
                if (depth < MaxIncludeDepth && Resolve(file, value) is { } target && File.Exists(target))
                {
                    Scan(target, depth + 1, found);
                }
            }
            else if (remote is not null && string.Equals(key, "url", StringComparison.OrdinalIgnoreCase))
            {
                found.First ??= value;
                if (string.Equals(remote, Origin, StringComparison.Ordinal))
                {
                    found.Origin ??= value;
                }
            }
        }
    }

    // A relative include path is relative to the file that names it.
    private static string? Resolve(string file, string path) =>
        path.Length == 0 || path.StartsWith('~') ? null : Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(Path.GetDirectoryName(file) ?? "", path));

    // The text between the brackets before the first space or quote: remote for [remote "origin"], include for [include].
    private static string SectionOf(string header)
    {
        var end = header.IndexOfAny([' ', '\t', '"', ']']);
        return end < 0 ? header[1..] : header[1..end];
    }

    // The text after the bracket that closes the header, a bracket inside a quoted subsection name not counted.
    private static string AfterHeader(string header)
    {
        var quoted = false;
        for (var i = 1; i < header.Length; i++)
        {
            if (header[i] == '\\' && quoted)
            {
                i++;
            }
            else if (header[i] == '"')
            {
                quoted = !quoted;
            }
            else if (header[i] == ']' && !quoted)
            {
                return header[(i + 1)..].Trim();
            }
        }

        return "";
    }

    private static bool TryKeyValue(string line, out string key, out string value)
    {
        key = value = "";
        var equals = line.IndexOf('=', StringComparison.Ordinal);
        if (equals <= 0 || line.StartsWith('#') || line.StartsWith(';'))
        {
            return false;
        }

        key = line[..equals].TrimEnd();
        value = ParseValue(line[(equals + 1)..]);
        return true;
    }

    /// <summary>A config value as git reads it: an unquoted <c>#</c> or <c>;</c> starts a comment, a quoted part keeps them, the
    /// quotes themselves are dropped and a backslash escapes the next character.</summary>
    private static string ParseValue(string text)
    {
        var value = new System.Text.StringBuilder(text.Length);
        var quoted = false;
        var kept = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"')
            {
                quoted = !quoted;
                kept = value.Length;
            }
            else if (c == '\\' && i + 1 < text.Length)
            {
                i++;
                value.Append(text[i] switch { 'n' => '\n', 't' => '\t', 'b' => '\b', var other => other });
                kept = value.Length;
            }
            else if (!quoted && (c == '#' || c == ';'))
            {
                break;
            }
            else if (quoted || !char.IsWhiteSpace(c) || value.Length > 0)
            {
                value.Append(c);
                kept = quoted || !char.IsWhiteSpace(c) ? value.Length : kept;
            }
        }

        return value.ToString(0, kept);
    }

    private sealed class Found
    {
        public string? Origin { get; set; }

        public string? First { get; set; }
    }

    // [remote "origin"] gives origin; any other section gives null.
    private static string? RemoteName(string header)
    {
        const string Section = "[remote \"";
        if (!header.StartsWith(Section, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var end = header.IndexOf('"', Section.Length);
        return end < 0 ? null : header[Section.Length..end];
    }
}

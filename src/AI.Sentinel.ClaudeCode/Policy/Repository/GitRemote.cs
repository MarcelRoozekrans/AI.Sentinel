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
    /// <exception cref="InvalidDataException">The git files cannot be read, or their includes nest deeper than git follows or
    /// expand past <see cref="MaxConfigFiles"/> files. The hook blocks the call: it cannot tell which node owns the repository, and
    /// git itself stops on such a config too.</exception>
    public static string? UrlOf(string folder)
    {
        ArgumentException.ThrowIfNullOrEmpty(folder);
        try
        {
            return FindGitDirectory(Path.GetFullPath(folder)) is { } gitDir ? ReadUrl(ConfigFolder(gitDir)) : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // Treating an unreadable config as no repository would drop the owning node's rules, so the call is blocked instead.
            throw new InvalidDataException($"the git config of '{folder}' cannot be read, so the hook cannot tell which node owns the repository: {e.Message}", e);
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

    // Git refuses a config whose includes nest deeper than this, which also ends a file that includes itself.
    private const int MaxIncludeDepth = 10;

    /// <summary>How many config files one lookup reads at most, counting a file each time it is included. Includes that fan out stay
    /// under the depth limit and can still multiply, so this bounds the work of one hook call.</summary>
    internal const int MaxConfigFiles = 1000;

    /// <summary>Reads the remote urls of one config file, and of the files it includes where the include stands, so the order is the
    /// one git reads them in. A missing include is skipped as git skips it. <c>includeIf</c> is not followed: its condition is for
    /// git to judge.</summary>
    private static void Scan(string file, int depth, Found found)
    {
        if (++found.Files > MaxConfigFiles)
        {
            throw new IOException($"its includes expand past {MaxConfigFiles} files");
        }

        string? remote = null;
        var include = false;
        foreach (var logical in LogicalLines(file))
        {
            var line = logical.Trim();
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
                if (Resolve(file, value) is { } target && File.Exists(target))
                {
                    if (depth >= MaxIncludeDepth)
                    {
                        throw new IOException($"its includes nest deeper than the {MaxIncludeDepth} levels git follows");
                    }

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

    // A relative include path is relative to the file that names it; ~/ is the home folder, as git expands it.
    private static string? Resolve(string file, string path)
    {
        if (path.Length == 0)
        {
            return null;
        }

        if (path.StartsWith("~/", StringComparison.Ordinal))
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return home.Length == 0 ? null : Path.GetFullPath(Path.Combine(home, path[2..]));
        }

        return path.StartsWith('~') ? null : Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(Path.GetDirectoryName(file) ?? "", path));
    }

    /// <summary>The lines of a config file as git reads them: a line that ends in an unescaped backslash continues on the next one.</summary>
    private static IEnumerable<string> LogicalLines(string file)
    {
        var pending = new System.Text.StringBuilder();
        foreach (var raw in File.ReadLines(file))
        {
            var trailing = raw.Length - raw.TrimEnd('\\').Length;
            if (trailing % 2 == 1)
            {
                pending.Append(raw, 0, raw.Length - 1);
                continue;
            }

            pending.Append(raw);
            yield return pending.ToString();
            pending.Clear();
        }

        if (pending.Length > 0)
        {
            yield return pending.ToString();
        }
    }

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

        public int Files { get; set; }
    }

    // [remote "origin"] gives origin; any other section gives null. Git also accepts blanks or a tab between the section and the quoted
    // subsection, blanks before the closing bracket, and the old form [remote.origin].
    private static string? RemoteName(string header)
    {
        var close = header.IndexOf(']', StringComparison.Ordinal);
        var body = (close < 0 ? header[1..] : header[1..close]).Trim();
        const string Section = "remote";
        if (!body.StartsWith(Section, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var rest = body[Section.Length..];
        if (rest.StartsWith('.'))
        {
            return rest.Length > 1 ? rest[1..] : null;
        }

        rest = rest.TrimStart(' ', '\t');
        if (rest.Length == body.Length - Section.Length || !rest.StartsWith('"'))
        {
            return null;
        }

        var end = rest.IndexOf('"', 1);
        return end < 0 ? null : rest[1..end];
    }
}

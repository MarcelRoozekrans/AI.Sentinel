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

        string? remote = null;
        string? first = null;
        string? origin = null;
        foreach (var raw in File.ReadLines(config))
        {
            var line = raw.Trim();
            if (line.StartsWith('['))
            {
                remote = RemoteName(line);
                continue;
            }

            if (remote is null || !line.StartsWith("url", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var rest = line[3..].TrimStart();
            if (!rest.StartsWith('='))
            {
                continue;
            }

            var url = rest[1..].Trim().Trim('"');
            first ??= url;
            if (string.Equals(remote, Origin, StringComparison.Ordinal))
            {
                origin ??= url;
            }
        }

        return origin ?? first;
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

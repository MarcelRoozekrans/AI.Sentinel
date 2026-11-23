using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>Builds the <see cref="PolicyInput"/> of one tool call. Nothing reads it yet.</summary>
internal static class PolicyInputBuilder
{
    private const string McpPrefix = "mcp__";
    private static readonly string[] PathKeys = ["file_path", "path", "notebook_path"];

    /// <param name="cli">One of <see cref="PolicyClis"/>.</param>
    /// <param name="toolName">The CLI's own tool name.</param>
    /// <param name="toolInput">The tool arguments, or default when none were sent. Copilot may send them as a JSON string, which is read too.</param>
    /// <param name="session">The session id.</param>
    /// <param name="findings">Detector findings for the call.</param>
    /// <param name="repositoryRoot">The root a path must lie under to count as inside the repository. Null when unknown.</param>
    public static PolicyInput Build(
        string cli, string toolName, JsonElement toolInput, string session, IReadOnlyList<PolicyFinding> findings, string? repositoryRoot)
    {
        ArgumentNullException.ThrowIfNull(cli);
        ArgumentNullException.ThrowIfNull(toolName);
        ArgumentNullException.ThrowIfNull(findings);
        var kind = ToolKinds.Map(cli, toolName);
        var details = Details(kind, cli, toolName, ReadObject(toolInput), repositoryRoot);
        return new PolicyInput(kind.ToWire(), cli, toolName, details, findings, "", "", session ?? "");
    }

    private static PolicyDetails Details(ToolKind kind, string cli, string tool, JsonElement args, string? root) => kind switch
    {
        ToolKind.Shell => new PolicyDetails { Shell = Shell(cli, tool, args) },
        ToolKind.Mcp => new PolicyDetails { Mcp = Mcp(tool) },
        ToolKind.Read or ToolKind.Search or ToolKind.Write or ToolKind.Edit => Paths(args, root),
        ToolKind.Fetch => new PolicyDetails { Url = String(args, "url") },
        _ => new PolicyDetails(),
    };

    private static ShellDetails Shell(string cli, string tool, JsonElement args)
    {
        // The parser reads POSIX quoting. PowerShell quotes and escapes differently, so a parse would mislead.
        if (string.Equals(cli, PolicyClis.Copilot, StringComparison.Ordinal) && tool.Contains("powershell", StringComparison.Ordinal))
        {
            return new ShellDetails(true, []);
        }

        var command = String(args, "command");
        if (command is null)
        {
            return new ShellDetails(true, []);
        }

        var parsed = ShellCommandParser.Parse(command);
        return new ShellDetails(parsed.Unparseable, parsed.Commands);
    }

    private static McpDetails Mcp(string tool)
    {
        var rest = tool.StartsWith(McpPrefix, StringComparison.Ordinal) ? tool[McpPrefix.Length..] : tool;
        var split = rest.IndexOf("__", StringComparison.Ordinal);
        return split < 0 ? new McpDetails(rest, "", "") : new McpDetails(rest[..split], "", rest[(split + 2)..]);
    }

    private static PolicyDetails Paths(JsonElement args, string? root)
    {
        var paths = new List<PolicyPath>();
        foreach (var key in PathKeys)
        {
            if (String(args, key) is { Length: > 0 } path)
            {
                paths.Add(Resolve(path, root));
            }
        }

        return paths.Count == 0 ? new PolicyDetails() : new PolicyDetails { Paths = paths };
    }

    // Symbolic links are not followed: the flag is about the path as written, after . and .. are resolved.
    private static PolicyPath Resolve(string path, string? root)
    {
        if (path.StartsWith('~'))
        {
            return new PolicyPath(path, false);
        }

        string full;
        try
        {
            full = root is null ? (Path.IsPathRooted(path) ? Path.GetFullPath(path) : path) : Path.GetFullPath(path, root);
        }
        catch (ArgumentException)
        {
            return new PolicyPath(path, false);
        }

        return new PolicyPath(full, root is not null && IsInside(full, Path.GetFullPath(root)));
    }

    private static bool IsInside(string full, string root)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        full = ComparisonForm(full);
        root = ComparisonForm(root);
        var trimmed = root.Length > 1 ? root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) : root;
        if (string.Equals(full, trimmed, comparison))
        {
            return true;
        }

        var prefix = trimmed.EndsWith(Path.DirectorySeparatorChar) ? trimmed : trimmed + Path.DirectorySeparatorChar;
        return full.StartsWith(prefix, comparison);
    }

    // \\?\C:\dir and C:\dir name the same file, and so do \\?\UNC\host\share\dir and \\host\share\dir. Only those two forms are
    // rewritten; other device paths stay as they are. Windows does not resolve . and .. in an extended path, so they are
    // resolved here, lexically and never above the drive root or the share.
    internal static string ComparisonForm(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) && path.Length > 8)
        {
            return ResolveUnc(path[8..]);
        }

        if (path.Length < 6 || !path.StartsWith(@"\\?\", StringComparison.Ordinal) || !char.IsAsciiLetter(path[4]) || path[5] != ':')
        {
            return path;
        }

        var drive = path[4..];
        return drive.Length > 2 && drive[2] == '\\' ? ResolveDotSegments(drive) : drive;
    }

    private static string ResolveUnc(string hostAndShare)
    {
        var segments = hostAndShare.Split('\\');
        if (segments.Length < 2)
        {
            return @"\\" + hostAndShare;
        }

        var root = @"\\" + segments[0] + '\\' + segments[1];
        var kept = new List<string>();
        for (var k = 2; k < segments.Length; k++)
        {
            if (string.Equals(segments[k], "..", StringComparison.Ordinal))
            {
                if (kept.Count > 0)
                {
                    kept.RemoveAt(kept.Count - 1);
                }
            }
            else if (segments[k] is not ("." or ""))
            {
                kept.Add(segments[k]);
            }
        }

        var resolved = kept.Count == 0 ? root : root + '\\' + string.Join('\\', kept);
        return hostAndShare.EndsWith('\\') && kept.Count > 0 ? resolved + '\\' : resolved;
    }

    private static string ResolveDotSegments(string drivePath)
    {
        var kept = new List<string>();
        var segments = drivePath[3..].Split('\\');
        foreach (var segment in segments)
        {
            if (string.Equals(segment, "..", StringComparison.Ordinal))
            {
                if (kept.Count > 0)
                {
                    kept.RemoveAt(kept.Count - 1);
                }
            }
            else if (segment is not ("." or ""))
            {
                kept.Add(segment);
            }
        }

        var resolved = drivePath[..3] + string.Join('\\', kept);
        return drivePath.EndsWith('\\') && kept.Count > 0 ? resolved + '\\' : resolved;
    }

    private static string? String(JsonElement args, string key) =>
        args.ValueKind == JsonValueKind.Object && args.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? Decode(v) : null;

    // A string with a lone surrogate parses but cannot be decoded. It counts as missing.
    private static string? Decode(JsonElement value)
    {
        try
        {
            return value.GetString();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    // An object, or default when the input is missing or is not an object. A string holding a JSON object is read too.
    private static JsonElement ReadObject(JsonElement input)
    {
        if (input.ValueKind == JsonValueKind.Object)
        {
            return input;
        }

        if (input.ValueKind != JsonValueKind.String || Decode(input) is not { } text)
        {
            return default;
        }

        try
        {
            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : default;
        }
        catch (JsonException)
        {
            return default;
        }
    }
}

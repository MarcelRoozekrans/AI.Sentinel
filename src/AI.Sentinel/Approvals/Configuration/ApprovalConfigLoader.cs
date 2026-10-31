using System.Text.Json;
using System.Text.RegularExpressions;
using AI.Sentinel.Approvals.Conditions;

namespace AI.Sentinel.Approvals.Configuration;

/// <summary>Loads and validates an <see cref="ApprovalConfig"/> from disk. Expands
/// <c>${ENV_VAR}</c> placeholders against the process environment so config files can
/// safely commit to source control without baking in tenant IDs or other deployment-specific
/// values.</summary>
internal static class ApprovalConfigLoader
{
    /// <summary>The keys a tool entry understands, spelled exactly as the loader reads them.</summary>
    private static readonly string[] ToolEntryKeys = ["role", "grantMinutes", "requireJustification", "when", "grantScope"];

    private static readonly Regex EnvPlaceholder = new(@"\$\{(?<var>[A-Z_][A-Z0-9_]*)\}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture,
        TimeSpan.FromSeconds(1));

    /// <summary>Reads, expands, and validates the config at <paramref name="path"/>.</summary>
    /// <exception cref="FileNotFoundException">No file at <paramref name="path"/>.</exception>
    /// <exception cref="JsonException">Invalid JSON.</exception>
    /// <exception cref="InvalidOperationException">Required field missing or invalid value.</exception>
    public static ApprovalConfig Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path)) throw new FileNotFoundException("Approval config not found.", path);

        var raw = File.ReadAllText(path);
        var expanded = ExpandEnvPlaceholders(raw);

        var doc = JsonDocument.Parse(expanded);
        return Parse(doc.RootElement);
    }

    /// <summary>Parses an already-loaded JSON element. Useful for tests + in-memory callers.</summary>
    public static ApprovalConfig Parse(JsonElement root)
    {
        var backend = RequireString(root, "backend");
        var tenantId = OptionalString(root, "tenantId");
        var databasePath = OptionalString(root, "databasePath");
        var defaultGrantMinutes = OptionalInt(root, "defaultGrantMinutes") ?? 15;
        var defaultJustificationTemplate = OptionalString(root, "defaultJustificationTemplate")
            ?? "AI agent invocation: {tool}";
        var includeConversationContext = OptionalBool(root, "includeConversationContext") ?? true;

        var tools = new Dictionary<string, IReadOnlyList<ApprovalToolConfig>>(StringComparer.Ordinal);
        if (root.TryGetProperty("tools", out var toolsEl) && toolsEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in toolsEl.EnumerateObject())
            {
                // JSON readers disagree on which duplicate wins, so a repeated key is never silently resolved.
                if (tools.ContainsKey(prop.Name))
                    throw new InvalidOperationException($"tools has duplicate key '{prop.Name}'");
                tools[prop.Name] = ParseTools(prop.Value, prop.Name, backend);
            }
        }

        var config = new ApprovalConfig(
            backend, tenantId, databasePath, defaultGrantMinutes, defaultJustificationTemplate,
            includeConversationContext, tools)
        {
            NotifyUrl = ParseHttpUrl(root, "notifyUrl"),
            NotifyHeaders = ParseNotifyHeaders(root),
            NotifyIncludeArgs = ParseNotifyIncludeArgs(root),
            DashboardUrl = ParseHttpUrl(root, "dashboardUrl"),
        };

        Validate(config);
        return config;
    }

    private static Uri? ParseHttpUrl(JsonElement root, string key)
    {
        if (!root.TryGetProperty(key, out var el)) return null;
        // A URL is a credential for a webhook (the path or query carries the secret) and ${VAR} has already been
        // expanded, so no message below quotes the value.
        if (el.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException($"{key} must be a string");
        var text = el.GetString();
        if (string.IsNullOrWhiteSpace(text))
            throw new InvalidOperationException($"{key} is empty");
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"{key} is not an absolute URL");
        // On Unix "/x" parses as an absolute file:// URI, so the scheme check is what rejects it.
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            // The scheme is shown only when the value really is scheme://..., never for a bare "a:b" that may be a token.
            var shown = text.StartsWith(uri.Scheme + "://", StringComparison.OrdinalIgnoreCase)
                ? $"has scheme '{uri.Scheme}'; only http and https are allowed"
                : "must use http or https";
            throw new InvalidOperationException($"{key} {shown}");
        }
        return uri;
    }

    private static bool ParseNotifyIncludeArgs(JsonElement root)
    {
        if (!root.TryGetProperty("notifyIncludeArgs", out var el)) return false;
        if (el.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidOperationException($"notifyIncludeArgs must be true or false");
        return el.GetBoolean();
    }

    private static Dictionary<string, string> ParseNotifyHeaders(JsonElement root)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("notifyHeaders", out var el)) return headers;
        if (el.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("notifyHeaders must be an object of header name to string value");
        using var probe = new HttpRequestMessage();
        foreach (var prop in el.EnumerateObject())
        {
            if (headers.ContainsKey(prop.Name))
                throw new InvalidOperationException($"notifyHeaders has duplicate key '{prop.Name}'");
            if (prop.Value.ValueKind != JsonValueKind.String)
                throw new InvalidOperationException($"notifyHeaders['{prop.Name}'] must be a string");
            if (string.Equals(prop.Name, "Content-Type", StringComparison.OrdinalIgnoreCase)
                || string.Equals(prop.Name, "Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"notifyHeaders['{prop.Name}'] is not allowed: the notifier sets the body headers itself");
            }
            var value = prop.Value.GetString()!;
            // An unset ${VAR} expands to an empty string; sending a blank header would hide the misconfiguration.
            if (string.IsNullOrWhiteSpace(value))
                throw new InvalidOperationException($"notifyHeaders['{prop.Name}'] must not be empty");
            if (!probe.Headers.TryAddWithoutValidation(prop.Name, value))
                throw new InvalidOperationException($"notifyHeaders['{prop.Name}'] is not a valid header name or value");
            headers[prop.Name] = value;
        }
        return headers;
    }

    private static IReadOnlyList<ApprovalToolConfig> ParseTools(JsonElement el, string toolName, string backend)
    {
        if (el.ValueKind == JsonValueKind.Array)
        {
            var entries = new List<ApprovalToolConfig>();
            var index = 0;
            foreach (var item in el.EnumerateArray())
            {
                var location = $"tools.{toolName}[{index}]";
                var entry = ParseTool(item, location, backend);
                // An entry without conditions matches every call, so anything after it is unreachable.
                if (index > 0 && entries[index - 1].When.Count == 0)
                {
                    throw new InvalidOperationException(
                        $"{location} is unreachable: tools.{toolName}[{index - 1}] has no 'when' and matches every call");
                }
                entries.Add(entry);
                index++;
            }
            if (entries.Count == 0)
                throw new InvalidOperationException($"tools.{toolName} must not be an empty array");
            return entries;
        }
        return new[] { ParseTool(el, $"tools.{toolName}", backend) };
    }

    private static ApprovalToolConfig ParseTool(JsonElement el, string location, string backend)
    {
        if (el.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"{location} must be an object");
        RejectBadEntryKeys(el, location);
        var role = RequireString(el, "role", $"{location}.role");
        var grantMinutes = OptionalInt(el, "grantMinutes");
        var requireJustification = OptionalBool(el, "requireJustification");
        var when = ParseWhen(el, location);
        var grantScope = ParseGrantScope(el, location);
        if (grantScope == ApprovalGrantScope.Call
            && string.Equals(backend.Trim(), "entra-pim", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"{location}.grantScope 'call' is not supported with backend 'entra-pim': a PIM grant is a role activation and cannot be tied to arguments");
        }
        return new ApprovalToolConfig(role, grantMinutes, requireJustification, grantScope) { When = when };
    }

    /// <summary>
    /// Rejects a key that is a known key in another spelling, such as <c>grant_scope</c> or <c>When</c>:
    /// the loader would otherwise ignore it and drop the rule's condition or scope without a word.
    /// Keys unrelated to a known key stay accepted, so existing files with extra fields keep loading.
    /// A key that appears twice in the entry is rejected too.
    /// </summary>
    private static void RejectBadEntryKeys(JsonElement el, string location)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var prop in el.EnumerateObject())
        {
            // JSON readers disagree on which duplicate wins, so a repeated key is never silently resolved.
            if (!seen.Add(prop.Name))
                throw new InvalidOperationException($"{location} has duplicate key '{prop.Name}'");
            if (ToolEntryKeys.Contains(prop.Name, StringComparer.Ordinal))
                continue;
            var normalised = NormaliseKey(prop.Name);
            foreach (var known in ToolEntryKeys)
            {
                if (string.Equals(normalised, NormaliseKey(known), StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"{location}.{prop.Name} is not a recognised key; did you mean '{known}'?");
                }
            }
        }
    }

    private static string NormaliseKey(string key) =>
        key.Replace("_", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal)
            .ToLowerInvariant();

    private static List<KeyValuePair<string, string>> ParseWhen(JsonElement el, string location)
    {
        var when = new List<KeyValuePair<string, string>>();
        if (!el.TryGetProperty("when", out var whenEl)) return when;
        if (whenEl.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"{location}.when must be an object of JSON path to regex");
        foreach (var cond in whenEl.EnumerateObject())
        {
            if (when.Exists(c => string.Equals(c.Key, cond.Name, StringComparison.Ordinal)))
                throw new InvalidOperationException($"{location}.when has duplicate key '{cond.Name}'");
            if (cond.Value.ValueKind != JsonValueKind.String)
                throw new InvalidOperationException(
                    $"{location}.when['{cond.Name}'] must be a regex string");
            var pattern = cond.Value.GetString()!;
            try
            {
                _ = new ArgumentCondition(cond.Name, pattern); // validates path and regex at load
            }
            catch (ArgumentException ex)
            {
                throw new InvalidOperationException(
                    $"{location}.when['{cond.Name}'] is invalid: {ex.Message}", ex);
            }
            when.Add(new KeyValuePair<string, string>(cond.Name, pattern));
        }
        if (when.Count == 0)
            throw new InvalidOperationException($"{location}.when must not be empty");
        return when;
    }

    private static ApprovalGrantScope ParseGrantScope(JsonElement el, string location)
    {
        if (!el.TryGetProperty("grantScope", out var scopeEl)) return ApprovalGrantScope.Rule;
        var text = scopeEl.ValueKind == JsonValueKind.String ? scopeEl.GetString() : null;
        return text switch
        {
            "rule" => ApprovalGrantScope.Rule,
            "call" => ApprovalGrantScope.Call,
            _ => throw new InvalidOperationException(
                $"{location}.grantScope must be 'rule' or 'call'. Got: {scopeEl.GetRawText()}"),
        };
    }

    private static void Validate(ApprovalConfig config)
    {
        var backend = config.Backend.Trim().ToLowerInvariant();
        if (backend is not ("in-memory" or "sqlite" or "entra-pim" or "none"))
        {
            throw new InvalidOperationException(
                $"backend must be one of: in-memory, sqlite, entra-pim, none. Got: '{config.Backend}'");
        }
        if (config.DefaultGrantMinutes <= 0)
        {
            throw new InvalidOperationException(
                $"defaultGrantMinutes must be > 0. Got: {config.DefaultGrantMinutes}");
        }
        if (string.Equals(backend, "sqlite", StringComparison.Ordinal) && string.IsNullOrWhiteSpace(config.DatabasePath))
        {
            throw new InvalidOperationException(
                "backend 'sqlite' requires a databasePath field.");
        }
        if (string.Equals(backend, "entra-pim", StringComparison.Ordinal) && string.IsNullOrWhiteSpace(config.TenantId))
        {
            throw new InvalidOperationException(
                "backend 'entra-pim' requires a tenantId field.");
        }
        if (config.NotifyUrl is null)
        {
            if (config.NotifyHeaders.Count > 0)
                throw new InvalidOperationException("notifyHeaders requires notifyUrl.");
            if (config.NotifyIncludeArgs)
                throw new InvalidOperationException("notifyIncludeArgs requires notifyUrl.");
        }
    }

    /// <summary>Replaces <c>${VAR}</c> with <c>Environment.GetEnvironmentVariable("VAR")</c>.
    /// Unset variables expand to empty string. Escapes via <c>$${VAR}</c> are not supported
    /// (no real-world need yet).</summary>
    internal static string ExpandEnvPlaceholders(string input) =>
        EnvPlaceholder.Replace(input, m =>
            Environment.GetEnvironmentVariable(m.Groups["var"].Value) ?? string.Empty);

    private static string RequireString(JsonElement el, string property, string? path = null)
    {
        if (!el.TryGetProperty(property, out var propEl) || propEl.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException($"Required string field missing: {path ?? property}");
        }
        var value = propEl.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Required string field empty: {path ?? property}");
        }
        return value!;
    }

    private static string? OptionalString(JsonElement el, string property) =>
        el.TryGetProperty(property, out var propEl) && propEl.ValueKind == JsonValueKind.String
            ? propEl.GetString()
            : null;

    private static int? OptionalInt(JsonElement el, string property) =>
        el.TryGetProperty(property, out var propEl) && propEl.ValueKind == JsonValueKind.Number &&
        propEl.TryGetInt32(out var v)
            ? v : null;

    private static bool? OptionalBool(JsonElement el, string property) =>
        el.TryGetProperty(property, out var propEl) &&
        (propEl.ValueKind == JsonValueKind.True || propEl.ValueKind == JsonValueKind.False)
            ? propEl.GetBoolean() : null;
}

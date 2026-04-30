using System.Text.Json;
using System.Text.RegularExpressions;

namespace AI.Sentinel.Approvals.Configuration;

/// <summary>Loads and validates an <see cref="ApprovalConfig"/> from disk. Expands
/// <c>${ENV_VAR}</c> placeholders against the process environment so config files can
/// safely commit to source control without baking in tenant IDs or other deployment-specific
/// values.</summary>
public static class ApprovalConfigLoader
{
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

        var tools = new Dictionary<string, ApprovalToolConfig>(StringComparer.Ordinal);
        if (root.TryGetProperty("tools", out var toolsEl) && toolsEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in toolsEl.EnumerateObject())
            {
                tools[prop.Name] = ParseTool(prop.Value, prop.Name);
            }
        }

        var config = new ApprovalConfig(
            backend, tenantId, databasePath, defaultGrantMinutes, defaultJustificationTemplate,
            includeConversationContext, tools);

        Validate(config);
        return config;
    }

    private static ApprovalToolConfig ParseTool(JsonElement el, string toolName)
    {
        if (el.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"tools.{toolName} must be an object");
        var role = RequireString(el, "role", $"tools.{toolName}.role");
        var grantMinutes = OptionalInt(el, "grantMinutes");
        var requireJustification = OptionalBool(el, "requireJustification");
        return new ApprovalToolConfig(role, grantMinutes, requireJustification);
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

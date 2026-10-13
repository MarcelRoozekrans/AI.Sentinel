namespace AI.Sentinel.Tests.Helpers;

/// <summary>Base for MCP proxy CLI test classes: turns SQLite recording off for the class's tests.</summary>
public abstract class McpAuditOffFixtureBase : IDisposable
{
    public const string SqliteVar = "SENTINEL_MCP_AUDIT_SQLITE";

    private readonly string? _previous = Environment.GetEnvironmentVariable(SqliteVar);

    protected McpAuditOffFixtureBase() =>
        Environment.SetEnvironmentVariable(SqliteVar, "off");

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(SqliteVar, _previous);
        GC.SuppressFinalize(this);
    }
}

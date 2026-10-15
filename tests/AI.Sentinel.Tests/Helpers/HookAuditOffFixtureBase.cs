namespace AI.Sentinel.Tests.Helpers;

/// <summary>Base for hook CLI test classes: turns SQLite recording off for the class's tests.</summary>
public abstract class HookAuditOffFixtureBase : IDisposable
{
    private readonly string? _previous = Environment.GetEnvironmentVariable(HookAuditTestSupport.SqliteVar);

    protected HookAuditOffFixtureBase() =>
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, "off");

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, _previous);
        GC.SuppressFinalize(this);
    }
}

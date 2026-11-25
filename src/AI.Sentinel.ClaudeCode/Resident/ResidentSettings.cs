using System.Globalization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The settings of the resident local process (#658). It is off by default: with <see cref="EnableVariable"/> unset no process
/// is started and a hook behaves as it did before. Setting <c>SENTINEL_HOOK_POLICY_DIR</c> does not turn it on, so a user of the
/// local policy keeps today's behaviour until they opt in.
/// </summary>
/// <param name="StateDirectory">The per-user folder that holds the socket, the lock, the pause state and the profile cache.</param>
/// <param name="IdleTimeout">How long the process waits without a request before it exits.</param>
/// <param name="Budget">How long a hook waits for the process to answer before it evaluates in-process.</param>
internal sealed record ResidentSettings(string StateDirectory, TimeSpan IdleTimeout, TimeSpan Budget)
{
    /// <summary>The environment variable that turns the resident process on: <c>on</c>, <c>1</c>, <c>true</c> or <c>yes</c>.</summary>
    public const string EnableVariable = "SENTINEL_HOOK_RESIDENT";

    /// <summary>The environment variable that moves the state folder.</summary>
    public const string DirectoryVariable = "SENTINEL_HOOK_RESIDENT_DIR";

    /// <summary>The environment variable that sets the answer budget in milliseconds.</summary>
    public const string BudgetVariable = "SENTINEL_HOOK_RESIDENT_BUDGET_MS";

    /// <summary>The process exits after this long without a request.</summary>
    public static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromMinutes(30);

    /// <summary>A hook waits this long for the answer, so the whole decision stays within the 50 ms of ADR-007.</summary>
    public static readonly TimeSpan DefaultBudget = TimeSpan.FromMilliseconds(15);

    /// <summary>The settings, or <see langword="null"/> when the resident process is not turned on.</summary>
    public static ResidentSettings? FromEnvironment(IReadOnlyDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (HookConfig.ParseSwitch(env, EnableVariable) != true)
        {
            return null;
        }

        var budget = DefaultBudget;
        if (env.TryGetValue(BudgetVariable, out var text)
            && int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var millis) && millis > 0)
        {
            budget = TimeSpan.FromMilliseconds(millis);
        }

        return new ResidentSettings(DefaultDirectory(env), DefaultIdleTimeout, budget);
    }

    /// <summary>The <c>SENTINEL_HOOK_</c> variables of this process, as the hook CLIs read them.</summary>
    public static Dictionary<string, string?> ProcessEnvironment()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key && key.StartsWith("SENTINEL_HOOK_", StringComparison.Ordinal))
            {
                env[key] = entry.Value as string;
            }
        }

        return env;
    }

    private static string DefaultDirectory(IReadOnlyDictionary<string, string?> env)
    {
        if (env.TryGetValue(DirectoryVariable, out var configured) && !string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(baseDir))
        {
            baseDir = Path.Combine(Path.GetTempPath(), "ai-sentinel-" + Environment.UserName);
        }

        return Path.Combine(baseDir, "ai-sentinel", "resident");
    }
}

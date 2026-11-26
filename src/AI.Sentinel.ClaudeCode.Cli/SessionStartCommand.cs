using System.Text;
using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Repository;

namespace AI.Sentinel.ClaudeCode.Cli;

/// <summary>
/// <c>sentinel-hook session-start</c>: tells the developer, once per session, when the repository they work in is in strict repository
/// mode, so they know only the organisation's top-level rules apply and no events are sent (#656). It prints nothing, and exits 0,
/// when the repository is owned by a node or no node map is cached, so a PC without a server sees no change.
/// </summary>
internal static class SessionStartCommand
{
    /// <summary>The argument that selects this command.</summary>
    public const string Verb = "session-start";

    public static bool Matches(string[] args) => args.Length >= 1 && string.Equals(args[0], Verb, StringComparison.Ordinal);

    /// <param name="env">The <c>SENTINEL_HOOK_</c> settings.</param>
    /// <param name="workingDirectory">Where the session starts.</param>
    /// <param name="stdout">Receives the hook output of Claude Code.</param>
    /// <param name="stderr">Receives the reason when the node map cannot be read.</param>
    public static async Task<int> RunAsync(IReadOnlyDictionary<string, string?> env, string workingDirectory, TextWriter stdout, TextWriter stderr)
    {
        string? notice;
        try
        {
            notice = RepositoryPolicy.Open(env, workingDirectory)?.Scope.Notice();
        }
        catch (InvalidDataException e)
        {
            // A broken cache is reported; the tool calls themselves fail closed when they read it.
            await stderr.WriteLineAsync($"[sentinel-hook] {e.Message}").ConfigureAwait(false);
            return 1;
        }

        if (notice is not null)
        {
            await stdout.WriteLineAsync(Output(notice)).ConfigureAwait(false);
        }

        return 0;
    }

    // The message is shown to the developer, and the context lets the model explain a denial it meets in this session.
    private static string Output(string notice)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("systemMessage", notice);
            writer.WriteStartObject("hookSpecificOutput");
            writer.WriteString("hookEventName", "SessionStart");
            writer.WriteString("additionalContext", notice);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }
}

using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The event names of the stream, and its path below the server's session control prefix.</summary>
internal static class SessionEventNames
{
    public const string Snapshot = "snapshot";
    public const string Pause = "pause";
    public const string Release = "release";
    public const string Configuration = "configuration";

    /// <summary>The default path of the event stream, as <c>MapAISentinelSessionControl</c> maps it.</summary>
    public const string StreamPath = "/ai-sentinel/sessions/events";
}

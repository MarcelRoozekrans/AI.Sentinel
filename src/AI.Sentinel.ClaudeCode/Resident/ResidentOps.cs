using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The operations of the local channel.</summary>
internal static class ResidentOps
{
    public const string Ping = "ping";
    public const string Shutdown = "shutdown";
}

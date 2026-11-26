namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Why <see cref="ResidentHost.RunAsync"/> returned.</summary>
internal enum ResidentExit
{
    /// <summary>No request came for the idle timeout.</summary>
    Idle,

    /// <summary>A client asked the process to stop.</summary>
    Shutdown,

    /// <summary>The caller cancelled it.</summary>
    Cancelled,

    /// <summary>Another process of this user holds the single-instance lock.</summary>
    AlreadyRunning,

    /// <summary>The process could not listen; the hook evaluates in-process.</summary>
    Failed,
}

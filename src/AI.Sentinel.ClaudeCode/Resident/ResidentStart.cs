namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>What <see cref="ResidentLauncher.EnsureStarted"/> found and did.</summary>
internal enum ResidentStart
{
    /// <summary>A process was started; it is not listening yet.</summary>
    Started,

    /// <summary>A process of this user holds the lock, so none was started.</summary>
    AlreadyRunning,

    /// <summary>No process runs and none could be started.</summary>
    Failed,
}

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>What <see cref="ProcessGroup.Detach(Func{ValueTuple{int, int}}, bool)"/> did.</summary>
internal enum ProcessGroupResult
{
    /// <summary>The process now leads a session and a process group of its own.</summary>
    Detached,

    /// <summary>The process was a group leader already (EPERM), so it cannot start a session and is left as it is.</summary>
    AlreadyLeader,

    /// <summary>The call failed for another reason; the process goes on in its parent's group.</summary>
    Failed,

    /// <summary>Windows: nothing to do, see <see cref="ProcessGroup"/>.</summary>
    NotApplicable,
}

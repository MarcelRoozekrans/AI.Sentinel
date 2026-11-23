using System.Runtime.InteropServices;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// Takes the resident process out of the process group and the session of the hook that started it, so a CLI that kills the group of
/// a hook, for example on a timeout, does not kill it. The calls are libc's <c>setsid</c> and <c>getsid</c>, bound at build time with
/// <c>LibraryImport</c>, so they are safe under Native AOT.
/// </summary>
/// <remarks>
/// Windows: nothing is done. A process started with <c>Process.Start</c> belongs to the job of its parent only when the parent runs
/// in one, and then the job's own limits decide whether it dies with it; .NET cannot ask for <c>CREATE_BREAKAWAY_FROM_JOB</c>, so
/// a hook under a job that kills its members takes the resident process with it. The next hook starts a new one.
/// </remarks>
internal static partial class ProcessGroup
{
    private const int Eperm = 1;

    [LibraryImport("libc", EntryPoint = "setsid", SetLastError = true)]
    private static partial int SetSid();

    [LibraryImport("libc", EntryPoint = "getsid", SetLastError = true)]
    private static partial int GetSid(int pid);

    /// <summary>Starts a session of our own with <c>setsid</c>. An EPERM, the process being a group leader already, is ignored.</summary>
    public static ProcessGroupResult Detach() =>
        Detach(() => (SetSid(), Marshal.GetLastPInvokeError()));

    /// <summary>As <see cref="Detach()"/>, with the call and the platform given, for a test.</summary>
    /// <param name="setsid">Returns the result of <c>setsid</c> and the error number.</param>
    /// <param name="isWindows">True where there is no <c>setsid</c>; <see cref="OperatingSystem.IsWindows"/> by default.</param>
    public static ProcessGroupResult Detach(Func<(int Result, int Errno)> setsid, bool? isWindows = null)
    {
        ArgumentNullException.ThrowIfNull(setsid);
        if (isWindows ?? OperatingSystem.IsWindows())
        {
            return ProcessGroupResult.NotApplicable;
        }

        try
        {
            var (result, errno) = setsid();
            if (result != -1)
            {
                return ProcessGroupResult.Detached;
            }

            return errno == Eperm ? ProcessGroupResult.AlreadyLeader : ProcessGroupResult.Failed;
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            return ProcessGroupResult.Failed;
        }
    }

    /// <summary>The session id of process <paramref name="pid"/>, or 0 for this process; -1 when it cannot be read.</summary>
    public static int SessionOf(int pid) => OperatingSystem.IsWindows() ? -1 : GetSid(pid);
}

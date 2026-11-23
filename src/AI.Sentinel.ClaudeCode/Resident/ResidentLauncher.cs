using System.ComponentModel;
using System.Diagnostics;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Starts the resident process detached, once. The decision of the hook that starts it does not wait for it.</summary>
internal static class ResidentLauncher
{
    /// <summary>Starts the process unless one holds the single-instance lock. The check and the start are not atomic: two hooks can
    /// both start one, and the lock makes the second exit at once.</summary>
    /// <param name="settings">The settings.</param>
    /// <param name="launch">What to start.</param>
    /// <param name="start">Starts it; <see cref="StartDetached"/> by default.</param>
    public static ResidentStart EnsureStarted(ResidentSettings settings, ResidentLaunch launch, Func<ResidentLaunch, bool>? start = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(launch);
        try
        {
            ResidentPaths.Prepare(settings);
            if (IsRunning(settings))
            {
                return ResidentStart.AlreadyRunning;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return ResidentStart.Unusable;
        }

        return (start ?? StartDetached)(launch) ? ResidentStart.Started : ResidentStart.Failed;
    }

    /// <summary>True when another process holds the single-instance lock.</summary>
    public static bool IsRunning(ResidentSettings settings)
    {
        try
        {
            using var probe = new FileStream(ResidentPaths.Lock(settings), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
    }

    /// <summary>Starts the process so that it outlives this one. Its standard streams are redirected and closed here, not
    /// inherited: the stdout of a hook is its answer to the CLI, and a child that held it open would keep the CLI waiting.</summary>
    public static bool StartDetached(ResidentLaunch launch)
    {
        ArgumentNullException.ThrowIfNull(launch);
        var psi = new ProcessStartInfo(launch.FileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in launch.Arguments)
        {
            psi.ArgumentList.Add(argument);
        }

        try
        {
            using var process = Process.Start(psi);
            if (process is null)
            {
                return false;
            }

            process.StandardInput.Close();
            return true;
        }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or IOException)
        {
            return false;
        }
    }
}

using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Where the resident process keeps its files. The folder is private to the user, as the policy cache is, so no other user
/// can connect to the socket, read the state or change it.</summary>
internal static class ResidentPaths
{
    /// <summary>The longest path a Unix domain socket can bind to: the sockaddr_un limit, less the terminator.</summary>
    private const int MaxSocketPath = 100;

    /// <summary>The state folder, created private when it is missing. When the configured folder exists and is open to others the
    /// private sibling is used instead, see <see cref="PolicyCache.Prepare"/>, so the hook and the process agree on one folder.</summary>
    public static string Prepare(ResidentSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return PolicyCache.Prepare(settings.StateDirectory);
    }

    /// <summary>The state folder as <see cref="Prepare"/> chose it, without creating anything.</summary>
    public static string Directory(ResidentSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var sibling = Path.TrimEndingDirectorySeparator(settings.StateDirectory) + ".private";
        return System.IO.Directory.Exists(sibling) ? sibling : settings.StateDirectory;
    }

    public static string Socket(ResidentSettings settings) => Path.Combine(Directory(settings), "resident.sock");

    public static string Lock(ResidentSettings settings) => Path.Combine(Directory(settings), "resident.lock");

    public static string Pid(ResidentSettings settings) => Path.Combine(Directory(settings), "resident.pid");

    /// <summary>Why a socket cannot be bound at <paramref name="socketPath"/>, or <see langword="null"/>.</summary>
    public static string? SocketPathProblem(string socketPath) =>
        socketPath.Length > MaxSocketPath
            ? $"the socket path '{socketPath}' is longer than {MaxSocketPath} characters; set {ResidentSettings.DirectoryVariable} to a shorter folder"
            : null;
}

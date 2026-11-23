using System.Text;
using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The files the resident process keeps in its private state folder: the pause state and the signed profile cache. A hook reads them
/// from disk, so it needs no network and no running process. A file is written whole under a temporary name and then moved onto its
/// name, with its digest in front, as <see cref="PolicyCache"/> does it, so a reader sees the old file or the new one and never half
/// of one; a file that is missing or fails its digest reads as absent.
/// </summary>
internal sealed class ResidentState(string directory)
{
    /// <summary>The file that holds the paused sessions.</summary>
    public const string PauseFile = "pause.json";

    /// <summary>The file that holds the last valid signed profile.</summary>
    public const string ProfileFile = "profile.json";

    /// <summary>The file that holds the map of repositories to the nodes that own them (#656).</summary>
    public const string NodesFile = "nodes.json";

    /// <summary>The state folder, as <see cref="ResidentPaths.Prepare"/> returned it.</summary>
    public string Directory { get; } = directory;

    /// <summary>The state of the folder <paramref name="settings"/> names, created private when it is missing.</summary>
    public static ResidentState Open(ResidentSettings settings) => new(ResidentPaths.Prepare(settings));

    /// <summary>Replaces the paused sessions with <paramref name="pauses"/>; an empty list lifts every pause.</summary>
    public void WritePauses(IReadOnlyList<PausedSession> pauses)
    {
        ArgumentNullException.ThrowIfNull(pauses);
        PolicyCache.Write(Path.Combine(Directory, PauseFile), JsonSerializer.SerializeToUtf8Bytes(pauses.ToArray(), ResidentStateJsonContext.Default.PausedSessionArray));
    }

    /// <summary>The paused sessions; none when the file does not exist.</summary>
    /// <exception cref="InvalidDataException">The file exists and cannot be read, fails its digest or does not parse. That must not
    /// read as "nobody is paused", which would fail open, so the hook blocks the call as an internal error (#478).</exception>
    public IReadOnlyList<PausedSession> ReadPauses()
    {
        var path = Path.Combine(Directory, PauseFile);
        try
        {
            // Absence is told by the read itself: File.Exists says false for a file it cannot get at, which would read as nobody paused.
            var bytes = PolicyCache.TryRead(path);
            if (bytes is null)
            {
                // TryRead says absent for a missing file, and for one that is short or fails its digest.
                return IsMissing(path) ? [] : throw new InvalidDataException("fails its digest");
            }

            return JsonSerializer.Deserialize(bytes, ResidentStateJsonContext.Default.PausedSessionArray)?.Where(p => p?.Session is not null).ToArray()
                ?? throw new InvalidDataException("holds no list");
        }
        catch (Exception e) when (e is InvalidDataException or JsonException or IOException or UnauthorizedAccessException)
        {
            throw new InvalidDataException($"the pause state is unreadable ({e.Message}); every session is treated as paused until it is rewritten", e);
        }
    }

    // Opening is what separates a file that is not there from one that is there and cannot be read: the second throws
    // UnauthorizedAccessException or IOException, which the caller turns into an error.
    private static bool IsMissing(string path)
    {
        try
        {
            using var _ = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return false;
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return true;
        }
    }

    /// <summary>The pause that names <paramref name="session"/> and has not ended at <paramref name="now"/>, or <see langword="null"/>.</summary>
    /// <exception cref="InvalidDataException">The pause state is unreadable, see <see cref="ReadPauses"/>.</exception>
    public PausedSession? FindPause(string session, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(session);
        return ReadPauses().FirstOrDefault(p => string.Equals(p.Session, session, StringComparison.Ordinal) && (p.Until is null || now < p.Until));
    }

    /// <summary>Caches <paramref name="signed"/> when <see cref="ProfileVerifier"/> accepts it, and only then: a profile that fails the
    /// check leaves the last valid one in place.</summary>
    public ProfileVerification StoreProfile(SignedProfile signed, PinnedProfileKeys pinned, string organisation, string repository, DateTimeOffset now, string? slot = null)
    {
        var verification = ProfileVerifier.Verify(signed, pinned, organisation, repository, now);
        if (verification.IsAccepted)
        {
            PolicyCache.Write(Path.Combine(Directory, ProfileFileOf(slot)), Encoding.UTF8.GetBytes(signed.ToJson()));
        }

        return verification;
    }

    /// <summary>The cached profile, checked again as a profile from the server is: a cache that fails the check is not used, and one
    /// that passes is used offline until it expires. <see langword="null"/> when nothing is cached.</summary>
    public ProfileVerification? ReadProfile(PinnedProfileKeys pinned, string organisation, string repository, DateTimeOffset now, string? slot = null)
    {
        if (PolicyCache.TryRead(Path.Combine(Directory, ProfileFileOf(slot))) is not { } bytes)
        {
            return null;
        }

        return SignedProfile.Parse(Encoding.UTF8.GetString(bytes)) is { } signed
            ? ProfileVerifier.Verify(signed, pinned, organisation, repository, now)
            : ProfileVerification.Rejected(ProfileRejection.Malformed);
    }

    /// <summary>The cache file of a profile: the one profile of the state folder, or the one of <paramref name="slot"/>, which keeps a
    /// profile per repository.</summary>
    private static string ProfileFileOf(string? slot) => slot is null ? ProfileFile : $"profile-{slot}.json";

    /// <summary>Caches the node map, whole, for a hook to read.</summary>
    public void WriteNodeMap(NodeMap map)
    {
        ArgumentNullException.ThrowIfNull(map);
        PolicyCache.Write(Path.Combine(Directory, NodesFile), map.ToJson());
    }

    /// <summary>The cached node map; <see langword="null"/> when none is cached.</summary>
    /// <exception cref="InvalidDataException">A map is cached and cannot be read. That must not read as "no node owns anything", which
    /// would loosen the policy of every repository, so the hook blocks the call as an internal error.</exception>
    public NodeMap? ReadNodeMap()
    {
        var path = Path.Combine(Directory, NodesFile);
        try
        {
            // Read, not probed: File.Exists is false for a directory and for a path it cannot stat, which must not read as no map.
            return PolicyCache.ReadFile(path) is { } bytes
                ? NodeMap.FromJson(PolicyCache.Verify(bytes) ?? throw new InvalidDataException("fails its digest"))
                : null;
        }
        catch (Exception e) when (e is InvalidDataException or JsonException or IOException or UnauthorizedAccessException)
        {
            throw new InvalidDataException($"the node map is unreadable ({e.Message})", e);
        }
    }
}

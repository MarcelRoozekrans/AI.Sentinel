using System.Text;
using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Rego;
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

    /// <summary>The paused sessions; none when the file is missing or damaged.</summary>
    public IReadOnlyList<PausedSession> ReadPauses()
    {
        if (PolicyCache.TryRead(Path.Combine(Directory, PauseFile)) is not { } bytes)
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize(bytes, ResidentStateJsonContext.Default.PausedSessionArray)?.Where(p => p?.Session is not null).ToArray() ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>The pause that names <paramref name="session"/> and has not ended at <paramref name="now"/>, or <see langword="null"/>.</summary>
    public PausedSession? FindPause(string session, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(session);
        return ReadPauses().FirstOrDefault(p => string.Equals(p.Session, session, StringComparison.Ordinal) && (p.Until is null || now < p.Until));
    }

    /// <summary>Caches <paramref name="signed"/> when <see cref="ProfileVerifier"/> accepts it, and only then: a profile that fails the
    /// check leaves the last valid one in place.</summary>
    public ProfileVerification StoreProfile(SignedProfile signed, PinnedProfileKeys pinned, string organisation, string repository, DateTimeOffset now)
    {
        var verification = ProfileVerifier.Verify(signed, pinned, organisation, repository, now);
        if (verification.IsAccepted)
        {
            PolicyCache.Write(Path.Combine(Directory, ProfileFile), Encoding.UTF8.GetBytes(signed.ToJson()));
        }

        return verification;
    }

    /// <summary>The cached profile, checked again as a profile from the server is: a cache that fails the check is not used, and one
    /// that passes is used offline until it expires. <see langword="null"/> when nothing is cached.</summary>
    public ProfileVerification? ReadProfile(PinnedProfileKeys pinned, string organisation, string repository, DateTimeOffset now)
    {
        if (PolicyCache.TryRead(Path.Combine(Directory, ProfileFile)) is not { } bytes)
        {
            return null;
        }

        return SignedProfile.Parse(Encoding.UTF8.GetString(bytes)) is { } signed
            ? ProfileVerifier.Verify(signed, pinned, organisation, repository, now)
            : ProfileVerification.Rejected(ProfileRejection.Malformed);
    }
}

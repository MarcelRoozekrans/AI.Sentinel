using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.AspNetCore.SessionControl;

/// <summary>A pause in force and the repository whose node decides who may lift it. The repository stays on the server: the event
/// stream carries the pause only, which names a session and no person.</summary>
internal sealed record HeldPause(PausedSession Pause, string Repository);

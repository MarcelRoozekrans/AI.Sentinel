namespace AI.Sentinel.Copilot;

public enum CopilotHookEvent
{
    UserPromptSubmitted,
    PreToolUse,
    PostToolUse,

    /// <summary>The prompt after Copilot has transformed it, before the model receives it. Experimental: the hook can
    /// rewrite it through <c>modifiedTransformedPrompt</c>, which the Copilot reference lists, but command-hook support
    /// awaits a live check with the Copilot CLI.</summary>
    UserPromptTransformed,
}

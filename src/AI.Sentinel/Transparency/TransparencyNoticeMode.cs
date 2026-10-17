namespace AI.Sentinel.Transparency;

/// <summary>When the human-readable AI disclosure notice is added to a reply.</summary>
public enum TransparencyNoticeMode
{
    /// <summary>Add the notice to the first reply of each conversation (session). The default.</summary>
    OncePerConversation,

    /// <summary>Add the notice to every reply.</summary>
    EveryReply,

    /// <summary>Never add the notice. Use when the application's own UI already discloses the AI.</summary>
    Never,
}

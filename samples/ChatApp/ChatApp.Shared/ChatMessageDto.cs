namespace ChatApp.Shared;

/// <summary>Simple message DTO shared between client and server over SignalR.</summary>
/// <param name="Role">"user" or "assistant"</param>
/// <param name="Text">Message text</param>
public record ChatMessageDto(string Role, string Text);

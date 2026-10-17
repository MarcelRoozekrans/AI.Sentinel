using Microsoft.Extensions.AI;

namespace AI.Sentinel;

/// <summary>
/// Tells where a new message starts in a stream, the way <c>ToChatResponse</c> groups updates: a new message
/// starts when a non-empty message id or author name differs from the current message's, or when a role is
/// given that differs from the current message's role, which is assistant until one is given. Empty ids and
/// authors and a missing role continue the current message; a non-empty value is adopted by it.
/// Feed it every update of a stream in order.
/// </summary>
internal sealed class StreamMessageBoundaries
{
    private bool _started;
    private string? _id;
    private string? _author;
    private ChatRole _role;

    /// <summary>The role of the message the last update fed to <see cref="StartsNewMessage"/> belongs to.</summary>
    public ChatRole Role => _role;

    public bool StartsNewMessage(ChatResponseUpdate update)
    {
        var isNew = !_started
            || Differs(update.MessageId, _id)
            || Differs(update.AuthorName, _author)
            || (update.Role is { } role && role != _role);
        if (isNew)
        {
            _started = true;
            _id = null;
            _author = null;
            _role = ChatRole.Assistant;
        }

        if (!string.IsNullOrEmpty(update.MessageId))
        {
            _id = update.MessageId;
        }
        if (!string.IsNullOrEmpty(update.AuthorName))
        {
            _author = update.AuthorName;
        }
        if (update.Role is { } given)
        {
            _role = given;
        }
        return isNew;
    }

    private static bool Differs(string? value, string? current) =>
        !string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(current) && !string.Equals(value, current, StringComparison.Ordinal);
}

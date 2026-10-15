namespace AI.Sentinel.Redaction;

/// <summary>
/// A tool invoked during a redacted request threw. Only <see cref="Exception.Message"/> is redacted: it is the
/// tool's message with sensitive values replaced by placeholders, because a function-invoking client can send
/// it to the model or rethrow it to the caller. <see cref="Exception.InnerException"/> is the original exception
/// and keeps the real values for the application, so <see cref="Exception.ToString"/>, which includes it, and
/// any log that writes the whole exception, can contain them.
/// </summary>
public sealed class RedactedToolInvocationException : Exception
{
    /// <summary>Creates the exception with a default message.</summary>
    public RedactedToolInvocationException()
    {
    }

    /// <summary>Creates the exception with an already redacted message.</summary>
    /// <param name="redactedMessage">The tool's message with values replaced by placeholders.</param>
    public RedactedToolInvocationException(string redactedMessage)
        : base(redactedMessage)
    {
    }

    /// <summary>Creates the exception with an already redacted message.</summary>
    /// <param name="redactedMessage">The tool's message with values replaced by placeholders.</param>
    /// <param name="inner">The exception the tool threw.</param>
    public RedactedToolInvocationException(string redactedMessage, Exception inner)
        : base(redactedMessage, inner)
    {
    }
}

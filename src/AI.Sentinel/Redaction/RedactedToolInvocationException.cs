namespace AI.Sentinel.Redaction;

/// <summary>
/// A tool invoked during a redacted request threw. <see cref="Exception.Message"/> is the tool's message with
/// sensitive values replaced by placeholders, because it can reach the model or a log; the original exception,
/// which may hold the values, is the <see cref="Exception.InnerException"/>.
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

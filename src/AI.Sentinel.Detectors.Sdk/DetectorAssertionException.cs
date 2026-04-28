namespace AI.Sentinel.Detectors.Sdk;

/// <summary>
/// Thrown by <see cref="DetectorTestBuilder"/> assertion terminals when a detector's behavior
/// does not match the expected severity. Test-framework-neutral — xUnit, NUnit, and MSTest all
/// surface plain exception messages as test failures.
/// </summary>
public sealed class DetectorAssertionException : Exception
{
    public DetectorAssertionException() { }
    public DetectorAssertionException(string message) : base(message) { }
    public DetectorAssertionException(string message, Exception innerException) : base(message, innerException) { }
}

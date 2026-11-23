namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>What the developer is shown to approve a sign-in.</summary>
/// <param name="DeviceCode">Kept by the client; it is never shown.</param>
/// <param name="UserCode">The code the developer types at <paramref name="VerificationUri"/>.</param>
/// <param name="VerificationUri">Where to go.</param>
/// <param name="VerificationUriComplete">The address with the code in it, when the provider offers one.</param>
/// <param name="ExpiresAt">When the device code runs out.</param>
/// <param name="Interval">The first wait between polls.</param>
internal sealed record DeviceAuthorization(
    string DeviceCode, string UserCode, Uri VerificationUri, Uri? VerificationUriComplete, DateTimeOffset ExpiresAt, TimeSpan Interval)
{
    public override string ToString() => $"DeviceAuthorization {UserCode}";
}

using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Detectors.Security;

// FindSpans runs on every string sent to the model, so adversarial input must not make it superlinear. These
// tests time the detectors, so they run on their own: other tests running in parallel on a small CI runner
// slow the two measurements unevenly and make the ratio meaningless.
[Collection("NonParallel")]
public class SpanDetectorLinearityTests
{
    [Theory]
    [InlineData("a-")]
    [InlineData("a.")]
    [InlineData("a+")]
    public void PiiLeakage_LongInputWithoutAt_StaysLinear(string unit)
    {
        var detector = new PiiLeakageDetector();
        LinearTime.Assert(
            chars => string.Concat(Enumerable.Repeat(unit, chars / unit.Length)),
            text => detector.FindSpans(text),
            n: 25_000);
    }

    // A keyword followed by a long run of whitespace, with or without a separator in it, and no value.
    [Theory]
    [InlineData("BSN", "")]
    [InlineData("burgerservicenummer", "")]
    [InlineData("passport", "")]
    [InlineData("Steuer-ID", "")]
    [InlineData("tax id", "")]
    [InlineData("born", "")]
    [InlineData("DOB", "")]
    [InlineData("date of birth", "")]
    [InlineData("BSN", ":")]
    [InlineData("\"date_of_birth\"", "=")]
    public void PiiLeakage_KeywordThenLongWhitespace_StaysLinear(string keyword, string separator)
    {
        var detector = new PiiLeakageDetector();
        LinearTime.Assert(
            chars => keyword + new string(' ', chars / 2) + separator + new string(' ', chars / 2),
            text => detector.FindSpans(text),
            n: 10_000);
    }

    [Theory]
    [InlineData("password=")]
    [InlineData("password=\"")]
    [InlineData("password=\"\\")]
    [InlineData("password=\"a\\\"b")]
    [InlineData("password='a ")]
    [InlineData("password=\"a\n")]
    [InlineData("password=\"a\\\n")]
    [InlineData("\"password\": \"a\nb\"x")]
    [InlineData("api_key=\"x\",")]
    [InlineData("-----BEGIN PRIVATE KEY-----")]
    [InlineData("sk-")]
    [InlineData("Authorization: Bearer ")]
    [InlineData("client_secret=")]
    [InlineData("A_TOKEN=")]
    [InlineData("access_token: ")]
    [InlineData("password=\\\"a")]
    [InlineData("password=\\\"a\\\\")]
    [InlineData("password=a\\")]
    [InlineData("x_secret=\\\"")]
    [InlineData("\\\"password\\\": a\\\"")]
    [InlineData("password=a\"")]
    [InlineData("password=a\"b")]
    [InlineData("password=\\\"a\\\\\\\"")]
    [InlineData("ClientSecret: $")]
    [InlineData("secret=<a")]
    public void CredentialExposure_LongAdversarialInput_StaysLinear(string unit)
    {
        var detector = new CredentialExposureDetector();
        LinearTime.Assert(
            chars => string.Concat(Enumerable.Repeat(unit, chars / unit.Length)),
            text => detector.FindSpans(text),
            n: 25_000);
    }

    // An unclosed $( or ${{ after a key: the reference check must not scan the rest of the line for every key. The
    // cost per key is small, so the input has to be long before a quadratic scan stands out from the slack.
    [Theory]
    [InlineData("password=$( ")]
    [InlineData("password=${{ ")]
    [InlineData("\\\"password\\\": \\\"${{ ")]
    public void CredentialExposure_UnclosedReferenceAfterManyKeys_StaysLinear(string unit)
    {
        var detector = new CredentialExposureDetector();
        LinearTime.Assert(
            chars => string.Concat(Enumerable.Repeat(unit, chars / unit.Length)),
            text => detector.FindSpans(text),
            n: 200_000);
    }
}

using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class PlaceholderFormatTests
{
    [Fact]
    public void Normalise_ReplacesTagAndCounter() =>
        Assert.Equal("mail [EMAIL] now", PlaceholderFormat.Normalise("mail [EMAIL_1_k3f9x2] now"));

    [Fact]
    public void Normalise_MultiPartType_KeepsTheWholeType() =>
        Assert.Equal("[API_KEY] and [IBAN_NL]", PlaceholderFormat.Normalise("[API_KEY_2_k3f9x2] and [IBAN_NL_10_ab12cd]"));

    /// <summary>Normalisation goes by shape, not by the placeholders this process minted.</summary>
    [Fact]
    public void Normalise_UnmintedPlaceholderShape_IsNormalisedToo() =>
        Assert.Equal("[PHONE]", PlaceholderFormat.Normalise("[PHONE_3_zz9y8x]"));

    [Fact]
    public void Normalise_NonPlaceholderBrackets_AreKept()
    {
        const string text = "[draft] [EMAIL_1]";
        Assert.Equal(text, PlaceholderFormat.Normalise(text));
    }

    [Fact]
    public void Normalise_TextWithoutBracket_IsReturnedAsIs()
    {
        const string text = "no placeholder here";
        Assert.Same(text, PlaceholderFormat.Normalise(text));
    }
}

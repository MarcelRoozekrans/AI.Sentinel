using System.Text;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.SignIn;

/// <summary>A pinned-keys file that is damaged reads as no pins, and with no pinned key every profile is refused.</summary>
public sealed class PinnedKeysFileTests : IDisposable
{
    private readonly string _dir = ResidentTestSupport.NewDir();

    public void Dispose() => ResidentTestSupport.Delete(_dir);

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"Organisation":"acme","Keys":["%%% not base64 %%%"]}""")]
    [InlineData("""{"Organisation":"","Keys":[]}""")]
    [InlineData("""{"Organisation":"acme"}""")]
    public void A_pinned_keys_file_that_cannot_be_used_reads_as_no_pins(string content)
    {
        var state = new ResidentState(Directory.CreateDirectory(_dir).FullName);
        PolicyCache.Write(Path.Combine(_dir, ResidentState.PinnedKeysFile), Encoding.UTF8.GetBytes(content));

        Assert.Null(state.ReadPinnedKeys());
    }

    [Fact]
    public void A_pinned_keys_path_that_cannot_be_read_as_a_file_reads_as_no_pins()
    {
        var state = new ResidentState(Directory.CreateDirectory(_dir).FullName);
        Directory.CreateDirectory(Path.Combine(_dir, ResidentState.PinnedKeysFile));

        Assert.Null(state.ReadPinnedKeys());
    }
}

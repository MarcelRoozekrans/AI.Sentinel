using System.Text;
using AI.Sentinel.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

public sealed class ResidentHardeningTests : IDisposable
{
    private readonly string _dir = ResidentTestSupport.NewDir();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => ResidentTestSupport.Delete(_dir);

    private ResidentState State() => new(ResidentPaths.Prepare(new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));

    private static ResidentRequest Evaluation() =>
        new() { Op = ResidentOps.Evaluate, Folder = "/nowhere", Version = "v", CacheDirectory = "/nowhere", Input = "{}", Session = "s-1" };

    [Fact]
    public void An_unreadable_pause_file_denies_every_resident_evaluation_until_a_snapshot_replaces_it()
    {
        var state = State();
        File.WriteAllText(Path.Combine(state.Directory, ResidentState.PauseFile), "not a pause file");
        var board = new PauseBoard(state);
        using var service = new ResidentService(null, null, board);

        var denied = service.Answer(Evaluation());
        board.Replace([]);
        var afterSnapshot = service.Answer(Evaluation());

        Assert.True(denied.Ok);
        Assert.Equal("deny", denied.Outcome);
        Assert.True(board.Unreadable is false);
        Assert.False(afterSnapshot.Ok);
    }

    [Fact]
    public void A_missing_pause_file_is_not_unreadable()
    {
        Assert.False(new PauseBoard(State()).Unreadable);
    }

    [Fact]
    public async Task A_line_that_passes_the_limit_is_refused_whatever_field_it_belongs_to()
    {
        var huge = ": " + new string('x', SseReader.MaxLineChars + 10) + "\n\n";
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(huge));

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
        {
            await foreach (var _ in SseReader.ReadAsync(stream, TimeSpan.FromSeconds(10), Ct))
            {
            }
        });
    }

    [Fact]
    public async Task Lines_end_at_lf_cr_or_crlf_and_a_split_crlf_is_one_line_end()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("event: a\r\ndata: 1\r\r\nevent: b\ndata: 2\n\n"));
        var messages = new List<SseMessage>();

        await foreach (var message in SseReader.ReadAsync(stream, TimeSpan.FromSeconds(10), Ct))
        {
            messages.Add(message);
        }

        Assert.Equal([("a", "1"), ("b", "2")], messages.Select(m => (m.Event, m.Data)));
    }
}

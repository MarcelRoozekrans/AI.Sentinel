using System.Text;
using System.Text.Json;
using AI.Sentinel.AspNetCore.Events;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore.Events;

public sealed class EventsUnitTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<int> ReadAsync(Stream stream, int count) => await stream.ReadAsync(new byte[count].AsMemory(), Ct);

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static string EventJson(string extra = "") => "{\"event_id\":\"e1\",\"tool_kind\":\"shell\",\"outcome\":\"deny\"" + extra + "}";

    private static ParsedBatch? ReadEvents(string events) => EventBatchReader.Read(Json("{\"organisation\":\"acme\",\"events\":[" + events + "]}"));

    [Fact]
    public void LimitedStream_ReadsWithinLimitAndExposesStreamShape()
    {
        using var stream = new LimitedStream(new MemoryStream(new byte[10]), 10);
        var buffer = new byte[10];
        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Equal(10, stream.Read(buffer, 0, 10));
        stream.Flush();
    }

    [Fact]
    public void LimitedStream_RefusesToReadPastTheLimit_Sync()
    {
        using var stream = new LimitedStream(new MemoryStream(new byte[11]), 10);
        Assert.Throws<InvalidDataException>(() => stream.Read(new byte[11], 0, 11));
    }

    [Fact]
    public async Task LimitedStream_RefusesToReadPastTheLimit_Async()
    {
        await using var stream = new LimitedStream(new MemoryStream(new byte[11]), 10);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await ReadAsync(stream, 11));
    }

    [Fact]
    public async Task LimitedStream_CountsAcrossReads()
    {
        await using var stream = new LimitedStream(new MemoryStream(new byte[12]), 10);
        Assert.Equal(6, await ReadAsync(stream, 6));
        await Assert.ThrowsAsync<InvalidDataException>(async () => await ReadAsync(stream, 6));
    }

    [Fact]
    public void LimitedStream_RefusesSeekingAndWriting()
    {
        using var stream = new LimitedStream(new MemoryStream(), 10);
        Assert.Throws<NotSupportedException>(() => stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
        Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
    }

    [Fact]
    public void Reader_RefusesARootThatIsNotAnObject() => Assert.Null(EventBatchReader.Read(Json("[]")));

    [Fact]
    public void Reader_RefusesABatchWithoutOrganisation() =>
        Assert.Null(EventBatchReader.Read(Json("{\"events\":[]}")));

    [Fact]
    public void Reader_RefusesTooManyEvents()
    {
        var many = string.Join(',', Enumerable.Repeat("{}", EventBatchReader.MaxEvents + 1));
        Assert.Null(ReadEvents(many));
    }

    [Fact]
    public void Reader_CountsUnknownTopLevelFieldsWithoutKeepingThem()
    {
        var batch = EventBatchReader.Read(Json("{\"organisation\":\"acme\",\"events\":[],\"command\":\"rm -rf\"}"));
        Assert.NotNull(batch);
        Assert.Equal(1, batch.Dropped["command"]);
    }

    [Fact]
    public void Reader_RejectsAnEventThatIsNotAnObject()
    {
        var batch = ReadEvents("42");
        Assert.NotNull(batch);
        Assert.Empty(batch.Events);
        Assert.Equal(1, batch.Rejected);
    }

    [Theory]
    [InlineData(",\"policies\":\"p\"")]
    [InlineData(",\"policies\":[1]")]
    [InlineData(",\"redactions\":[]")]
    [InlineData(",\"redactions\":{\"email\":-1}")]
    [InlineData(",\"redactions\":{\"email\":\"x\"}")]
    [InlineData(",\"at\":5")]
    [InlineData(",\"node\":\"\"")]
    public void Reader_RejectsAnEventWithAMalformedField(string extra)
    {
        var batch = ReadEvents(EventJson(extra));
        Assert.NotNull(batch);
        Assert.Empty(batch.Events);
        Assert.Equal(1, batch.Rejected);
    }

    [Fact]
    public void Reader_RejectsAPolicyListOverTheItemLimit()
    {
        var policies = string.Join(',', Enumerable.Repeat("\"p\"", EventBatchReader.MaxItems + 1));
        Assert.Equal(1, ReadEvents(EventJson(",\"policies\":[" + policies + "]"))!.Rejected);
    }

    [Fact]
    public void Reader_RejectsTooManyRedactionKindsAndOverlongNames()
    {
        var kinds = string.Join(',', Enumerable.Range(0, EventBatchReader.MaxItems + 1).Select(i => "\"k" + i + "\":1"));
        Assert.Equal(1, ReadEvents(EventJson(",\"redactions\":{" + kinds + "}"))!.Rejected);
        Assert.Equal(1, ReadEvents(EventJson(",\"redactions\":{\"" + new string('k', 65) + "\":1}"))!.Rejected);
    }

    [Fact]
    public void Reader_RejectsAnEventMissingARequiredField()
    {
        Assert.Equal(1, ReadEvents("{\"event_id\":\"e1\",\"tool_kind\":\"shell\"}")!.Rejected);
    }

    [Fact]
    public void Reader_TruncatesLongUnknownFieldNamesAndReadsTheGap()
    {
        var name = new string('x', 100);
        var batch = EventBatchReader.Read(Json("{\"organisation\":\"acme\",\"events\":[" + EventJson(",\"" + name + "\":1") + "],\"gap\":{\"pruned\":3,\"node\":\"n1\",\"other\":1}}"));
        Assert.NotNull(batch);
        Assert.Single(batch.Events);
        Assert.Equal(1, batch.Dropped[new string('x', 64)]);
        Assert.Equal(3, batch.Pruned);
        Assert.Equal("n1", batch.GapNode);
    }

    [Fact]
    public void EventWriter_WritesRedactionCounts()
    {
        var e = new ServerEvent("e1", "acme", "dev-1", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, "shell", "deny", ["p"],
            null, null, null, null, null, null, null, new Dictionary<string, int>(StringComparer.Ordinal) { ["email"] = 2 }, null);
        using var doc = JsonDocument.Parse(EventWriter.Write([e], null));
        Assert.Equal(2, doc.RootElement.GetProperty("events")[0].GetProperty("redactions").GetProperty("email").GetInt32());
    }

    [Fact]
    public async Task Store_ReadsAndPrunesAnOrganisationItNeverSaw()
    {
        var store = new InMemoryServerEventStore();
        await store.PruneAsync("none", DateTimeOffset.MaxValue, DateOnly.MaxValue, Ct);
        Assert.Empty(await store.ReadEventsAsync("none", Ct));
        Assert.Empty(await store.ReadGapsAsync("none", Ct));
        Assert.Empty(await store.ReadDailyCountsAsync("none", Ct));
        Assert.Empty(await store.ReadDroppedAsync("none", Ct));
    }

    [Fact]
    public void PseudonymKeys_RefusesAShortKey() =>
        Assert.Throws<ArgumentException>(() => new PseudonymKeys(Convert.ToBase64String(Encoding.UTF8.GetBytes("short"))));
}

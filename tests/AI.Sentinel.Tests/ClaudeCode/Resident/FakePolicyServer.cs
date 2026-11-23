using System.Net;
using System.Text;
using System.Threading.Channels;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>A server that serves a node map, signed profiles and an event stream the test writes to, and can fail or drop on cue.</summary>
internal sealed class FakePolicyServer : HttpMessageHandler
{
    public const string Organisation = "acme";
    public const string Widgets = "github.com/acme/widgets";

    private readonly Lock _gate = new();
    private readonly ProfileSigner _signer;
    private Channel<byte[]>? _stream;
    private int _failProfiles;
    private int _refuseConnections;
    private int _profileRequests;
    private int _connections;
    private readonly List<DateTimeOffset> _profileTimes = [];

    public FakePolicyServer()
    {
        Key = ProfileSigningKey.Generate();
        _signer = new ProfileSigner(Key);
    }

    public ProfileSigningKey Key { get; }

    public long Version { get; set; } = 1;

    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>The repositories the node map names, besides the organisation's own profile.</summary>
    public List<string> Repositories { get; } = [];

    /// <summary>The module text of the profile of the repository; the organisation profile is <c>*</c>.</summary>
    public Func<string, string> Module { get; set; } = _ => Rule("deny contains \"v" + "1\" if input.kind == \"shell\"");

    /// <summary>How long a profile request takes to answer.</summary>
    public TimeSpan ProfileDelay { get; set; }

    public int ProfileRequests => Volatile.Read(ref _profileRequests);

    public int Connections => Volatile.Read(ref _connections);

    public IReadOnlyList<DateTimeOffset> ProfileTimes
    {
        get
        {
            lock (_gate)
            {
                return [.. _profileTimes];
            }
        }
    }

    public PinnedProfileKeys Pinned => PinnedProfileKeys.FromBase64([Convert.ToBase64String(Key.PublicKey)]);

    public static string Rule(string rule) => $"package sentinel\n\nimport rego.v1\n\n{rule}\n";

    /// <summary>The next <paramref name="count"/> profile requests answer 503.</summary>
    public void FailProfiles(int count) => Volatile.Write(ref _failProfiles, count);

    /// <summary>The next <paramref name="count"/> attempts to open the event stream fail.</summary>
    public void RefuseConnections(int count) => Volatile.Write(ref _refuseConnections, count);

    /// <summary>Writes an event to the open stream.</summary>
    public void Push(string name, string data) => Open()?.Writer.TryWrite(Encoding.UTF8.GetBytes($"event: {name}\ndata: {data}\n\n"));

    /// <summary>Ends the open stream, as a dropped connection does.</summary>
    public void Drop()
    {
        lock (_gate)
        {
            _stream?.Writer.TryComplete();
            _stream = null;
        }
    }

    public SignedProfile Issue(string repository)
    {
        var profile = new PolicyProfile
        {
            Organisation = Organisation,
            Repository = repository,
            Node = repository is "*" ? "acme" : "team-a",
            ConfigurationVersion = Version,
            ModuleHash = "h",
            Module = Module(repository),
            FailMode = "closed",
            SeverityDefaults = new Dictionary<string, string>(StringComparer.Ordinal),
            LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal),
            IssuedAt = default,
            ExpiresAt = default,
        };
        return _signer.Issue(profile, Lifetime);
    }

    private Channel<byte[]>? Open()
    {
        lock (_gate)
        {
            return _stream;
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (ProfileDelay > TimeSpan.Zero && request.RequestUri!.AbsolutePath.EndsWith("/profile", StringComparison.Ordinal))
        {
            await Task.Delay(ProfileDelay, cancellationToken);
        }

        return Answer(request);
    }

    private HttpResponseMessage Answer(HttpRequestMessage request)
    {
        var path = request.RequestUri!.AbsolutePath;
        if (path.EndsWith("/events", StringComparison.Ordinal))
        {
            return OpenStream();
        }

        if (path.EndsWith("/node-map", StringComparison.Ordinal))
        {
            var map = "{" + string.Join(",", Repositories.Select(r => $"\"{r}\":\"team-a\"")) + "}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(map, Encoding.UTF8, "application/json") };
        }

        if (path.EndsWith("/profile", StringComparison.Ordinal))
        {
            var repository = Uri.UnescapeDataString(request.RequestUri.Query.Split("repository=", 2)[1]);
            lock (_gate)
            {
                _profileTimes.Add(DateTimeOffset.UtcNow);
            }

            _ = Interlocked.Increment(ref _profileRequests);
            if (Interlocked.Decrement(ref _failProfiles) >= 0)
            {
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }

            Volatile.Write(ref _failProfiles, 0);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Issue(repository).ToJson(), Encoding.UTF8, "application/json") };
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private HttpResponseMessage OpenStream()
    {
        if (Interlocked.Decrement(ref _refuseConnections) >= 0)
        {
            throw new HttpRequestException("the server is down");
        }

        Volatile.Write(ref _refuseConnections, 0);
        _ = Interlocked.Increment(ref _connections);
        var channel = Channel.CreateUnbounded<byte[]>();
        lock (_gate)
        {
            _stream = channel;
        }

        channel.Writer.TryWrite(Encoding.UTF8.GetBytes($"event: snapshot\ndata: {{\"configuration_version\":{Version},\"pauses\":[]}}\n\n"));
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new ChannelStream(channel.Reader)) };
        response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/event-stream");
        return response;
    }

    private sealed class ChannelStream(ChannelReader<byte[]> reader) : Stream
    {
        private byte[] _left = [];
        private int _at;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (_at >= _left.Length)
            {
                if (!await reader.WaitToReadAsync(cancellationToken))
                {
                    return 0;
                }

                if (reader.TryRead(out var next))
                {
                    _left = next;
                    _at = 0;
                }
            }

            var count = Math.Min(buffer.Length, _left.Length - _at);
            _left.AsMemory(_at, count).CopyTo(buffer);
            _at += count;
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

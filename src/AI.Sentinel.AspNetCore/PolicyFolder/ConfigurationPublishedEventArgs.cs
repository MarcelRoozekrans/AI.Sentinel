namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>A configuration that has come into force.</summary>
internal sealed class ConfigurationPublishedEventArgs(PublishedConfiguration configuration) : EventArgs
{
    public PublishedConfiguration Configuration { get; } = configuration;
}

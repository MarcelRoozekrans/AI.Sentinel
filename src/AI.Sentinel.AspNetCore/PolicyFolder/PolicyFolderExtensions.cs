using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Profiles;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AI.Sentinel.AspNetCore;

/// <summary>Registers and maps the policy folder and the signed profiles served from it. Optional and off by default.</summary>
public static class PolicyFolderExtensions
{
    /// <summary>The path where a plugin fetches the keys to pin, as the sign-in of the hook adapters expects it.</summary>
    public const string ProfileKeysPath = "/.well-known/ai-sentinel/profile-keys";

    private const string Actor = "policy-folder";

    /// <summary>Registers the loader that reads, compiles and validates the policy folder, and the signer of profiles.
    /// Needs <see cref="AdminAuditExtensions.AddAISentinelAdminAudit"/>: a publish and a rejected publish are written to that log.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Sets <see cref="PolicyFolderOptions.Path"/> and <see cref="PolicyFolderOptions.SigningKey"/>.</param>
    public static IServiceCollection AddAISentinelPolicyFolder(this IServiceCollection services, Action<PolicyFolderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<PolicyFolderOptions>().Configure(configure);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IReadOnlyList<IRegoCompiler>>(sp =>
            [new OpaBinaryCompiler(sp.GetRequiredService<IOptions<PolicyFolderOptions>>().Value.OpaPath is { Length: > 0 } path ? path : FindOpa(Environment.GetEnvironmentVariable("PATH")), ChildProcessRegoCompiler.DefaultTimeout)]);
        services.TryAddSingleton(sp =>
        {
            var o = sp.GetRequiredService<IOptions<PolicyFolderOptions>>().Value;
            if (string.IsNullOrWhiteSpace(o.SigningKey))
            {
                throw new InvalidOperationException("PolicyFolderOptions.SigningKey is required to sign profiles.");
            }

            return ProfileSigningKeys.FromBase64(o.SigningKey, o.PreviousSigningKey);
        });
        services.TryAddSingleton(sp => new ProfileSigner(sp.GetRequiredService<ProfileSigningKeys>(), sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton(sp =>
        {
            var o = sp.GetRequiredService<IOptions<PolicyFolderOptions>>().Value;
            if (string.IsNullOrWhiteSpace(o.Path))
            {
                throw new InvalidOperationException("PolicyFolderOptions.Path is required.");
            }

            var audit = sp.GetRequiredService<AdminAuditLog>();
            return new PolicyFolderLoader(
                o.Path,
                new ConfigurationCompiler(sp.GetRequiredService<IReadOnlyList<IRegoCompiler>>()),
                async (organisation, action, target, ct) =>
                    await audit.RecordAsync(organisation, action, Actor, target, AdminAuditChannel.Git, ct).ConfigureAwait(false),
                sp.GetService<IOptions<AdminAuditOptions>>()?.Value.Organisation ?? "default",
                sp.GetRequiredService<TimeProvider>(),
                PolicyFolderTiming.Default with { Settle = o.SettleDelay, PollInterval = o.PollInterval },
                sp.GetRequiredService<ILoggerFactory>().CreateLogger<PolicyFolderLoader>());
        });
        services.TryAddSingleton<ProfileIssuer>();
        services.AddSingleton<Microsoft.Extensions.Hosting.IHostedService>(sp => new PolicyFolderService(
            sp.GetRequiredService<PolicyFolderLoader>(),
            sp.GetRequiredService<IOptions<PolicyFolderOptions>>().Value.Path!,
            sp.GetRequiredService<ILogger<PolicyFolderService>>()));
        return services;
    }

    /// <summary>Maps the endpoints that serve what the folder produced. All are <c>GET</c>: no endpoint accepts policy or node
    /// configuration. The host's authorization policy named in <see cref="PolicyFolderOptions.PolicyName"/> is checked with the
    /// organisation as the resource.
    /// <list type="bullet">
    /// <item><c>GET /.well-known/ai-sentinel/profile-keys</c>: the organisation and the base64 public keys to pin.</item>
    /// <item><c>GET {pathPrefix}/profile?repository=</c>: the signed profile of the repository; 404 when no node owns it.</item>
    /// <item><c>GET {pathPrefix}/node-map</c>: which node owns which repository, in the form the hooks cache.</item>
    /// </list>
    /// All answer 503 until a configuration has been published.</summary>
    public static RouteGroupBuilder MapAISentinelPolicyServer(
        this IEndpointRouteBuilder endpoints, string pathPrefix = "/ai-sentinel/policy")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapGet(ProfileKeysPath, KeysAsync);
        var group = endpoints.MapGroup(pathPrefix);
        group.MapGet("/profile", ProfileAsync);
        group.MapGet("/node-map", NodeMapAsync);
        return group;
    }

    private static async Task<(IResult? Failure, PublishedConfiguration? Configuration)> AdmitAsync(
        HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer)
    {
        if (http.User.Identity?.IsAuthenticated != true)
        {
            return (Results.StatusCode(StatusCodes.Status401Unauthorized), null);
        }

        if (issuer.Current is not { } configuration)
        {
            return (Results.StatusCode(StatusCodes.Status503ServiceUnavailable), null);
        }

        var result = await authorization.AuthorizeAsync(http.User, configuration.Organisation, options.Value.PolicyName).ConfigureAwait(false);
        return result.Succeeded ? (null, configuration) : (Results.StatusCode(StatusCodes.Status403Forbidden), null);
    }

    private static async Task<IResult> KeysAsync(
        HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer)
    {
        var (failure, configuration) = await AdmitAsync(http, authorization, options, issuer).ConfigureAwait(false);
        return failure ?? Results.Json(
            new ProfileKeysResponse { Organisation = configuration!.Organisation, Keys = [.. issuer.PublicKeys()] },
            PolicyServerJsonContext.Default.ProfileKeysResponse);
    }

    private static async Task<IResult> ProfileAsync(
        string? repository, HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer)
    {
        var (failure, configuration) = await AdmitAsync(http, authorization, options, issuer).ConfigureAwait(false);
        if (failure is not null)
        {
            return failure;
        }

        if (string.IsNullOrWhiteSpace(repository))
        {
            return Results.StatusCode(StatusCodes.Status400BadRequest);
        }

        return issuer.Issue(configuration!, repository) is { } profile
            ? Results.Text(profile.ToJson(), "application/json")
            : Results.StatusCode(StatusCodes.Status404NotFound);
    }

    private static async Task<IResult> NodeMapAsync(
        HttpContext http, IAuthorizationService authorization, IOptions<PolicyFolderOptions> options, ProfileIssuer issuer)
    {
        var (failure, configuration) = await AdmitAsync(http, authorization, options, issuer).ConfigureAwait(false);
        return failure ?? Results.Bytes(configuration!.Nodes.Map.ToJson(), "application/json");
    }

    /// <summary>The <c>opa</c> binary in the first folder of <paramref name="searchPath"/> that holds one, or null.</summary>
    internal static string? FindOpa(string? searchPath)
    {
        var exe = OperatingSystem.IsWindows() ? "opa.exe" : "opa";
        foreach (var dir in (searchPath ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir, exe);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}

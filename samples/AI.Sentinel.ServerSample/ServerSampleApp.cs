using AI.Sentinel;
using AI.Sentinel.Approvals;
using AI.Sentinel.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.ServerSample;

/// <summary>The server part of AI.Sentinel in a plain ASP.NET Core app, with no central product. It serves the signed profiles, the
/// pause and release endpoints with their event stream, the dashboard with its approve and deny, and the audit export.</summary>
public static class ServerSampleApp
{
    /// <summary>The identity-provider settings the sample reads from configuration: <c>Oidc:Authority</c> and <c>Oidc:Audience</c>.</summary>
    public const string OidcSection = "Oidc";

    /// <summary>Builds the app. <paramref name="configure"/> runs before the app is built, so a test can replace a registration.</summary>
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(args);
        var signingKey = builder.Configuration["Sentinel:SigningKey"]
            ?? throw new InvalidOperationException("Sentinel:SigningKey is required: the base64 of a 32 byte Ed25519 seed, set through the deployment.");
        var policyPath = builder.Configuration["Sentinel:PolicyPath"]
            ?? throw new InvalidOperationException("Sentinel:PolicyPath is required: the folder, or the link, that git-sync keeps up to date.");

        // Sign-in: the identity provider issues the tokens the plugin sends. MapInboundClaims is off so the claims keep the names
        // the server reads: sub for the developer and groups for the group bindings of nodes.json.
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(o =>
            {
                o.Authority = builder.Configuration[$"{OidcSection}:Authority"];
                o.Audience = builder.Configuration[$"{OidcSection}:Audience"];
                o.MapInboundClaims = false;
                o.TokenValidationParameters.NameClaimType = "sub";
            });

        // Both policies only ask for a signed-in user. Who may do what comes from the role bindings of nodes.json.
        builder.Services.AddAuthorization(o =>
        {
            o.AddPolicy("AISentinelDeveloper", p => p.RequireAuthenticatedUser());
            o.AddPolicy("AISentinelAdminAudit", p => p.RequireAuthenticatedUser());
        });

        builder.Services.AddAISentinel();
        builder.Services.AddSentinelApprovalStore(_ => new InMemoryApprovalStore());
        builder.Services.AddAISentinelAdminAudit(o =>
        {
            o.SigningKey = signingKey;
            o.Organisation = builder.Configuration["Sentinel:Organisation"] ?? "default";
        });
        builder.Services.AddAISentinelPolicyFolder(o =>
        {
            o.Path = policyPath;
            o.SigningKey = signingKey;
            o.PreviousSigningKey = builder.Configuration["Sentinel:PreviousSigningKey"];
            o.OpaPath = builder.Configuration["Sentinel:OpaPath"];
        });
        configure?.Invoke(builder);

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapAISentinel("/ai-sentinel").RequireAuthorization();
        app.MapAISentinelPolicyServer();
        app.MapAISentinelSessionControl();
        app.MapAISentinelAdminAudit();
        return app;
    }
}

using ZeroAlloc.Inject;
using System.Runtime.CompilerServices;

[assembly: ZeroAllocInject("AddAISentinelDetectors")]
[assembly: InternalsVisibleTo("AI.Sentinel.Tests")]
[assembly: InternalsVisibleTo("AI.Sentinel.AspNetCore")]
[assembly: InternalsVisibleTo("AI.Sentinel.ClaudeCode")]
[assembly: InternalsVisibleTo("AI.Sentinel.Copilot")]

[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.ISecurityContext))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.IAuthorizationPolicy))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.RequirePolicyAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.PolicyAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AnonymousSecurityContext))]

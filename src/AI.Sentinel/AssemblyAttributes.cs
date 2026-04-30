using ZeroAlloc.Inject;
using System.Runtime.CompilerServices;

[assembly: ZeroAllocInject("AddAISentinelDetectors")]
[assembly: InternalsVisibleTo("AI.Sentinel.Tests")]

[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.ISecurityContext))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.IAuthorizationPolicy))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AuthorizeAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AuthorizationPolicyAttribute))]
[assembly: TypeForwardedTo(typeof(ZeroAlloc.Authorization.AnonymousSecurityContext))]

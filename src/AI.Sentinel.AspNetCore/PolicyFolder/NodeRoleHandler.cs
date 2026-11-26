using Microsoft.AspNetCore.Authorization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>Succeeds a <see cref="NodeRoleRequirement"/> when the signed-in user holds the role on the node, or above it, in the
/// node configuration that is current now.</summary>
internal sealed class NodeRoleHandler(NodeRoles roles) : AuthorizationHandler<NodeRoleRequirement, string>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NodeRoleRequirement requirement, string node)
    {
        if (roles.Allows(context.User, requirement.Minimum, node))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

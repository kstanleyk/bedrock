using Crestacle.Sentinel.Core.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Crestacle.Sentinel.AspNetCore.Authorization;

/// <summary>
/// Requires the authenticated user to hold the specified feature/action permission.
/// Usage: [MustHavePermission(SentinelFeature.Role, AppAction.Read)] for the built-in management
/// endpoints, or [MustHavePermission("Invoice", AppAction.Read)] for an app-defined feature.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class MustHavePermissionAttribute : AuthorizeAttribute
{
    public MustHavePermissionAttribute(string feature, string action)
        => Policy = AppPermission.NameFor(feature, action);
}

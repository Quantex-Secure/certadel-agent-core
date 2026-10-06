using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// Scheme and policy names for the remote management API. The API accepts two
/// authentication schemes behind one policy scheme: Negotiate (Windows
/// Integrated Auth — the console's primary, Kerberos/NTLM SSO) and Basic
/// (username/password fallback).
/// </summary>
public static class ManagementApiAuth
{
    /// <summary>Authorization policy applied to every <c>/api/v1</c> endpoint.</summary>
    public const string Policy = "ManagementApi";

    /// <summary>
    /// Forwarding policy scheme that routes a request to Basic when it carries a
    /// Basic <c>Authorization</c> header, otherwise to Negotiate.
    /// </summary>
    public const string PolicyScheme = "ManagementApiScheme";
}

/// <summary>
/// Requires the caller to be a member of <c>Auth:AllowedGroup</c>, evaluated by
/// <see cref="AllowedGroupAuthorizer"/> for every scheme: a Windows token is
/// tested by SID (deny-only included), anything else by the role claims its
/// backend produced. No scheme is trusted to have "already checked".
/// </summary>
public sealed class AllowedGroupRequirement : IAuthorizationRequirement;

/// <summary>Authorization handler for <see cref="AllowedGroupRequirement"/>.</summary>
public sealed class ManagementApiAuthorizationHandler(
    AllowedGroupAuthorizer authorizer,
    ILogger<ManagementApiAuthorizationHandler> logger)
    : AuthorizationHandler<AllowedGroupRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AllowedGroupRequirement requirement)
    {
        var user = context.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            // RequireAuthenticatedUser() on the policy also covers this; be explicit.
            return Task.CompletedTask;
        }

        if (authorizer.IsAuthorized(user))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Fail closed. This also covers Negotiate on non-Windows hosts, where the
        // principal carries no group information we can evaluate: operators there
        // authenticate the API with Basic (PAM + group resolution) or leave
        // Auth:EnableNegotiate=false (the default in the systemd unit).
        logger.LogWarning(
            "Management API: denied '{User}' (auth {Auth}) — not a member of {Group}.",
            user.Identity.Name, user.Identity.AuthenticationType, authorizer.AllowedGroupDisplay);
        return Task.CompletedTask;
    }
}
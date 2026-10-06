namespace AcmeManager.Service;

/// <summary>
/// Named rate-limiter policies applied to the authentication-bearing endpoints
/// (configured in <c>Program</c>'s <c>AddRateLimiter</c>).
/// </summary>
public static class RateLimitPolicies
{
    /// <summary>Per-client-IP throttle on the interactive form-login endpoint.</summary>
    public const string Login = "login";

    /// <summary>Per-client-IP throttle on the remote management API (Basic brute-force guard).</summary>
    public const string ManagementApi = "management-api";
}
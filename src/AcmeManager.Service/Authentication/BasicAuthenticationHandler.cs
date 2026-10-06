using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

using AcmeManager.Core.Authentication;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// HTTP Basic authentication for the management API — the username/password
/// fallback for agents that can't do Windows Integrated Auth (non-domain hosts,
/// or a console connecting cross-realm). Credentials are validated through the
/// same <see cref="IAuthBackend"/> as the form login, so the OS logon and the
/// <c>Auth:AllowedGroup</c> membership check are reused verbatim. Basic is only
/// exposed over Kestrel's HTTPS-only endpoint, so credentials never travel in
/// the clear.
/// </summary>
public sealed class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "Basic";

    private const string Prefix = "Basic ";

    private readonly IAuthBackend _auth;
    private readonly AuthThrottle _throttle;

    public BasicAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IAuthBackend auth,
        AuthThrottle throttle)
        : base(options, logger, encoder)
    {
        _auth = auth;
        _throttle = throttle;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? header = Request.Headers.Authorization;
        if (string.IsNullOrEmpty(header) || !header.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            // Let the pipeline fall through to a challenge rather than failing hard.
            return AuthenticateResult.NoResult();
        }

        string username, password;
        try
        {
            var encoded = header[Prefix.Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var separator = decoded.IndexOf(':');
            if (separator < 0)
            {
                return AuthenticateResult.Fail("Malformed Basic credentials");
            }
            username = decoded[..separator];
            password = decoded[(separator + 1)..];
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Malformed Basic credentials");
        }

        // Per-account lockout runs BEFORE the OS logon so a stuffing loop can neither
        // brute-force the password nor drive the directory's own lockout counter.
        // Attempts for one account are serialised so a parallel burst can't all
        // reach the OS ahead of the first counted failure.
        AuthResult result;
        using (await _throttle.EnterAsync(username, Context.RequestAborted))
        {
            if (_throttle.IsLockedOut(username, out var retryAfter))
            {
                Logger.LogWarning("Basic auth refused for {User}: account throttled for another {Seconds:0}s",
                    username, retryAfter.TotalSeconds);
                return AuthenticateResult.Fail("Authentication failed");
            }

            result = await _auth.AuthenticateAsync(username, password, Context.RequestAborted);
            if (!result.Success)
            {
                // Don't echo the OS reason to the wire; log it, return a generic failure.
                var lockout = _throttle.RecordFailure(username);
                Logger.LogInformation("Basic auth rejected for {User}: {Reason}{Lockout}", username, result.Reason,
                    lockout is { } l ? $" — account throttled for {l.TotalMinutes:0} min" : "");
                return AuthenticateResult.Fail("Authentication failed");
            }
            _throttle.RecordSuccess(username);
        }

        var claims = new List<Claim> { new(ClaimTypes.Name, result.Username ?? username) };
        if (result.Groups is not null)
        {
            claims.AddRange(result.Groups.Select(g => new Claim(ClaimTypes.Role, g)));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "Basic realm=\"acme-manager\", charset=\"UTF-8\"";
        return Task.CompletedTask;
    }
}
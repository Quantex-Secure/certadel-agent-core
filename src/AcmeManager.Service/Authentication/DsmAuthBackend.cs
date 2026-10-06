using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

using AcmeManager.Core.Authentication;
using AcmeManager.Plugins.Linux.Synology;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// Validates credentials against Synology DSM's Web API on the local NAS. DSM 7
/// runs the agent as an unprivileged package user, so PAM is not an option; DSM
/// itself checks the password (local or domain accounts, e.g. <c>EXAMPLE\name</c>).
///
/// Group resolution: the user is reported as a member of
/// <see cref="AdministratorsGroup"/> only if DSM lets them list certificates —
/// DSM refuses that call (code 105) to non-administrators, and it is precisely the
/// permission the agent's DSM installer needs. As with the other backends, the
/// authorization decision itself is made by <see cref="AllowedGroupAuthorizer"/>.
/// Any failure to establish membership yields no groups, which that decision refuses.
///
/// Successful administrator sign-ins are cached for <see cref="CacheLifetime"/>:
/// the management API authenticates every request (HTTP Basic), and each DSM
/// sign-in is a slow round trip on small NAS hardware and an entry in DSM's
/// connection log. The cache key is an HMAC of username and password under a
/// per-process random key, so no password is retained. Failures and
/// non-administrators are never cached.
/// </summary>
public sealed class DsmAuthBackend(
    Func<DsmApiClient> clientFactory,
    ILogger<DsmAuthBackend> logger,
    TimeProvider clock) : IAuthBackend
{
    public const string AdministratorsGroup = "administrators";

    public static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(5);
    private const int MaxCachedSignIns = 64;

    private readonly byte[] _cacheKey = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _adminSignIns = new(StringComparer.Ordinal);

    public async ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            return AuthResult.Fail("Username and password are required");
        }

        var cacheKey = CacheKey(username, password);
        if (_adminSignIns.TryGetValue(cacheKey, out var expires) && expires > clock.GetUtcNow())
        {
            return AuthResult.Ok(username, [AdministratorsGroup]);
        }

        var result = await AuthenticateWithDsmAsync(username, password, ct);
        if (result.Success && result.Groups?.Contains(AdministratorsGroup) == true)
        {
            Remember(cacheKey);
        }
        return result;
    }

    private async Task<AuthResult> AuthenticateWithDsmAsync(string username, string password, CancellationToken ct)
    {
        using var client = clientFactory();
        DsmSession session;
        try
        {
            session = await client.LoginAsync(username, password, ct);
        }
        catch (DsmApiException ex) when (ex.Kind != DsmErrorKind.Transport)
        {
            logger.LogInformation("DSM refused sign-in for {User}: {Kind} (code {Code})", username, ex.Kind, ex.Code);
            return AuthResult.Fail(Describe(ex));
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "DSM sign-in service unavailable at {Url}", client.BaseAddress);
            return AuthResult.Fail("DSM sign-in service is unavailable");
        }

        try
        {
            return AuthResult.Ok(username, await ResolveGroupsAsync(client, session, username, ct));
        }
        finally
        {
            await client.LogoutAsync(session, CancellationToken.None);
        }
    }

    private async Task<IReadOnlyList<string>> ResolveGroupsAsync(
        DsmApiClient client, DsmSession session, string username, CancellationToken ct)
    {
        try
        {
            await client.ListCertificatesAsync(session, ct);
            return [AdministratorsGroup];
        }
        catch (DsmApiException ex) when (ex.Kind == DsmErrorKind.PermissionDenied)
        {
            logger.LogInformation("{User} signed in to DSM but is not a DSM administrator", username);
            return [];
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Could not confirm DSM administrator rights for {User}", username);
            return [];
        }
    }

    private string CacheKey(string username, string password) =>
        Convert.ToHexString(HMACSHA256.HashData(_cacheKey, Encoding.UTF8.GetBytes($"{username}\0{password}")));

    private void Remember(string cacheKey)
    {
        var now = clock.GetUtcNow();
        if (_adminSignIns.Count >= MaxCachedSignIns)
        {
            foreach (var stale in _adminSignIns.Where(e => e.Value <= now).Select(e => e.Key).ToList())
            {
                _adminSignIns.TryRemove(stale, out _);
            }
            if (_adminSignIns.Count >= MaxCachedSignIns)
            {
                _adminSignIns.Clear();
            }
        }
        _adminSignIns[cacheKey] = now + CacheLifetime;
    }

    private static string Describe(DsmApiException ex) => ex.Kind switch
    {
        DsmErrorKind.BadCredentials => "Invalid username or password",
        DsmErrorKind.AccountDisabled => "This DSM account is disabled",
        DsmErrorKind.TwoFactorRequired => "This DSM account requires two-factor sign-in, which the agent cannot complete",
        DsmErrorKind.IpBlocked => "DSM has blocked sign-ins from the agent (Auto Block)",
        DsmErrorKind.PasswordExpired => "The DSM password has expired; change it in DSM first",
        DsmErrorKind.PermissionDenied => "This account is not allowed to sign in to DSM",
        _ => $"DSM refused sign-in (error {ex.Code})",
    };
}

namespace AcmeManager.Core.Authentication;

/// <summary>
/// Validates user credentials against the host OS. Implementations:
/// <list type="bullet">
///   <item>Windows: <c>LogonUser</c> via P/Invoke for explicit form login;
///         Kestrel Negotiate middleware handles browser SSO separately and
///         does not pass through this interface.</item>
///   <item>Linux: PAM via P/Invoke to <c>libpam.so</c>.</item>
/// </list>
/// </summary>
public interface IAuthBackend
{
    ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct);
}

public sealed record AuthResult(
    bool Success,
    string? Username = null,
    IReadOnlyList<string>? Groups = null,
    string? Reason = null)
{
    public static AuthResult Fail(string reason) => new(false, Reason: reason);

    public static AuthResult Ok(string username, IReadOnlyList<string>? groups = null) =>
        new(true, username, groups);
}
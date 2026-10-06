using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

using AcmeManager.Core.Authentication;

using Microsoft.Win32.SafeHandles;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// Validates Windows credentials via <c>LogonUserW</c> in advapi32.dll using
/// <c>LOGON32_LOGON_NETWORK</c> — the cheapest logon type, which doesn't
/// require <c>SeTcbPrivilege</c> on Vista+. After a successful logon we
/// reconstruct a <see cref="WindowsIdentity"/> from the access token to
/// surface the canonical username and the full group list.
///
/// This backend <em>authenticates only</em>. The <c>Auth:AllowedGroup</c>
/// decision is made once, by <see cref="AllowedGroupAuthorizer"/>, at the login
/// endpoint and the management-API policy, so every backend on every OS is
/// held to the same rule. The returned group names include deny-only SIDs
/// (a UAC-filtered admin token) so that decision still recognizes an admin
/// once the token itself is gone.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsAuthBackend : IAuthBackend
{
    private const int LOGON32_LOGON_NETWORK = 3;
    private const int LOGON32_PROVIDER_DEFAULT = 0;

    [LibraryImport("advapi32.dll", EntryPoint = "LogonUserW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LogonUser(
        string lpszUsername,
        string? lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out SafeAccessTokenHandle phToken);

    public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct)
    {
        var (user, domain) = SplitUserAndDomain(username);

        if (!LogonUser(user, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out var token))
        {
            var code = Marshal.GetLastWin32Error();
            return ValueTask.FromResult(AuthResult.Fail($"LogonUser failed (Win32 0x{code:X8})"));
        }

        using (token)
        {
            using var identity = new WindowsIdentity(token.DangerousGetHandle());
            var groups = AllowedGroupAuthorizer.EnumerateTokenGroupNames(identity);
            return ValueTask.FromResult(AuthResult.Ok(identity.Name ?? username, groups));
        }
    }

    private static (string User, string? Domain) SplitUserAndDomain(string username)
    {
        var slashIdx = username.IndexOf('\\');
        if (slashIdx >= 0)
        {
            return (username[(slashIdx + 1)..], username[..slashIdx]);
        }
        if (username.Contains('@'))
        {
            // UPN — pass through whole string as user, no separate domain.
            return (username, null);
        }
        return (username, ".");
    }
}
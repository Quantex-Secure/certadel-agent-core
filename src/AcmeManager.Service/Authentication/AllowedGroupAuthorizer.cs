using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Principal;

namespace AcmeManager.Service.Authentication;

/// <summary>
/// The single source of truth for the <c>Auth:AllowedGroup</c> membership test.
/// Cert management writes private keys and the machine keystore, so only members
/// of the configured group may manage a node.
///
/// Authentication backends (<see cref="WindowsAuthBackend"/>, <see cref="LinuxPamAuthBackend"/>)
/// only establish <em>who</em> the caller is and which groups they belong to; the
/// authorization decision is made here, once, for every scheme and every OS —
/// by the form-login endpoint and by the management-API policy. A backend that
/// returns no groups therefore yields "not authorized" (fail closed) rather than
/// "already checked".
///
/// Two evaluation paths:
/// <list type="bullet">
///   <item>A live <see cref="WindowsIdentity"/> (Negotiate SSO on Windows) is
///         tested against the token's SIDs, including deny-only SIDs.</item>
///   <item>Anything else (Basic, cookie, PAM) is tested by group <em>name</em>
///         against the role claims / group list the backend produced.</item>
/// </list>
/// </summary>
public sealed partial class AllowedGroupAuthorizer
{
    private const int TokenGroups = 2;

    /// <summary>
    /// When <c>Auth:AllowedGroup</c> is blank on a Unix host, membership in any of
    /// the conventional administrator groups is required (Debian/Ubuntu use
    /// <c>sudo</c>, RHEL/Fedora/SUSE/Arch use <c>wheel</c>, some images use
    /// <c>admin</c>; <c>root</c> always counts).
    /// </summary>
    internal static readonly string[] UnixDefaultAdminGroups = ["root", "sudo", "wheel", "admin"];

    internal const string WindowsDefaultAdminGroup = "BUILTIN\\Administrators";

    private readonly string? _allowedGroup;

    /// <param name="allowedGroup">
    /// Group whose members are authorized (e.g. <c>CONTOSO\Certificate Admins</c>,
    /// <c>BUILTIN\Administrators</c>, or a Unix group like <c>certadmins</c>). When
    /// null/blank, the box's local administrators are required: the local
    /// Administrators group on Windows, or one of <see cref="UnixDefaultAdminGroups"/>
    /// elsewhere.
    /// </param>
    public AllowedGroupAuthorizer(string? allowedGroup) =>
        _allowedGroup = string.IsNullOrWhiteSpace(allowedGroup) ? null : allowedGroup.Trim();

    public string AllowedGroupDisplay =>
        _allowedGroup
        ?? (OperatingSystem.IsWindows() ? WindowsDefaultAdminGroup : string.Join("/", UnixDefaultAdminGroups));

    /// <summary>
    /// Authorizes an authenticated principal regardless of how it was
    /// authenticated. Unauthenticated principals and principals with no usable
    /// group information are refused.
    /// </summary>
    public bool IsAuthorized(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        if (OperatingSystem.IsWindows() && principal.Identity is WindowsIdentity windowsIdentity)
        {
#pragma warning disable CA1416 // guarded by OperatingSystem.IsWindows() above
            return IsAuthorized(windowsIdentity);
#pragma warning restore CA1416
        }

        return IsAuthorized(principal.FindAll(ClaimTypes.Role).Select(c => c.Value));
    }

    /// <summary>
    /// Name-based membership test over the groups a backend resolved for the user.
    /// Null or empty means the backend could not establish membership — refused.
    /// </summary>
    public bool IsAuthorized(IEnumerable<string>? groupNames)
    {
        if (groupNames is null)
        {
            return false;
        }

        var required = RequiredGroupNames();
        foreach (var actual in groupNames)
        {
            if (string.IsNullOrWhiteSpace(actual))
            {
                continue;
            }
            foreach (var expected in required)
            {
                if (GroupNameMatches(actual, expected))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private IReadOnlyList<string> RequiredGroupNames()
    {
        if (_allowedGroup is not null)
        {
            return [_allowedGroup];
        }
        return OperatingSystem.IsWindows() ? [WindowsDefaultAdminGroup] : UnixDefaultAdminGroups;
    }

    /// <summary>
    /// Case-insensitive name match. A configured group without a qualifier
    /// (<c>Administrators</c>, <c>certadmins</c>) matches an unqualified token
    /// group (Unix) or a <em>local</em> Windows group — <c>BUILTIN\…</c> or
    /// <c>&lt;this machine&gt;\…</c>. It deliberately does not match a same-named
    /// group from a domain (<c>CONTOSO\Certificate Admins</c>): a trusted forest
    /// could otherwise mint a group of that name. Domain groups must be
    /// configured fully qualified, and then must match exactly.
    /// </summary>
    internal static bool GroupNameMatches(string actual, string expected) =>
        GroupNameMatches(actual, expected, Environment.MachineName);

    internal static bool GroupNameMatches(string actual, string expected, string localMachineName)
    {
        if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (expected.Contains('\\'))
        {
            return false;
        }

        var separator = actual.LastIndexOf('\\');
        if (separator < 0)
        {
            return false; // both unqualified and not equal
        }

        var qualifier = actual[..separator];
        var actualBare = actual[(separator + 1)..];
        var isLocal = string.Equals(qualifier, "BUILTIN", StringComparison.OrdinalIgnoreCase)
            || string.Equals(qualifier, localMachineName, StringComparison.OrdinalIgnoreCase);
        return isLocal && string.Equals(actualBare, expected, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True if the identity is a member of the allowed group, tested against the
    /// token's full group list <em>including deny-only SIDs</em>.
    ///
    /// This is essential for Negotiate SSO from a non-elevated console: such a
    /// process carries a UAC-filtered token in which the Administrators SID is
    /// present only as deny-only. Both <see cref="WindowsPrincipal.IsInRole(string)"/>
    /// and <see cref="WindowsIdentity.Groups"/> omit deny-only SIDs, so they would
    /// wrongly reject a genuine admin. The raw <c>GetTokenInformation</c> /
    /// <c>TokenGroups</c> data includes them, and for an authorization
    /// <em>decision</em> ("is this account an admin?") deny-only membership counts.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public bool IsAuthorized(WindowsIdentity identity)
    {
        var target = ResolveTargetSid();
        if (target is not null && EnumerateTokenGroupSids(identity).Any(sid => sid == target))
        {
            return true;
        }

        // Fallback for a named group we couldn't translate to a SID (won't see
        // deny-only membership, but better than nothing).
        return _allowedGroup is not null && new WindowsPrincipal(identity).IsInRole(_allowedGroup);
    }

    /// <summary>
    /// Every group the token carries (enabled and deny-only) as account names —
    /// <c>BUILTIN\Administrators</c>, <c>CONTOSO\Certificate Admins</c>, … — with
    /// the SID string as a fallback for anything that can't be translated. This
    /// is what a Windows backend hands to the name-based decision so that a
    /// UAC-filtered admin is still recognized after the token is gone.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<string> EnumerateTokenGroupNames(WindowsIdentity identity)
    {
        var names = new List<string>();
        foreach (var sid in EnumerateTokenGroupSids(identity))
        {
            names.Add(TryTranslate(sid));
        }
        return names;
    }

    [SupportedOSPlatform("windows")]
    private SecurityIdentifier? ResolveTargetSid()
    {
        if (_allowedGroup is null)
        {
            return new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        }
        try
        {
            return (SecurityIdentifier)new NTAccount(_allowedGroup).Translate(typeof(SecurityIdentifier));
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string TryTranslate(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException)
        {
            return sid.Value;
        }
    }

    /// <summary>
    /// Enumerates every group SID in the token (enabled <em>and</em> deny-only).
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static List<SecurityIdentifier> EnumerateTokenGroupSids(WindowsIdentity identity)
    {
        var sids = new List<SecurityIdentifier>();
        var token = identity.AccessToken;
        if (token is null || token.IsInvalid)
        {
            return sids;
        }
        var handle = token.DangerousGetHandle();

        // First call sizes the buffer.
        GetTokenInformation(handle, TokenGroups, IntPtr.Zero, 0, out var length);
        if (length <= 0)
        {
            return sids;
        }

        var buffer = Marshal.AllocHGlobal(length);
        try
        {
            if (!GetTokenInformation(handle, TokenGroups, buffer, length, out _))
            {
                return sids;
            }

            // TOKEN_GROUPS { DWORD GroupCount; SID_AND_ATTRIBUTES Groups[]; }
            // The array is pointer-aligned, so it starts one pointer-width in. Each
            // SID_AND_ATTRIBUTES is { PSID Sid; DWORD Attributes; } padded to a
            // pointer-width multiple.
            var count = Marshal.ReadInt32(buffer);
            var arrayStart = buffer + IntPtr.Size;
            var stride = IntPtr.Size == 8 ? 16 : 8;
            for (var i = 0; i < count; i++)
            {
                var sidPtr = Marshal.ReadIntPtr(arrayStart + (i * stride));
                if (sidPtr != IntPtr.Zero)
                {
                    sids.Add(new SecurityIdentifier(sidPtr));
                }
            }
            return sids;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        out int ReturnLength);
}
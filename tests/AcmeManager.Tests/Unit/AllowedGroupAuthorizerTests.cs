using System.Runtime.InteropServices;
using System.Security.Principal;

using AcmeManager.Service.Authentication;

namespace AcmeManager.Tests.Unit;

public sealed class AllowedGroupAuthorizerTests
{
    private const int LuaToken = 0x4; // create a UAC-filtered ("limited") token

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(
        IntPtr ExistingTokenHandle, int Flags,
        int DisableSidCount, IntPtr SidsToDisable,
        int DeletePrivilegeCount, IntPtr PrivilegesToDelete,
        int RestrictedSidCount, IntPtr SidsToRestrict,
        out IntPtr NewTokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>
    /// The SSO 403 bug: a non-elevated admin connects via Negotiate and the agent
    /// sees a UAC-filtered token where Administrators is deny-only. This fabricates
    /// exactly that token and asserts the authorizer still recognizes the admin —
    /// where the old IsInRole/Groups approaches do not.
    /// </summary>
    [Fact]
    public void AuthorizesAdmin_FromUacFilteredToken()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var current = WindowsIdentity.GetCurrent();
        var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        // Test only means something when running as an elevated admin (so the base
        // token actually contains an enabled Administrators SID to filter down).
        var elevatedAdmin = new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator);
        if (!elevatedAdmin)
        {
            return;
        }

        Assert.True(
            CreateRestrictedToken(current.AccessToken.DangerousGetHandle(), LuaToken, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out var filtered),
            "CreateRestrictedToken failed");

        try
        {
            using var filteredIdentity = new WindowsIdentity(filtered);

            // Sanity: this is genuinely the filtered case the bug hit — the old
            // approaches do NOT see Administrators on this token.
            Assert.False(new WindowsPrincipal(filteredIdentity).IsInRole(adminSid),
                "expected IsInRole to miss the deny-only Administrators SID (filtered token)");
            Assert.DoesNotContain(adminSid, filteredIdentity.Groups!);

            // The fix: the authorizer recognizes the admin anyway.
            var authorizer = new AllowedGroupAuthorizer(allowedGroup: null); // default: local Administrators
            Assert.True(authorizer.IsAuthorized(filteredIdentity),
                "an Administrators member must be authorized even from a UAC-filtered token");
        }
        finally
        {
            CloseHandle(filtered);
        }
    }
}
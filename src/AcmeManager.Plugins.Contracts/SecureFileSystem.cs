using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Locks filesystem objects that hold private keys or secrets down to the owning
/// service account. On Windows: SYSTEM + Administrators only, with inheritance
/// broken so the default <c>Users</c>-readable ACL never applies (a directory's
/// rules propagate to the files created inside it). On Unix: <c>0600</c> for
/// files, <c>0700</c> for directories.
///
/// Best-effort: hardening never throws. A failure to tighten the ACL must not
/// crash the agent or fail a certificate write — the data directory is already
/// admin-scoped by the installer as a backstop.
/// </summary>
public static class SecureFileSystem
{
    /// <summary>Restricts a single file to the service account (owner-only).</summary>
    public static void HardenFile(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                HardenWindows(path, isDirectory: false);
            }
            else
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch
        {
            // Best effort — see type remarks.
        }
    }

    /// <summary>
    /// Restricts a directory to the service account and propagates that to the
    /// files created inside it (so e.g. the SQLite DB and secret key inherit it).
    /// </summary>
    public static void HardenDirectory(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                HardenWindows(path, isDirectory: true);
            }
            else
            {
                File.SetUnixFileMode(
                    path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }
        catch
        {
            // Best effort — see type remarks.
        }
    }

    [SupportedOSPlatform("windows")]
    private static void HardenWindows(string path, bool isDirectory)
    {
        var grantees = new List<SecurityIdentifier>
        {
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
        };

        // Keep the account the agent runs as, which wrote this file: it may be neither
        // SYSTEM nor a local admin (e.g. a dedicated service account or gMSA) and must
        // still read its own key material. This grants a specific account, not a group,
        // so low-privileged users are still excluded.
        using (var current = WindowsIdentity.GetCurrent())
        {
            if (current.User is { } owner && !grantees.Contains(owner))
            {
                grantees.Add(owner);
            }
        }

        if (isDirectory)
        {
            var info = new DirectoryInfo(path);
            var security = new DirectorySecurity();
            // Break inheritance (drop the inherited Users ACE) and grant only the
            // trusted accounts, propagating to child files and folders.
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            foreach (var sid in grantees)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            }
            info.SetAccessControl(security);
        }
        else
        {
            var info = new FileInfo(path);
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in grantees)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    sid, FileSystemRights.FullControl, AccessControlType.Allow));
            }
            info.SetAccessControl(security);
        }
    }
}
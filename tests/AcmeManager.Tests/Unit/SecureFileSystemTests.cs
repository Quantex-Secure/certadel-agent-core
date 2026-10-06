using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Tests.Unit;

/// <summary>
/// Verifies the at-rest hardening applied to key material and the data directory:
/// on Windows the ACL is reduced to SYSTEM + Administrators with the default
/// Users access removed. (The Unix path is a thin <c>chmod</c> wrapper.) The
/// class is Windows-only; every test skips at runtime on other platforms.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SecureFileSystemTests
{
    [SkippableFact]
    public void HardenFile_RestrictsToSystemAndAdministrators()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows ACLs");

        var path = Path.Combine(Path.GetTempPath(), $"acme-hardentest-{Guid.NewGuid():N}.key");
        File.WriteAllText(path, "secret");
        try
        {
            SecureFileSystem.HardenFile(path);

            var identities = ExplicitIdentities(new FileInfo(path).GetAccessControl());
            Assert.Contains(Sid(WellKnownSidType.LocalSystemSid), identities);
            Assert.Contains(Sid(WellKnownSidType.BuiltinAdministratorsSid), identities);
            Assert.DoesNotContain(Sid(WellKnownSidType.BuiltinUsersSid), identities);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [SkippableFact]
    public void HardenDirectory_RestrictsToSystemAndAdministrators_AndPropagatesToNewFiles()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "Windows ACLs");

        var dir = Path.Combine(Path.GetTempPath(), $"acme-hardentest-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            SecureFileSystem.HardenDirectory(dir);

            var dirIdentities = ExplicitIdentities(new DirectoryInfo(dir).GetAccessControl());
            Assert.Contains(Sid(WellKnownSidType.LocalSystemSid), dirIdentities);
            Assert.Contains(Sid(WellKnownSidType.BuiltinAdministratorsSid), dirIdentities);
            Assert.DoesNotContain(Sid(WellKnownSidType.BuiltinUsersSid), dirIdentities);

            // A file created inside inherits the locked-down ACL (no Users access).
            var child = Path.Combine(dir, "db.sqlite");
            File.WriteAllText(child, "data");
            var childIdentities = AllIdentities(new FileInfo(child).GetAccessControl());
            Assert.DoesNotContain(Sid(WellKnownSidType.BuiltinUsersSid), childIdentities);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static SecurityIdentifier Sid(WellKnownSidType type) => new(type, null);

    private static List<SecurityIdentifier> ExplicitIdentities(FileSystemSecurity security) =>
        Identities(security, includeInherited: false);

    private static List<SecurityIdentifier> AllIdentities(FileSystemSecurity security) =>
        Identities(security, includeInherited: true);

    private static List<SecurityIdentifier> Identities(FileSystemSecurity security, bool includeInherited) =>
        security.GetAccessRules(includeExplicit: true, includeInherited, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(r => (SecurityIdentifier)r.IdentityReference)
            .ToList();
}
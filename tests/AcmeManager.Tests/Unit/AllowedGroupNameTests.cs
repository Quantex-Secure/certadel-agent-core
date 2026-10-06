using System.Security.Claims;

using AcmeManager.Service.Authentication;

namespace AcmeManager.Tests.Unit;

/// <summary>
/// The name-based half of <see cref="AllowedGroupAuthorizer"/>: the decision
/// applied to Basic/PAM/cookie principals on every OS. (The Windows-token half
/// is covered by <see cref="AllowedGroupAuthorizerTests"/>.)
/// </summary>
public sealed class AllowedGroupNameTests
{
    [Fact]
    public void RefusesNullGroups_FailClosed()
    {
        var authorizer = new AllowedGroupAuthorizer("certadmins");
        Assert.False(authorizer.IsAuthorized((IEnumerable<string>?)null));
    }

    [Fact]
    public void RefusesEmptyGroups()
    {
        var authorizer = new AllowedGroupAuthorizer("certadmins");
        Assert.False(authorizer.IsAuthorized(Array.Empty<string>()));
    }

    [Fact]
    public void AuthorizesConfiguredGroup_CaseInsensitive()
    {
        var authorizer = new AllowedGroupAuthorizer("CertAdmins");
        Assert.True(authorizer.IsAuthorized(["users", "certadmins"]));
    }

    [Fact]
    public void RefusesWhenConfiguredGroupAbsent()
    {
        var authorizer = new AllowedGroupAuthorizer("certadmins");
        Assert.False(authorizer.IsAuthorized(["users", "docker", "sudo"]));
    }

    [Fact]
    public void BareConfiguredName_MatchesLocalGroups_ButNotADomainGroupOfTheSameName()
    {
        // A trusted forest could contain a "Certificate Admins" too; only a
        // fully-qualified configuration may admit a domain group.
        Assert.True(AllowedGroupAuthorizer.GroupNameMatches("BUILTIN\\Certificate Admins", "Certificate Admins", "HOST1"));
        Assert.True(AllowedGroupAuthorizer.GroupNameMatches("host1\\Certificate Admins", "Certificate Admins", "HOST1"));
        Assert.False(AllowedGroupAuthorizer.GroupNameMatches("CONTOSO\\Certificate Admins", "Certificate Admins", "HOST1"));
        Assert.False(AllowedGroupAuthorizer.GroupNameMatches("FABRIKAM\\Certificate Admins", "Certificate Admins", "HOST1"));
    }

    [Fact]
    public void QualifiedConfiguredName_RequiresExactMatch()
    {
        var authorizer = new AllowedGroupAuthorizer("CONTOSO\\Certificate Admins");
        Assert.False(authorizer.IsAuthorized(["FABRIKAM\\Certificate Admins"]));
        Assert.True(authorizer.IsAuthorized(["contoso\\certificate admins"]));
    }

    [Fact]
    public void BlankConfiguration_RequiresPlatformAdministrators()
    {
        var authorizer = new AllowedGroupAuthorizer(allowedGroup: null);

        Assert.False(authorizer.IsAuthorized(["users", "docker"]));

        if (OperatingSystem.IsWindows())
        {
            Assert.True(authorizer.IsAuthorized(["BUILTIN\\Users", "BUILTIN\\Administrators"]));
            Assert.False(authorizer.IsAuthorized(["sudo"]));
        }
        else
        {
            Assert.True(authorizer.IsAuthorized(["users", "sudo"]));
            Assert.True(authorizer.IsAuthorized(["wheel"]));
            Assert.False(authorizer.IsAuthorized(["BUILTIN\\Administrators"]));
        }
    }

    [Fact]
    public void Principal_WithRoleClaimInAllowedGroup_IsAuthorized()
    {
        var authorizer = new AllowedGroupAuthorizer("certadmins");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "alice"), new Claim(ClaimTypes.Role, "certadmins")],
            authenticationType: "Basic"));

        Assert.True(authorizer.IsAuthorized(principal));
    }

    [Fact]
    public void Principal_AuthenticatedWithoutRoleClaims_IsRefused()
    {
        var authorizer = new AllowedGroupAuthorizer("certadmins");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "alice")],
            authenticationType: "Basic"));

        Assert.False(authorizer.IsAuthorized(principal));
    }

    [Fact]
    public void Principal_Unauthenticated_IsRefused()
    {
        var authorizer = new AllowedGroupAuthorizer("certadmins");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.Role, "certadmins")])); // no authentication type → not authenticated

        Assert.False(authorizer.IsAuthorized(principal));
    }

    [Fact]
    public void IdOutput_IsSplitIntoDistinctGroupNames()
    {
        var groups = IdCommandGroupResolver.ParseIdOutput("alice sudo docker sudo\n");
        Assert.Equal(["alice", "sudo", "docker"], groups);
    }

    [Theory]
    [InlineData("alice", true)]
    [InlineData("svc_certadel", true)]
    [InlineData("alice@corp.example.com", true)]
    [InlineData("CORP\\alice", true)]
    [InlineData("machine$", true)]
    [InlineData("-Gn", false)]
    [InlineData("", false)]
    [InlineData("alice bob", false)]
    [InlineData("alice;id", false)]
    public void AccountNameValidation_RejectsOptionLikeAndShellLikeNames(string name, bool valid)
    {
        Assert.Equal(valid, IdCommandGroupResolver.IsValidAccountName(name));
    }
}
using System.Net;
using System.Net.Http.Headers;
using System.Text;

using AcmeManager.Core.Authentication;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AcmeManager.Tests.Integration;

/// <summary>
/// Exercises the management API's authentication AND authorization gate
/// end-to-end through the real middleware (policy scheme → Basic handler →
/// AllowedGroup authorization), with the OS auth backend swapped for a fake.
/// The backend only reports who the caller is and which groups they hold; the
/// Auth:AllowedGroup decision must be made by the policy — a backend that
/// returns no groups (the old Linux behaviour) must not get in.
/// Negotiate isn't testable on the in-memory test server, so these cover the
/// Basic path.
/// </summary>
public sealed class ManagementApiAuthTests
{
    private const string AllowedGroup = "CERTADEL-ADMINS";

    private static WebApplicationFactory<Program> CreateFactory(IAuthBackend auth)
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-it-{Guid.NewGuid():N}.db");
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            // Production avoids loading appsettings.Development.json (Web:AllowAnonymous=true).
            builder.UseEnvironment("Production");
            builder.UseSetting("Storage:DatabaseFile", dbFile);
            builder.UseSetting("Web:AllowAnonymous", "false");
            // Negotiate can't run on the in-memory test server; Basic-only here.
            builder.UseSetting("Auth:EnableNegotiate", "false");
            builder.UseSetting("Auth:AllowedGroup", AllowedGroup);
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IAuthBackend>();
                services.AddSingleton(auth);
            });
        });
    }

    private sealed class FakeAuthBackend(bool succeed, IReadOnlyList<string>? groups) : IAuthBackend
    {
        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            ValueTask.FromResult(succeed
                ? AuthResult.Ok(username, groups)
                : AuthResult.Fail("denied"));
    }

    [Fact]
    public async Task ManagementApi_WithValidCredentialsInAllowedGroup_Returns200()
    {
        using var factory = CreateFactory(new FakeAuthBackend(succeed: true, groups: ["users", AllowedGroup]));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = Basic("admin", "pw");

        var response = await client.GetAsync("/api/v1/agent");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("acme-manager", body);
    }

    [Fact]
    public async Task ManagementApi_WithInvalidBasicCredentials_Returns401()
    {
        using var factory = CreateFactory(new FakeAuthBackend(succeed: false, groups: null));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = Basic("admin", "wrong");

        var response = await client.GetAsync("/api/v1/agent");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ManagementApi_AuthenticatedButNotInAllowedGroup_Returns403()
    {
        // A valid OS logon for an account outside Auth:AllowedGroup must be refused
        // by the policy, not waved through because "Basic already checked".
        using var factory = CreateFactory(new FakeAuthBackend(succeed: true, groups: ["users", "docker"]));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = Basic("deploy", "pw");

        var response = await client.GetAsync("/api/v1/agent");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ManagementApi_AuthenticatedWithNoGroupInformation_Returns403()
    {
        // The pre-fix Linux backend returned Groups = null. That must fail closed.
        using var factory = CreateFactory(new FakeAuthBackend(succeed: true, groups: null));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = Basic("deploy", "pw");

        var response = await client.GetAsync("/api/v1/agent");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Login_AuthenticatedButNotInAllowedGroup_IsRedirectedBackWithoutACookie()
    {
        using var factory = CreateFactory(new FakeAuthBackend(succeed: true, groups: ["users"]));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "deploy",
                ["password"] = "pw",
            }),
        };
        request.Headers.Add("Sec-Fetch-Site", "same-origin");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/login?error=", response.Headers.Location?.ToString());
        Assert.False(response.Headers.Contains("Set-Cookie"), "no session cookie may be issued to an unauthorized account");
    }

    [Fact]
    public async Task Login_InAllowedGroup_IssuesTheSessionCookie()
    {
        using var factory = CreateFactory(new FakeAuthBackend(succeed: true, groups: [AllowedGroup]));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "admin",
                ["password"] = "pw",
            }),
        };
        request.Headers.Add("Sec-Fetch-Site", "same-origin");

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/", response.Headers.Location?.ToString());
        Assert.True(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task WellKnownEndpoint_IsAnonymous_Returns200()
    {
        using var factory = CreateFactory(new FakeAuthBackend(succeed: false, groups: null));
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/.well-known/acme-manager");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static AuthenticationHeaderValue Basic(string user, string password) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}")));
}
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
/// The per-account lockout seen through the real pipeline: once an account has
/// failed enough times, further attempts are refused without reaching the OS
/// backend at all — so neither the password nor the directory's lockout counter
/// can be ground down from rotating addresses.
/// </summary>
public sealed class AuthThrottleIntegrationTests
{
    private sealed class CountingBackend : IAuthBackend
    {
        public int Calls;

        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return ValueTask.FromResult(password == "right"
                ? AuthResult.Ok(username, ["CERTADEL-ADMINS"])
                : AuthResult.Fail("bad password"));
        }
    }

    private static WebApplicationFactory<Program> CreateFactory(IAuthBackend auth)
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-throttle-it-{Guid.NewGuid():N}.db");
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Storage:DatabaseFile", dbFile);
            builder.UseSetting("Web:AllowAnonymous", "false");
            builder.UseSetting("Auth:EnableNegotiate", "false");
            builder.UseSetting("Auth:AllowedGroup", "CERTADEL-ADMINS");
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IAuthBackend>();
                services.AddSingleton(auth);
            });
        });
    }

    private static AuthenticationHeaderValue Basic(string user, string password) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}")));

    [Fact]
    public async Task Basic_AfterFiveFailures_TheAccountIsRefusedWithoutAnOsLogon()
    {
        var backend = new CountingBackend();
        using var factory = CreateFactory(backend);
        using var client = factory.CreateClient();

        for (var i = 0; i < 5; i++)
        {
            client.DefaultRequestHeaders.Authorization = Basic("alice", $"wrong{i}");
            using var response = await client.GetAsync("/api/v1/agent");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        Assert.Equal(5, backend.Calls);

        // Even the CORRECT password is refused while locked, and the backend is not consulted.
        client.DefaultRequestHeaders.Authorization = Basic("alice", "right");
        using var locked = await client.GetAsync("/api/v1/agent");
        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);
        Assert.Equal(5, backend.Calls);

        // Another account is unaffected.
        client.DefaultRequestHeaders.Authorization = Basic("bob", "right");
        using var other = await client.GetAsync("/api/v1/agent");
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task FormLogin_AfterFiveFailures_IsRefusedWithoutAnOsLogon()
    {
        var backend = new CountingBackend();
        using var factory = CreateFactory(backend);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        static HttpRequestMessage Login(string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/login")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["username"] = "carol",
                    ["password"] = password,
                }),
            };
            request.Headers.Add("Sec-Fetch-Site", "same-origin");
            return request;
        }

        for (var i = 0; i < 5; i++)
        {
            using var response = await client.SendAsync(Login($"wrong{i}"));
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        }
        Assert.Equal(5, backend.Calls);

        using var locked = await client.SendAsync(Login("right"));
        Assert.Equal(HttpStatusCode.Redirect, locked.StatusCode);
        Assert.StartsWith("/login?error=", locked.Headers.Location?.ToString());
        Assert.False(locked.Headers.Contains("Set-Cookie"));
        Assert.Equal(5, backend.Calls);
    }
}
using System.Net;
using System.Net.Http;

using AcmeManager.Core.Authentication;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AcmeManager.Tests.Integration;

/// <summary>
/// Covers the hardening on the cookie-issuing <c>/api/login</c> endpoint: the
/// login-CSRF (same-site) guard and the per-IP rate limit. Auth is stubbed to
/// always fail, so a successful login is never required to observe the gate.
/// </summary>
public sealed class LoginSecurityTests
{
    private static WebApplicationFactory<Program> CreateFactory()
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-login-it-{Guid.NewGuid():N}.db");
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Storage:DatabaseFile", dbFile);
            builder.UseSetting("Web:AllowAnonymous", "false");
            builder.UseSetting("Auth:EnableNegotiate", "false");
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IAuthBackend>();
                services.AddSingleton<IAuthBackend>(new AlwaysFailAuthBackend());
            });
        });
    }

    private sealed class AlwaysFailAuthBackend : IAuthBackend
    {
        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            ValueTask.FromResult(AuthResult.Fail("denied"));
    }

    private static HttpRequestMessage Login(string fetchSite)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "admin",
                ["password"] = "pw",
            }),
        };
        request.Headers.Add("Sec-Fetch-Site", fetchSite);
        return request;
    }

    [Fact]
    public async Task Login_FromCrossSiteOrigin_IsRejected()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await client.SendAsync(Login("cross-site"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Login_FromSameOrigin_PassesCsrfGate()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await client.SendAsync(Login("same-origin"));

        // Auth fails, so the endpoint redirects back to /login — the point is that the
        // CSRF guard let the request THROUGH (not a 403).
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Login_ExceedingTheRateLimit_Returns429()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        // The login policy allows 10 attempts per window; the 11th must be throttled.
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 11; i++)
        {
            using var response = await client.SendAsync(Login("same-origin"));
            statuses.Add(response.StatusCode);
        }

        Assert.Contains(HttpStatusCode.Redirect, statuses);              // early attempts allowed through
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[^1]);      // last one throttled
    }
}
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;

using AcmeManager.Api.Contracts;
using AcmeManager.Core.Authentication;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AcmeManager.Tests.Integration;

/// <summary>The coverage and AD CS endpoints the console's estate view reads.</summary>
public sealed class CoverageApiTests
{
    [Fact]
    public async Task Coverage_ReturnsAReport_AndRequiresAuth()
    {
        using var factory = CreateFactory();
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(ApiV1.Coverage)).StatusCode);

        using var client = CreateAuthedClient(factory);
        var response = await client.GetAsync(ApiV1.Coverage);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var report = await response.Content.ReadFromJsonAsync<CoverageReportDto>();
        Assert.NotNull(report);
        Assert.NotNull(report.Entries);
        // On a Windows host without IIS the report is empty; on Linux without an
        // haproxy.cfg it carries an error. Either way it is a well-formed report.
        Assert.True(report.Error is null || report.Error.Contains("not found"));
    }

    [Fact]
    public async Task AdcsCertificates_IsEmpty_WhenNoCaIsConfigured()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);

        var certs = await client.GetFromJsonAsync<List<AdcsCertificateDto>>(ApiV1.AdcsCertificates);

        Assert.NotNull(certs);
        Assert.Empty(certs);
    }

    private static WebApplicationFactory<Program> CreateFactory()
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-cov-it-{Guid.NewGuid():N}.db");
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Storage:DatabaseFile", dbFile);
            builder.UseSetting("Web:AllowAnonymous", "false");
            builder.UseSetting("Auth:EnableNegotiate", "false");
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IAuthBackend>();
                services.AddSingleton<IAuthBackend>(new AlwaysAdminAuthBackend());
            });
        });
    }

    private static HttpClient CreateAuthedClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:pw")));
        return client;
    }

    private sealed class AlwaysAdminAuthBackend : IAuthBackend
    {
        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            ValueTask.FromResult(AuthResult.Ok(username, ["BUILTIN\\Administrators"]));
    }
}
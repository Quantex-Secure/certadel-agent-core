using System.Net;
using System.Net.Http.Headers;
using System.Text;

using AcmeManager.Core.Authentication;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AcmeManager.Tests.Integration;

/// <summary>DELETE /api/v1/renewals/{id} through the full middleware stack.</summary>
public sealed class RenewalDeleteApiTests
{
    [Fact]
    public async Task DeleteRenewal_RemovesIt_AndReturns204()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var id = await SeedRenewalAsync(factory);

        var response = await client.DeleteAsync($"/api/v1/renewals/{id}");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var follow = await client.GetAsync($"/api/v1/renewals/{id}");
        Assert.Equal(HttpStatusCode.NotFound, follow.StatusCode);
    }

    [Fact]
    public async Task DeleteRenewal_UnknownId_Returns404()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);

        var response = await client.DeleteAsync($"/api/v1/renewals/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static WebApplicationFactory<Program> CreateFactory()
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-it-{Guid.NewGuid():N}.db");
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

    private static async Task<Guid> SeedRenewalAsync(WebApplicationFactory<Program> factory)
    {
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        var account = new Account { Name = "test", DirectoryUrl = "https://ca.test/dir" };
        db.Accounts.Add(account);
        var renewal = new Renewal
        {
            Name = $"delete-api-test-{Guid.NewGuid():N}",
            AccountId = account.Id,
            SourceJson = """{"pluginId":"source.manual","options":{}}""",
            ValidationJson = """{"pluginId":"validation.dns-01.manual","options":{}}""",
        };
        db.Renewals.Add(renewal);
        await db.SaveChangesAsync();
        return renewal.Id;
    }

    private sealed class AlwaysAdminAuthBackend : IAuthBackend
    {
        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            ValueTask.FromResult(AuthResult.Ok(username, ["BUILTIN\\Administrators"]));
    }
}
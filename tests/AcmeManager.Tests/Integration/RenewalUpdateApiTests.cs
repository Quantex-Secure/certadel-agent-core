using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;

using AcmeManager.Api.Contracts;
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

/// <summary>PUT /api/v1/renewals/{id} with the expanded edit surface (plugin steps + account).</summary>
public sealed class RenewalUpdateApiTests
{
    [Fact]
    public async Task Update_ChangesPluginSteps()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory);

        var newSource = """{"pluginId":"source.manual","options":{"identifiers":["changed.test"]}}""";
        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}",
            new UpdateRenewalRequest(SourceJson: newSource));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var config = await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config");
        Assert.Contains("changed.test", config!.SourceJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Update_RejectsPluginInWrongSlot()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory);

        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}",
            new UpdateRenewalRequest(SourceJson: """{"pluginId":"store.winstore","options":{}}"""));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Update_ChangesAccount_WhenValid()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory);
        var otherAccountId = Guid.Empty;
        await Seed(factory, db =>
        {
            var a = new Account { Name = "Other", DirectoryUrl = "https://ca2.test/dir" };
            db.Accounts.Add(a);
            otherAccountId = a.Id;
        });

        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}",
            new UpdateRenewalRequest(AccountId: otherAccountId));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var config = await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config");
        Assert.Equal(otherAccountId, config!.AccountId);
    }

    [Fact]
    public async Task Update_RejectsUnknownAccount()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory);

        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}",
            new UpdateRenewalRequest(AccountId: Guid.NewGuid()));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static async Task<(Guid RenewalId, Guid AccountId)> SeedAsync(WebApplicationFactory<Program> factory)
    {
        var renewalId = Guid.Empty;
        var accountId = Guid.Empty;
        await Seed(factory, db =>
        {
            var account = new Account { Name = "a", DirectoryUrl = "https://ca.test/dir" };
            db.Accounts.Add(account);
            var renewal = new Renewal
            {
                Name = "edit-test",
                AccountId = account.Id,
                SourceJson = """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
                ValidationJson = """{"pluginId":"validation.dns-01.manual","options":{}}""",
            };
            db.Renewals.Add(renewal);
            renewalId = renewal.Id;
            accountId = account.Id;
        });
        return (renewalId, accountId);
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

    private static async Task Seed(WebApplicationFactory<Program> factory, Action<AcmeManagerDbContext> seed)
    {
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        seed(db);
        await db.SaveChangesAsync();
    }

    private sealed class AlwaysAdminAuthBackend : IAuthBackend
    {
        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            ValueTask.FromResult(AuthResult.Ok(username, ["BUILTIN\\Administrators"]));
    }
}
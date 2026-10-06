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

/// <summary>POST /api/v1/renewals (request a certificate) through the full stack.</summary>
public sealed class RenewalCreateApiTests
{
    private const string ManualSource = """{"pluginId":"source.manual","options":{"identifiers":["create-api.test"]}}""";
    private const string ManualDns = """{"pluginId":"validation.dns-01.manual","options":{}}""";

    [Fact]
    public async Task Create_ValidRequest_Returns201_AndPersists()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var accountId = await SeedAccountAsync(factory);
        var request = new CreateRenewalRequest(
            Name: "created-via-api",
            AccountId: accountId,
            SourceJson: ManualSource,
            ValidationJson: ManualDns,
            RenewalWindowDays: 21);

        var response = await client.PostAsJsonAsync("/api/v1/renewals", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var dto = await response.Content.ReadFromJsonAsync<RenewalDetailDto>();
        Assert.NotNull(dto);
        Assert.Equal("created-via-api", dto!.Name);
        Assert.Equal("source.manual", dto.SourcePluginId);
        Assert.Equal(21, dto.RenewalWindowDays);
        Assert.True(dto.Enabled);

        var follow = await client.GetAsync(response.Headers.Location);
        Assert.Equal(HttpStatusCode.OK, follow.StatusCode);
    }

    [Fact]
    public async Task Create_UnknownPlugin_Returns400()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var accountId = await SeedAccountAsync(factory);
        var request = new CreateRenewalRequest(
            Name: "bad-plugin",
            AccountId: accountId,
            SourceJson: """{"pluginId":"source.does-not-exist","options":{}}""",
            ValidationJson: ManualDns);

        var response = await client.PostAsJsonAsync("/api/v1/renewals", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Create_PluginInWrongSlot_Returns400()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var accountId = await SeedAccountAsync(factory);
        var request = new CreateRenewalRequest(
            Name: "wrong-slot",
            AccountId: accountId,
            SourceJson: """{"pluginId":"store.pfx","options":{}}""", // a Store plugin in the Source slot
            ValidationJson: ManualDns);

        var response = await client.PostAsJsonAsync("/api/v1/renewals", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Create_DuplicateName_Returns409()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var accountId = await SeedAccountAsync(factory);
        var request = new CreateRenewalRequest(
            Name: "duplicate-name",
            AccountId: accountId,
            SourceJson: ManualSource,
            ValidationJson: ManualDns);

        var first = await client.PostAsJsonAsync("/api/v1/renewals", request);
        var second = await client.PostAsJsonAsync("/api/v1/renewals", request);

        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Create_UnknownAccount_Returns400()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var request = new CreateRenewalRequest(
            Name: "no-account",
            AccountId: Guid.NewGuid(),
            SourceJson: ManualSource,
            ValidationJson: ManualDns);

        var response = await client.PostAsJsonAsync("/api/v1/renewals", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
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

    private static async Task<Guid> SeedAccountAsync(WebApplicationFactory<Program> factory)
    {
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        var account = new Account { Name = "test", DirectoryUrl = "https://ca.test/dir" };
        db.Accounts.Add(account);
        await db.SaveChangesAsync();
        return account.Id;
    }

    private sealed class AlwaysAdminAuthBackend : IAuthBackend
    {
        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            ValueTask.FromResult(AuthResult.Ok(username, ["BUILTIN\\Administrators"]));
    }
}
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;

using AcmeManager.Api.Contracts;
using AcmeManager.Core.Authentication;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Plugins.Contracts;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AcmeManager.Tests.Integration;

/// <summary>
/// Credential-valued options through the real API: never returned, restored on
/// a redacted round-trip, refused when set literally or copied from elsewhere.
/// </summary>
public sealed class SensitiveOptionsApiTests
{
    private const string StoredStores =
        """[{"pluginId":"store.pfx","options":{"filePath":"C:\\certs\\a.pfx","password":"hunter2"}}]""";

    [Fact]
    public async Task Config_NeverReturnsTheLiteralPassword()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory, StoredStores);

        var config = await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config");

        Assert.DoesNotContain("hunter2", config!.StoresJson);
        Assert.Contains(SensitiveOptionAttribute.RedactedValue, config.StoresJson);
        Assert.Contains("a.pfx", config.StoresJson);
    }

    [Fact]
    public async Task Update_RoundTrippingTheRedactedConfig_KeepsTheStoredPassword()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory, StoredStores);
        var config = await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config");

        // Edit the path, echo the placeholder — exactly what the console does.
        var edited = config!.StoresJson.Replace("a.pfx", "b.pfx");
        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}", new UpdateRenewalRequest(StoresJson: edited));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var stored = await ReadStoresAsync(factory, id);
        Assert.Contains("hunter2", stored);
        Assert.Contains("b.pfx", stored);
        Assert.DoesNotContain(SensitiveOptionAttribute.RedactedValue, stored);
    }

    [Fact]
    public async Task Update_WithANewLiteralPassword_IsRefused()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory, StoredStores);

        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}", new UpdateRenewalRequest(
            StoresJson: """[{"pluginId":"store.pfx","options":{"filePath":"C:\\certs\\a.pfx","password":"newpw"}}]"""));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ApiError>();
        Assert.Contains("secret", error!.Message);
        Assert.Contains("hunter2", await ReadStoresAsync(factory, id)); // unchanged
    }

    [Fact]
    public async Task Update_EchoingTheLegacyLiteralUnchanged_IsAllowed()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory, StoredStores);

        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}",
            new UpdateRenewalRequest(StoresJson: StoredStores, RenewalWindowDays: 45));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Update_PlaceholderForAStepThatWasNotStored_IsRefused()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (id, _) = await SeedAsync(factory, StoredStores);

        // Two redacted store.pfx steps sent, one stored: the second has nothing to restore from.
        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}", new UpdateRenewalRequest(
            StoresJson: """[{"pluginId":"store.pfx","options":{"filePath":"a.pfx","password":"********"}},{"pluginId":"store.pfx","options":{"filePath":"b.pfx","password":"********"}}]"""));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Create_WithALiteralPassword_IsRefused()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (_, accountId) = await SeedAsync(factory, "[]");

        var response = await client.PostAsJsonAsync("/api/v1/renewals", new CreateRenewalRequest(
            Name: "literal",
            AccountId: accountId,
            SourceJson: """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
            ValidationJson: """{"pluginId":"validation.dns-01.manual","options":{}}""",
            StoresJson: StoredStores,
            InstallationsJson: null,
            RenewalWindowDays: null,
            Enabled: null));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Create_WithACopiedPlaceholder_IsRefused()
    {
        // Cross-server migrate copies a redacted config; the credential didn't travel.
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (_, accountId) = await SeedAsync(factory, "[]");

        var response = await client.PostAsJsonAsync("/api/v1/renewals", new CreateRenewalRequest(
            Name: "migrated",
            AccountId: accountId,
            SourceJson: """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
            ValidationJson: """{"pluginId":"validation.dns-01.manual","options":{}}""",
            StoresJson: """[{"pluginId":"store.pfx","options":{"filePath":"a.pfx","password":"********"}}]""",
            InstallationsJson: null,
            RenewalWindowDays: null,
            Enabled: null));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<ApiError>();
        Assert.Contains("does not travel", error!.Message);
    }

    [Fact]
    public async Task Create_WithASecretReference_IsAccepted()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var (_, accountId) = await SeedAsync(factory, "[]");

        var response = await client.PostAsJsonAsync("/api/v1/renewals", new CreateRenewalRequest(
            Name: "by-secret",
            AccountId: accountId,
            SourceJson: """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
            ValidationJson: """{"pluginId":"validation.dns-01.manual","options":{}}""",
            StoresJson: """[{"pluginId":"store.pfx","options":{"filePath":"a.pfx","passwordSecretName":"pfx-pw"}}]""",
            InstallationsJson: null,
            RenewalWindowDays: null,
            Enabled: null));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    // ---------------- harness ----------------

    private static async Task<string> ReadStoresAsync(WebApplicationFactory<Program> factory, Guid id)
    {
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        return (await db.Renewals.AsNoTracking().SingleAsync(r => r.Id == id)).StoresJson;
    }

    private static async Task<(Guid RenewalId, Guid AccountId)> SeedAsync(WebApplicationFactory<Program> factory, string storesJson)
    {
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        var account = new Account { Name = "a", DirectoryUrl = "https://ca.test/dir" };
        db.Accounts.Add(account);
        var renewal = new Renewal
        {
            Name = "sensitive-test",
            AccountId = account.Id,
            SourceJson = """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
            ValidationJson = """{"pluginId":"validation.dns-01.manual","options":{}}""",
            StoresJson = storesJson,
        };
        db.Renewals.Add(renewal);
        await db.SaveChangesAsync();
        return (renewal.Id, account.Id);
    }

    private static WebApplicationFactory<Program> CreateFactory()
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-sens-it-{Guid.NewGuid():N}.db");
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
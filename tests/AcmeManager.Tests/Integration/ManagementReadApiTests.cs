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

/// <summary>
/// The read endpoints the console needs to render create/edit forms:
/// /accounts, /secrets, /plugins, /renewals/{id}/config.
/// </summary>
public sealed class ManagementReadApiTests
{
    [Fact]
    public async Task GetAccounts_ReturnsSeededAccounts()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        await SeedAsync(factory, db => db.Accounts.Add(new Account
        {
            Name = "LE-Prod",
            DirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory",
            ContactEmail = "ops@example.com",
        }));

        var accounts = await client.GetFromJsonAsync<List<AccountSummaryDto>>("/api/v1/accounts");

        var account = Assert.Single(accounts!);
        Assert.Equal("LE-Prod", account.Name);
        Assert.Equal("ops@example.com", account.ContactEmail);
    }

    [Fact]
    public async Task GetSecrets_ReturnsNamesOnly()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        await SeedAsync(factory, db => db.Secrets.Add(new Secret
        {
            Name = "Azure",
            EncryptedValue = [1, 2, 3], // must never be returned
        }));

        var response = await client.GetAsync("/api/v1/secrets");
        var names = await response.Content.ReadFromJsonAsync<List<string>>();
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(["Azure"], names);
        // The encrypted value bytes must not leak in any form.
        Assert.DoesNotContain("EncryptedValue", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetPlugins_DescribesOptionSchemas()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);

        var plugins = await client.GetFromJsonAsync<List<PluginDescriptorDto>>("/api/v1/plugins");

        Assert.NotNull(plugins);
        // Manual source exposes an identifiers string-list field.
        var manual = Assert.Single(plugins!, p => p.Id == "source.manual");
        Assert.Equal("Source", manual.Category);
        Assert.Contains(manual.Options, o => o.Name == "identifiers" && o.Type == PluginOptionFieldTypes.StringList);

        // Azure DNS validation exposes a masked secret-reference field.
        var azure = Assert.Single(plugins!, p => p.Id == "validation.dns-01.azure");
        var secretField = Assert.Single(azure.Options, o => o.Type == PluginOptionFieldTypes.SecretRef);
        Assert.True(secretField.IsSecret);

        // The Windows store exposes Location as an enum and StoreName as a cert-store picker.
        var winstore = Assert.Single(plugins!, p => p.Id == "store.winstore");
        Assert.Contains(winstore.Options, o => o.Type == PluginOptionFieldTypes.Enum && o.EnumValues is { Count: > 0 });
        Assert.Contains(winstore.Options, o => o.Name == "storeName" && o.Type == PluginOptionFieldTypes.CertStoreRef);
    }

    [Fact]
    public async Task GetRenewalConfig_ReturnsRawStepJson()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var id = Guid.Empty;
        await SeedAsync(factory, db =>
        {
            var account = new Account { Name = "a", DirectoryUrl = "https://ca.test/dir" };
            db.Accounts.Add(account);
            var renewal = new Renewal
            {
                Name = "config-test",
                AccountId = account.Id,
                SourceJson = """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
                ValidationJson = """{"pluginId":"validation.dns-01.manual","options":{}}""",
                StoresJson = """[{"pluginId":"store.winstore","options":{}}]""",
            };
            db.Renewals.Add(renewal);
            id = renewal.Id;
        });

        var config = await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config");

        Assert.NotNull(config);
        Assert.Equal("config-test", config!.Name);
        Assert.Contains("source.manual", config.SourceJson, StringComparison.Ordinal);
        Assert.Contains("store.winstore", config.StoresJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetRenewalConfig_UnknownId_Returns404()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);

        var response = await client.GetAsync($"/api/v1/renewals/{Guid.NewGuid()}/config");

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

    private static async Task SeedAsync(WebApplicationFactory<Program> factory, Action<AcmeManagerDbContext> seed)
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
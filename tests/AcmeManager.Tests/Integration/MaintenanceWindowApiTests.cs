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

/// <summary>Maintenance windows through the management API: set on create, changed and cleared on update, refused when malformed.</summary>
public sealed class MaintenanceWindowApiTests
{
    private const string Weekend = """{"days":["saturday","sunday"],"start":"01:00","end":"05:00","timeZone":"UTC"}""";

    [Fact]
    public async Task Create_StoresTheWindow_AndConfigAndDetailReportIt()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var accountId = await SeedAccountAsync(factory);

        var response = await client.PostAsJsonAsync("/api/v1/renewals", new CreateRenewalRequest(
            Name: "windowed", AccountId: accountId,
            SourceJson: """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
            ValidationJson: """{"pluginId":"validation.dns-01.manual","options":{}}""",
            MaintenanceWindowJson: Weekend));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<RenewalDetailDto>();

        var config = await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{created!.Id}/config");
        Assert.Contains("saturday", config!.MaintenanceWindowJson);
        var detail = await client.GetFromJsonAsync<RenewalDetailDto>($"/api/v1/renewals/{created.Id}");
        Assert.Equal("Sun, Sat 01:00–05:00 (UTC)", detail!.MaintenanceWindow);
    }

    [Fact]
    public async Task Update_ChangesAndClearsTheWindow()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var id = await SeedRenewalAsync(factory, Weekend);

        var changed = await client.PutAsJsonAsync($"/api/v1/renewals/{id}", new UpdateRenewalRequest(
            MaintenanceWindowJson: """{"days":["monday"],"start":"22:00","end":"23:00"}"""));
        Assert.Equal(HttpStatusCode.NoContent, changed.StatusCode);
        Assert.Contains("monday", (await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config"))!.MaintenanceWindowJson);

        var untouched = await client.PutAsJsonAsync($"/api/v1/renewals/{id}", new UpdateRenewalRequest(RenewalWindowDays: 40));
        Assert.Equal(HttpStatusCode.NoContent, untouched.StatusCode);
        Assert.Contains("monday", (await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config"))!.MaintenanceWindowJson);

        var cleared = await client.PutAsJsonAsync($"/api/v1/renewals/{id}", new UpdateRenewalRequest(MaintenanceWindowJson: ""));
        Assert.Equal(HttpStatusCode.NoContent, cleared.StatusCode);
        Assert.Null((await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config"))!.MaintenanceWindowJson);
    }

    [Fact]
    public async Task Update_RejectsAMalformedWindow_WithoutChangingAnything()
    {
        using var factory = CreateFactory();
        using var client = CreateAuthedClient(factory);
        var id = await SeedRenewalAsync(factory, Weekend);

        var response = await client.PutAsJsonAsync($"/api/v1/renewals/{id}", new UpdateRenewalRequest(
            MaintenanceWindowJson: """{"days":["funday"],"start":"01:00","end":"05:00"}"""));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("funday", (await response.Content.ReadFromJsonAsync<ApiError>())!.Message);
        Assert.Contains("saturday", (await client.GetFromJsonAsync<RenewalConfigDto>($"/api/v1/renewals/{id}/config"))!.MaintenanceWindowJson);
    }

    // ---------------- harness ----------------

    private static async Task<Guid> SeedAccountAsync(WebApplicationFactory<Program> factory)
    {
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        var account = new Account { Name = "a", DirectoryUrl = "https://ca.test/dir" };
        db.Accounts.Add(account);
        await db.SaveChangesAsync();
        return account.Id;
    }

    private static async Task<Guid> SeedRenewalAsync(WebApplicationFactory<Program> factory, string windowJson)
    {
        var dbf = factory.Services.GetRequiredService<IDbContextFactory<AcmeManagerDbContext>>();
        await using var db = await dbf.CreateDbContextAsync();
        var account = new Account { Name = "a", DirectoryUrl = "https://ca.test/dir" };
        db.Accounts.Add(account);
        var renewal = new Renewal
        {
            Name = "windowed",
            AccountId = account.Id,
            SourceJson = """{"pluginId":"source.manual","options":{"identifiers":["x.test"]}}""",
            ValidationJson = """{"pluginId":"validation.dns-01.manual","options":{}}""",
            MaintenanceWindowJson = windowJson,
        };
        db.Renewals.Add(renewal);
        await db.SaveChangesAsync();
        return renewal.Id;
    }

    private static WebApplicationFactory<Program> CreateFactory()
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-window-it-{Guid.NewGuid():N}.db");
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
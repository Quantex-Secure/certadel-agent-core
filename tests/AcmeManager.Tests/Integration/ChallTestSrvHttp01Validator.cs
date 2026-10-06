using System.Net.Http;
using System.Net.Http.Json;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

namespace AcmeManager.Tests.Integration;

/// <summary>Empty options — this validator is fully configured by its injected mgmt client.</summary>
public sealed record ChallTestSrvHttp01Options : PluginOptions;

/// <summary>
/// Test-only <see cref="IValidator"/> that drives <c>pebble-challtestsrv</c>'s
/// HTTP-01 mock via its management REST API. Lets us exercise the engine
/// end-to-end without spinning up a real HTTP server in the test process.
/// </summary>
public sealed class ChallTestSrvHttp01Validator(HttpClient mgmtClient) : IValidator
{
    public PluginMetadata Metadata { get; } = new(
        Id: "test.validator.challtestsrv.http01",
        Name: "challtestsrv HTTP-01",
        Description: "Drives pebble-challtestsrv to publish HTTP-01 responses",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0));

    public ChallengeType ChallengeType => ChallengeType.Http01;

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        using var resp = await mgmtClient.PostAsJsonAsync(
            "/add-http01",
            new { token = ctx.Token, content = ctx.KeyAuthorization },
            ct);
        resp.EnsureSuccessStatusCode();
    }

    public async ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        using var resp = await mgmtClient.PostAsJsonAsync(
            "/del-http01",
            new { token = ctx.Token },
            ct);
        // Best-effort cleanup — Pebble may already have moved past it.
        if (!resp.IsSuccessStatusCode)
        {
            return;
        }
    }
}
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using AcmeManager.Api.Contracts;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AcmeManager.Tests.Integration;

/// <summary>
/// The anonymous identity surface a console relies on to survive endpoint
/// certificate rotation: the well-known identity publishes the node key, and
/// the attest route signs the caller's nonce with it.
/// </summary>
public sealed class NodeAttestationEndpointTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private static WebApplicationFactory<Program> CreateFactory()
    {
        var dbFile = Path.Combine(Path.GetTempPath(), $"acme-attest-it-{Guid.NewGuid():N}.db");
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Storage:DatabaseFile", dbFile);
            builder.UseSetting("Web:AllowAnonymous", "false");
            builder.UseSetting("Auth:EnableNegotiate", "false");
        });
    }

    private sealed record Identity(string Product, Guid NodeId, string? NodeKey);

    [Fact]
    public async Task WellKnown_PublishesTheNodeKey_AndAttestVerifiesAgainstIt()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        var identity = await client.GetFromJsonAsync<Identity>("/.well-known/acme-manager", Json);
        Assert.NotNull(identity);
        Assert.False(string.IsNullOrWhiteSpace(identity.NodeKey));

        var nonce = NodeAttestation.NewNonce();
        var statement = await client.GetFromJsonAsync<NodeAttestationDto>(
            $"{NodeAttestation.Path}?nonce={Uri.EscapeDataString(nonce)}", Json);

        Assert.NotNull(statement);
        Assert.Equal(identity.NodeId, statement.NodeId);
        Assert.Equal(nonce, statement.Nonce);
        Assert.Equal(64, statement.EndpointCertSha256.Length);
        Assert.True(NodeAttestation.Verify(identity.NodeKey!, statement), "attestation must verify with the published node key");
    }

    [Fact]
    public async Task NodeKey_IsStableAcrossRequests()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        var first = await client.GetFromJsonAsync<Identity>("/.well-known/acme-manager", Json);
        var second = await client.GetFromJsonAsync<Identity>("/.well-known/acme-manager", Json);

        Assert.Equal(first!.NodeKey, second!.NodeKey);
    }

    [Theory]
    [InlineData("")]
    [InlineData("AAAA")]
    [InlineData("not base64url!!")]
    public async Task Attest_RejectsABadNonce(string nonce)
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        var response = await client.GetAsync($"{NodeAttestation.Path}?nonce={Uri.EscapeDataString(nonce)}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Attest_DoesNotSignSomeoneElsesNonce()
    {
        // A statement for one nonce must not verify as a statement for another —
        // that's the replay protection the console relies on.
        using var factory = CreateFactory();
        using var client = factory.CreateClient();
        var identity = await client.GetFromJsonAsync<Identity>("/.well-known/acme-manager", Json);

        var statement = await client.GetFromJsonAsync<NodeAttestationDto>(
            $"{NodeAttestation.Path}?nonce={Uri.EscapeDataString(NodeAttestation.NewNonce())}", Json);

        Assert.False(NodeAttestation.Verify(identity!.NodeKey!, statement! with { Nonce = NodeAttestation.NewNonce() }));
    }
}
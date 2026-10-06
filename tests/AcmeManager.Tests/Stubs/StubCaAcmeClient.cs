using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AcmeManager.Core.Acme;

namespace AcmeManager.Tests.Stubs;

/// <summary>
/// A full in-memory <see cref="IAcmeClient"/> that issues REAL certificates with
/// no network and no Pebble. It maintains a self-signed CA and drives the ACME
/// order state machine exactly as <c>OrderRunner</c> expects:
///
///   CreateOrder (Pending, one authz per identifier)
///     → per authz: GetAuthorization (Pending + one challenge)
///                  → SubmitChallenge (marks the authz Valid)
///                  → GetAuthorization (Valid)
///     → RefreshOrder (Ready, once authorizations are done)
///     → FinalizeOrder (parses the CSR, signs a leaf for its public key)
///     → RefreshOrder (Valid)
///     → DownloadCertificate (leaf PEM + CA PEM chain)
///
/// The issued leaf carries the CSR's public key, so <c>OrderRunner</c>'s
/// <c>X509Certificate2.CreateFromPem(leafPem, privKeyPem)</c> matches the key it
/// generated and PFX assembly succeeds.
/// </summary>
internal sealed class StubCaAcmeClient : IAcmeClient, IDisposable
{
    private static readonly Uri BaseUri = new("https://stub-ca.test/");

    private readonly ECDsa _caKey;
    private readonly X509Certificate2 _ca;
    private readonly string _caPem;

    private readonly ConcurrentDictionary<Uri, OrderState> _orders = new();
    private readonly ConcurrentDictionary<Uri, AuthzState> _authorizations = new();

    public int FinalizeCalls { get; private set; }

    public StubCaAcmeClient()
    {
        _caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(
            new X500DistinguishedName("CN=Stub Test CA"), _caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var now = DateTimeOffset.UtcNow;
        _ca = caRequest.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));
        _caPem = _ca.ExportCertificatePem();
    }

    public Task<AcmeAccount> CreateAccountAsync(AcmeAccount unregistered, EabCredentials? eab, CancellationToken ct) =>
        Task.FromResult(unregistered with { KeyId = new Uri(BaseUri, "acct/1") });

    public Task<AcmeOrder> CreateOrderAsync(AcmeAccount account, IReadOnlyList<string> identifiers, CancellationToken ct)
    {
        var orderId = Guid.NewGuid().ToString("N");
        var orderUrl = new Uri(BaseUri, $"order/{orderId}");
        var finalizeUrl = new Uri(BaseUri, $"order/{orderId}/finalize");

        var authzUrls = new List<Uri>(identifiers.Count);
        foreach (var identifier in identifiers)
        {
            var authzUrl = new Uri(BaseUri, $"authz/{Guid.NewGuid():N}");
            var challenge = new AcmeChallenge(
                Url: new Uri(BaseUri, $"chall/{Guid.NewGuid():N}"),
                AuthorizationUrl: authzUrl,
                Type: AcmeChallengeTypes.Http01,
                Token: Guid.NewGuid().ToString("N"),
                Status: ChallengeStatus.Pending);
            _authorizations[authzUrl] = new AuthzState(identifier, challenge);
            authzUrls.Add(authzUrl);
        }

        _orders[orderUrl] = new OrderState(identifiers, authzUrls, finalizeUrl);

        return Task.FromResult(new AcmeOrder(
            Url: orderUrl,
            Status: OrderStatus.Pending,
            Identifiers: identifiers,
            AuthorizationUrls: authzUrls,
            FinalizeUrl: finalizeUrl,
            CertificateUrl: null,
            Expires: DateTimeOffset.UtcNow.AddDays(1)));
    }

    public Task<AcmeOrder> RefreshOrderAsync(AcmeAccount account, AcmeOrder order, CancellationToken ct)
    {
        var state = Lookup(order.Url);

        // Before finalize the order is Ready (all challenges auto-validate on submit);
        // after finalize it is Valid with the issued certificate available.
        if (!state.Finalized)
        {
            return Task.FromResult(order with { Status = OrderStatus.Ready });
        }

        return Task.FromResult(order with
        {
            Status = OrderStatus.Valid,
            CertificateUrl = new Uri(BaseUri, $"cert/{Guid.NewGuid():N}"),
        });
    }

    public Task<AcmeAuthorization> GetAuthorizationAsync(AcmeAccount account, Uri authorizationUrl, CancellationToken ct)
    {
        var state = _authorizations.TryGetValue(authorizationUrl, out var s)
            ? s
            : throw new InvalidOperationException($"Unknown authorization {authorizationUrl}");

        var status = state.Validated ? AuthorizationStatus.Valid : AuthorizationStatus.Pending;
        var challenge = state.Challenge with
        {
            Status = state.Validated ? ChallengeStatus.Valid : ChallengeStatus.Pending,
        };

        return Task.FromResult(new AcmeAuthorization(
            Url: authorizationUrl,
            Identifier: state.Identifier,
            Status: status,
            Challenges: [challenge],
            Expires: DateTimeOffset.UtcNow.AddDays(1)));
    }

    public string ComputeKeyAuthorization(AcmeAccount account, AcmeChallenge challenge) =>
        challenge.Token + ".stub-key-authorization";

    public string ComputeDnsTxtValue(AcmeAccount account, AcmeChallenge challenge) =>
        "stub-dns-txt-value";

    public Task<AcmeChallenge> SubmitChallengeAsync(AcmeAccount account, AcmeChallenge challenge, CancellationToken ct)
    {
        if (_authorizations.TryGetValue(challenge.AuthorizationUrl, out var state))
        {
            state.Validated = true;
        }

        return Task.FromResult(challenge with { Status = ChallengeStatus.Valid });
    }

    public Task<AcmeOrder> FinalizeOrderAsync(AcmeAccount account, AcmeOrder order, byte[] csrDer, CancellationToken ct)
    {
        FinalizeCalls++;
        var state = Lookup(order.Url);

        var csr = CertificateRequest.LoadSigningRequest(csrDer, HashAlgorithmName.SHA256);

        // Re-issue a leaf for the CSR's public key + subject, signed by the CA.
        // Reusing the CSR's public key is what makes the downloaded chain pair up
        // with the private key OrderRunner generated.
        var leafRequest = new CertificateRequest(csr.SubjectName, csr.PublicKey, HashAlgorithmName.SHA256);

        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var identifier in state.Identifiers)
        {
            sanBuilder.AddDnsName(identifier);
        }
        leafRequest.CertificateExtensions.Add(sanBuilder.Build());
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        var now = DateTimeOffset.UtcNow;
        using var leaf = leafRequest.Create(_ca, now.AddMinutes(-5), now.AddDays(90), NextSerial());
        state.LeafPem = leaf.ExportCertificatePem();
        state.Finalized = true;

        return Task.FromResult(order with { Status = OrderStatus.Valid });
    }

    public Task<string> DownloadCertificateAsync(AcmeAccount account, AcmeOrder order, CancellationToken ct)
    {
        var state = Lookup(order.Url);
        var leafPem = state.LeafPem
            ?? throw new InvalidOperationException($"Order {order.Url} was not finalized before download");

        return Task.FromResult(leafPem + "\n" + _caPem + "\n");
    }

    public Task<AcmeDirectory> GetDirectoryAsync(Uri directoryUrl, CancellationToken ct) =>
        Task.FromResult(new AcmeDirectory(directoryUrl, TermsOfServiceUrl: null, ExternalAccountRequired: false));

    public void Dispose()
    {
        _ca.Dispose();
        _caKey.Dispose();
    }

    private OrderState Lookup(Uri orderUrl) =>
        _orders.TryGetValue(orderUrl, out var state)
            ? state
            : throw new InvalidOperationException($"Unknown order {orderUrl}");

    private static byte[] NextSerial()
    {
        var serial = new byte[9];
        RandomNumberGenerator.Fill(serial.AsSpan(1));
        serial[0] = 0x01; // keep it positive and non-empty
        return serial;
    }

    private sealed class OrderState(
        IReadOnlyList<string> identifiers, IReadOnlyList<Uri> authzUrls, Uri finalizeUrl)
    {
        public IReadOnlyList<string> Identifiers { get; } = identifiers;

        public IReadOnlyList<Uri> AuthzUrls { get; } = authzUrls;

        public Uri FinalizeUrl { get; } = finalizeUrl;

        public bool Finalized { get; set; }

        public string? LeafPem { get; set; }
    }

    private sealed class AuthzState(string identifier, AcmeChallenge challenge)
    {
        public string Identifier { get; } = identifier;

        public AcmeChallenge Challenge { get; } = challenge;

        public bool Validated { get; set; }
    }
}

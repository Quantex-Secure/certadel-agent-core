using AcmeManager.Core.Acme;

namespace AcmeManager.Tests.Stubs;

/// <summary>
/// Hand-rolled stub for <see cref="IAcmeClient"/> — only the methods the unit
/// tests exercise are implemented; everything else throws. Use this for
/// AccountService-style tests where the ACME protocol layer is out of scope.
/// </summary>
internal sealed class StubAcmeClient : IAcmeClient
{
    public Uri DefaultKeyId { get; init; } = new("https://stub-ca.test/acct/1");

    public int CreateAccountCalls { get; private set; }

    public Task<AcmeAccount> CreateAccountAsync(AcmeAccount unregistered, EabCredentials? eab, CancellationToken ct)
    {
        CreateAccountCalls++;
        return Task.FromResult(unregistered with { KeyId = DefaultKeyId });
    }

    public Task<AcmeDirectory> GetDirectoryAsync(Uri directoryUrl, CancellationToken ct) =>
        throw new NotImplementedException();

    public Task<AcmeOrder> CreateOrderAsync(AcmeAccount account, IReadOnlyList<string> identifiers, CancellationToken ct) =>
        throw new NotImplementedException();

    public Task<AcmeOrder> RefreshOrderAsync(AcmeAccount account, AcmeOrder order, CancellationToken ct) =>
        throw new NotImplementedException();

    public Task<AcmeAuthorization> GetAuthorizationAsync(AcmeAccount account, Uri authorizationUrl, CancellationToken ct) =>
        throw new NotImplementedException();

    public string ComputeKeyAuthorization(AcmeAccount account, AcmeChallenge challenge) =>
        throw new NotImplementedException();

    public string ComputeDnsTxtValue(AcmeAccount account, AcmeChallenge challenge) =>
        throw new NotImplementedException();

    public Task<AcmeChallenge> SubmitChallengeAsync(AcmeAccount account, AcmeChallenge challenge, CancellationToken ct) =>
        throw new NotImplementedException();

    public Task<AcmeOrder> FinalizeOrderAsync(AcmeAccount account, AcmeOrder order, byte[] csrDer, CancellationToken ct) =>
        throw new NotImplementedException();

    public Task<string> DownloadCertificateAsync(AcmeAccount account, AcmeOrder order, CancellationToken ct) =>
        throw new NotImplementedException();
}
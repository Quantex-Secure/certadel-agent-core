using Certes;
using Certes.Acme;

using Microsoft.Extensions.Logging;

using CertesAuthorizationStatus = Certes.Acme.Resource.AuthorizationStatus;
using CertesChallengeStatus = Certes.Acme.Resource.ChallengeStatus;
using CertesOrderStatus = Certes.Acme.Resource.OrderStatus;

namespace AcmeManager.Core.Acme;

/// <summary>
/// <see cref="IAcmeClient"/> implementation backed by the Certes library.
/// Kept stateless — every call rebuilds the Certes context from the account
/// + URL inputs, so the host can persist accounts/orders as plain data.
/// </summary>
/// <param name="logger">Standard logger.</param>
/// <param name="contextFactory">
/// Optional override that constructs the <c>AcmeContext</c>. Lets tests
/// supply a Pebble-trusting <c>HttpClient</c> via <c>AcmeHttpClient</c>
/// without globally weakening TLS validation.
/// </param>
public sealed class CertesAcmeClient(
    ILogger<CertesAcmeClient> logger,
    Func<Uri, IKey?, AcmeContext>? contextFactory = null) : IAcmeClient
{
    private readonly Func<Uri, IKey?, AcmeContext> _newContext =
        contextFactory ?? ((url, key) => new AcmeContext(url, key));

    public async Task<AcmeDirectory> GetDirectoryAsync(Uri directoryUrl, CancellationToken ct)
    {
        return await RetryAsync(async () =>
        {
            var acme = _newContext(directoryUrl, null);
            var dir = await acme.GetDirectory();

            return new AcmeDirectory(
                DirectoryUrl: directoryUrl,
                TermsOfServiceUrl: dir.Meta?.TermsOfService,
                ExternalAccountRequired: dir.Meta?.ExternalAccountRequired ?? false);
        }, ct);
    }

    public async Task<AcmeAccount> CreateAccountAsync(
        AcmeAccount unregistered,
        EabCredentials? eab,
        CancellationToken ct)
    {
        var key = KeyFactory.FromPem(unregistered.Key.Pem);

        var location = await RetryAsync(async () =>
        {
            var acme = _newContext(unregistered.DirectoryUrl, key);
            var accountCtx = eab is not null
                ? await acme.NewAccount(
                    contact: ["mailto:" + unregistered.ContactEmail],
                    termsOfServiceAgreed: true,
                    eabKeyId: eab.KeyId,
                    eabKey: eab.HmacKeyBase64Url)
                : await acme.NewAccount(unregistered.ContactEmail, termsOfServiceAgreed: true);
            return accountCtx.Location;
        }, ct);

        logger.LogInformation(
            "Registered account at {Directory}, KeyId={KeyId}", unregistered.DirectoryUrl, location);

        return unregistered with { KeyId = location };
    }

    public async Task<AcmeOrder> CreateOrderAsync(
        AcmeAccount account,
        IReadOnlyList<string> identifiers,
        CancellationToken ct)
    {
        return await RetryAsync(async () =>
        {
            var acme = ContextFor(account);
            var orderCtx = await acme.NewOrder([.. identifiers]);
            var resource = await orderCtx.Resource();
            return MapOrder(orderCtx.Location, resource);
        }, ct);
    }

    public async Task<AcmeOrder> RefreshOrderAsync(AcmeAccount account, AcmeOrder order, CancellationToken ct)
    {
        return await RetryAsync(async () =>
        {
            var acme = ContextFor(account);
            var orderCtx = acme.Order(order.Url);
            var resource = await orderCtx.Resource();
            return MapOrder(order.Url, resource);
        }, ct);
    }

    public async Task<AcmeAuthorization> GetAuthorizationAsync(
        AcmeAccount account,
        Uri authorizationUrl,
        CancellationToken ct)
    {
        return await RetryAsync(async () =>
        {
            var acme = ContextFor(account);
            var authzCtx = acme.Authorization(authorizationUrl);
            var resource = await authzCtx.Resource();

            var challenges = resource.Challenges
                .Select(ch => new AcmeChallenge(
                    Url: ch.Url,
                    AuthorizationUrl: authorizationUrl,
                    Type: ch.Type,
                    Token: ch.Token,
                    Status: MapChallengeStatus(ch.Status),
                    Error: ch.Error?.Detail))
                .ToList();

            return new AcmeAuthorization(
                Url: authorizationUrl,
                Identifier: resource.Identifier.Value,
                Status: MapAuthorizationStatus(resource.Status),
                Challenges: challenges,
                Expires: resource.Expires);
        }, ct);
    }

    public string ComputeKeyAuthorization(AcmeAccount account, AcmeChallenge challenge)
    {
        var key = KeyFactory.FromPem(account.Key.Pem);
        return key.KeyAuthorization(challenge.Token);
    }

    public string ComputeDnsTxtValue(AcmeAccount account, AcmeChallenge challenge)
    {
        var key = KeyFactory.FromPem(account.Key.Pem);
        return key.DnsTxt(challenge.Token);
    }

    public async Task<AcmeChallenge> SubmitChallengeAsync(
        AcmeAccount account,
        AcmeChallenge challenge,
        CancellationToken ct)
    {
        return await RetryAsync(async () =>
        {
            var acme = ContextFor(account);
            var authzCtx = acme.Authorization(challenge.AuthorizationUrl);
            var challengeCtxs = await authzCtx.Challenges();
            // Match by challenge TYPE, not token: Let's Encrypt/Boulder issues the same
            // token for every challenge in an authorization, so a token-only match can
            // (and did) select the wrong challenge — e.g. validating HTTP-01 when we
            // published a DNS-01 record. There is exactly one challenge per type.
            var matching = challengeCtxs.FirstOrDefault(c => c.Type == challenge.Type)
                ?? throw new InvalidOperationException(
                    $"Challenge of type '{challenge.Type}' not found at authorization {challenge.AuthorizationUrl}");

            var result = await matching.Validate();

            return new AcmeChallenge(
                Url: challenge.Url,
                AuthorizationUrl: challenge.AuthorizationUrl,
                Type: challenge.Type,
                Token: challenge.Token,
                Status: MapChallengeStatus(result.Status));
        }, ct);
    }

    public async Task<AcmeOrder> FinalizeOrderAsync(
        AcmeAccount account,
        AcmeOrder order,
        byte[] csrDer,
        CancellationToken ct)
    {
        var acme = ContextFor(account);
        var orderCtx = acme.Order(order.Url);
        // Retry Finalize and Resource INDEPENDENTLY: a transient blip on the poll
        // must not re-submit Finalize on an already-finalized order.
        await RetryAsync(async () => { await orderCtx.Finalize(csrDer); return true; }, ct);
        var resource = await RetryAsync(() => orderCtx.Resource(), ct);
        return MapOrder(order.Url, resource);
    }

    public async Task<string> DownloadCertificateAsync(
        AcmeAccount account,
        AcmeOrder order,
        CancellationToken ct)
    {
        var acme = ContextFor(account);
        var orderCtx = acme.Order(order.Url);
        var chain = await RetryAsync(() => orderCtx.Download(), ct);

        // Assemble the PEM from the chain the CA returned (leaf + issuers) verbatim.
        // Do NOT use chain.ToPem(): it re-derives the chain up to a root via Certes'
        // bundled CertificateStore (GetIssuers) and throws "Can not find issuer" when
        // that root is unknown to it — e.g. Let's Encrypt STAGING ("Pretend Pear").
        // We only need leaf + intermediates for the PFX; the root never goes in it.
        // IEncodable.ToPem() encodes a single cert (safe) — unlike the chain-level
        // CertificateChainExtensions.ToPem() that walks to a root.
        return AssembleChainPem(chain.Certificate.ToPem(), chain.Issuers.Select(i => i.ToPem()));
    }

    /// <summary>Concatenates the leaf and issuer PEM blocks into one chain PEM,
    /// each block trimmed and newline-terminated. No issuer resolution.</summary>
    internal static string AssembleChainPem(string leafPem, IEnumerable<string> issuerPems)
    {
        var builder = new System.Text.StringBuilder();
        builder.Append(leafPem.Trim()).Append('\n');
        foreach (var issuer in issuerPems)
        {
            builder.Append(issuer.Trim()).Append('\n');
        }
        return builder.ToString();
    }

    private AcmeContext ContextFor(AcmeAccount account)
    {
        var key = KeyFactory.FromPem(account.Key.Pem);
        return _newContext(account.DirectoryUrl, key);
    }

    private const int MaxAttempts = 4;

    /// <summary>
    /// Runs an ACME operation with a short exponential backoff (1s, 2s, 4s) on
    /// TRANSIENT errors — CA "Service busy"/503 and network blips that staging in
    /// particular throws. A hard rate limit (which carries a "retry after
    /// &lt;timestamp&gt;") is NOT retried — it propagates so the engine can pause.
    /// </summary>
    private async Task<T> RetryAsync<T>(Func<Task<T>> operation, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await operation();
            }
            catch (Exception ex) when (attempt < MaxAttempts && !ct.IsCancellationRequested && IsTransient(ex))
            {
                var delay = TimeSpan.FromSeconds(1 << (attempt - 1));
                logger.LogWarning(
                    "Transient ACME error (attempt {Attempt}/{Max}); retrying in {Delay}s: {Message}",
                    attempt, MaxAttempts, delay.TotalSeconds, ex.Message);
                await Task.Delay(delay, ct);
            }
        }
    }

    /// <summary>Transient = worth retrying (server busy / 503 / network timeout).
    /// A hard rate limit carries a parseable "retry after" time and is NOT transient.</summary>
    internal static bool IsTransient(Exception ex)
    {
        if (AcmeRateLimit.TryGetRetryAfter(ex, out _))
        {
            return false;
        }
        if (ex is HttpRequestException or TaskCanceledException)
        {
            return true;
        }
        var m = ex.Message;
        return m.Contains("Service busy", StringComparison.OrdinalIgnoreCase)
            || m.Contains("try again", StringComparison.OrdinalIgnoreCase)
            || m.Contains("retry later", StringComparison.OrdinalIgnoreCase)
            || m.Contains("timeout", StringComparison.OrdinalIgnoreCase)
            || m.Contains("timed out", StringComparison.OrdinalIgnoreCase)
            || m.Contains("temporarily", StringComparison.OrdinalIgnoreCase);
    }

    private static AcmeOrder MapOrder(Uri url, Certes.Acme.Resource.Order resource)
    {
        return new AcmeOrder(
            Url: url,
            Status: MapOrderStatus(resource.Status),
            Identifiers: resource.Identifiers.Select(i => i.Value).ToList(),
            AuthorizationUrls: resource.Authorizations.ToList(),
            FinalizeUrl: resource.Finalize,
            CertificateUrl: resource.Certificate,
            Expires: resource.Expires);
    }

    private static OrderStatus MapOrderStatus(CertesOrderStatus? s) => s switch
    {
        CertesOrderStatus.Pending => OrderStatus.Pending,
        CertesOrderStatus.Ready => OrderStatus.Ready,
        CertesOrderStatus.Processing => OrderStatus.Processing,
        CertesOrderStatus.Valid => OrderStatus.Valid,
        CertesOrderStatus.Invalid => OrderStatus.Invalid,
        _ => OrderStatus.Invalid,
    };

    private static AuthorizationStatus MapAuthorizationStatus(CertesAuthorizationStatus? s) => s switch
    {
        CertesAuthorizationStatus.Pending => AuthorizationStatus.Pending,
        CertesAuthorizationStatus.Valid => AuthorizationStatus.Valid,
        CertesAuthorizationStatus.Invalid => AuthorizationStatus.Invalid,
        CertesAuthorizationStatus.Deactivated => AuthorizationStatus.Deactivated,
        CertesAuthorizationStatus.Expired => AuthorizationStatus.Expired,
        CertesAuthorizationStatus.Revoked => AuthorizationStatus.Revoked,
        _ => AuthorizationStatus.Invalid,
    };

    private static ChallengeStatus MapChallengeStatus(CertesChallengeStatus? s) => s switch
    {
        CertesChallengeStatus.Pending => ChallengeStatus.Pending,
        CertesChallengeStatus.Processing => ChallengeStatus.Processing,
        CertesChallengeStatus.Valid => ChallengeStatus.Valid,
        CertesChallengeStatus.Invalid => ChallengeStatus.Invalid,
        _ => ChallengeStatus.Invalid,
    };
}
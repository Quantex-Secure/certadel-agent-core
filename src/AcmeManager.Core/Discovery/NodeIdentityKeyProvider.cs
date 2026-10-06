using System.Security.Cryptography;

using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Core.Discovery;

/// <summary>
/// This node's long-lived identity key. Its public half is published with the
/// discovery identity; the private half signs attestations so a console can
/// verify that a changed endpoint certificate still belongs to the agent it
/// enrolled (see <c>NodeAttestation</c> in the API contracts).
/// </summary>
public interface INodeIdentityKey
{
    /// <summary>Base64 SubjectPublicKeyInfo of the node key.</summary>
    Task<string> GetPublicKeyAsync(CancellationToken ct = default);

    /// <summary>ECDSA P-256 / SHA-256 signature (IEEE P1363) over <paramref name="message"/>.</summary>
    Task<byte[]> SignAsync(byte[] message, CancellationToken ct = default);
}

/// <summary>
/// Default <see cref="INodeIdentityKey"/>: an ECDSA P-256 key generated once and
/// persisted (protected with the same secret protector as ACME account keys) in
/// the settings table, so it survives restarts, upgrades, and endpoint-cert
/// renewals — which is the whole point.
/// </summary>
public sealed class NodeIdentityKeyProvider(
    IDbContextFactory<AcmeManagerDbContext> dbFactory,
    ISecretProtector protector,
    ILogger<NodeIdentityKeyProvider> logger) : INodeIdentityKey, IDisposable
{
    internal const string KeySettingKey = "node.identity.key";

    private sealed record LoadedKey(ECDsa Key, string PublicKey);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _signLock = new();
    private volatile LoadedKey? _loaded;

    public async Task<string> GetPublicKeyAsync(CancellationToken ct = default) =>
        (await EnsureKeyAsync(ct)).PublicKey;

    public async Task<byte[]> SignAsync(byte[] message, CancellationToken ct = default)
    {
        var loaded = await EnsureKeyAsync(ct);
        lock (_signLock)
        {
            return loaded.Key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    private async Task<LoadedKey> EnsureKeyAsync(CancellationToken ct)
    {
        if (_loaded is { } ready)
        {
            return ready;
        }

        await _gate.WaitAsync(ct);
        try
        {
            if (_loaded is { } already)
            {
                return already;
            }

            await using var db = await dbFactory.CreateDbContextAsync(ct);
            var row = await db.Settings.FirstOrDefaultAsync(s => s.Key == KeySettingKey, ct);
            var key = row is null ? null : TryLoad(row.Value);

            if (key is null)
            {
                key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var protectedKey = Convert.ToBase64String(protector.Protect(key.ExportPkcs8PrivateKey()));
                if (row is null)
                {
                    db.Settings.Add(new SettingsValue { Key = KeySettingKey, Value = protectedKey });
                }
                else
                {
                    row.Value = protectedKey;
                    row.UpdatedAt = DateTimeOffset.UtcNow;
                }

                try
                {
                    await db.SaveChangesAsync(ct);
                    logger.LogInformation("Generated this node's identity key.");
                }
                catch (DbUpdateException)
                {
                    // A concurrent first-run writer won the insert: use theirs.
                    var winner = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Key == KeySettingKey, ct);
                    var theirs = winner is null ? null : TryLoad(winner.Value);
                    if (theirs is null)
                    {
                        throw;
                    }
                    key.Dispose();
                    key = theirs;
                }
            }

            var loaded = new LoadedKey(key, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
            _loaded = loaded;
            return loaded;
        }
        finally
        {
            _gate.Release();
        }
    }

    private ECDsa? TryLoad(string protectedBase64)
    {
        try
        {
            var pkcs8 = protector.Unprotect(Convert.FromBase64String(protectedBase64));
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(pkcs8, out _);
            return key;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            logger.LogWarning(ex,
                "The stored node identity key is unreadable; generating a new one. Consoles that enrolled this node will need to re-enroll it.");
            return null;
        }
    }

    public void Dispose()
    {
        _loaded?.Key.Dispose();
        _gate.Dispose();
    }
}
using System.Text;

using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Core.Acme.Accounts;

/// <summary>
/// Manages the lifecycle of ACME accounts — creation against the CA,
/// encrypted persistence, lookup. Account keys and EAB credentials are
/// always at-rest-encrypted via <see cref="ISecretProtector"/>; plaintext
/// only exists in <see cref="AcmeAccount"/> instances handed to callers.
/// </summary>
public sealed class AccountService(
    AcmeManagerDbContext db,
    IAcmeClient acme,
    ISecretProtector protector,
    ILogger<AccountService> logger)
{
    public async Task<AcmeAccount> CreateAsync(
        string name,
        Uri directoryUrl,
        string contactEmail,
        AcmeKeyAlgorithm algorithm,
        EabCredentials? eab,
        CancellationToken ct)
    {
        var localId = Guid.NewGuid();
        var key = AcmeKeyGenerator.Generate(algorithm);

        var unregistered = new AcmeAccount(
            LocalId: localId,
            DirectoryUrl: directoryUrl,
            ContactEmail: contactEmail,
            Key: key,
            KeyId: null);

        var registered = await acme.CreateAccountAsync(unregistered, eab, ct);

        var entity = new Account
        {
            Id = localId,
            Name = name,
            DirectoryUrl = directoryUrl.ToString(),
            ContactEmail = contactEmail,
            AccountKeyEncrypted = protector.Protect(Encoding.UTF8.GetBytes(key.Pem)),
            KeyId = registered.KeyId?.ToString(),
            EabKeyIdEncrypted = eab is null
                ? null
                : protector.Protect(Encoding.UTF8.GetBytes(eab.KeyId)),
            EabHmacEncrypted = eab is null
                ? null
                : protector.Protect(Encoding.UTF8.GetBytes(eab.HmacKeyBase64Url)),
            CreatedAt = DateTimeOffset.UtcNow,
            RegisteredAt = DateTimeOffset.UtcNow,
        };

        db.Accounts.Add(entity);
        await db.SaveChangesAsync(ct);

        logger.LogInformation(
            "Created account '{Name}' ({LocalId}) at {Directory}", name, localId, directoryUrl);

        return registered;
    }

    public async Task<AcmeAccount?> LoadAsync(Guid id, CancellationToken ct)
    {
        var entity = await db.Accounts.FindAsync([id], ct);
        return entity is null ? null : Decrypt(entity);
    }

    public async Task<IReadOnlyList<AcmeAccount>> ListAsync(CancellationToken ct)
    {
        var entities = await db.Accounts.AsNoTracking().ToListAsync(ct);
        return [.. entities.Select(Decrypt)];
    }

    private AcmeAccount Decrypt(Account entity)
    {
        var pem = Encoding.UTF8.GetString(protector.Unprotect(entity.AccountKeyEncrypted));

        return new AcmeAccount(
            LocalId: entity.Id,
            DirectoryUrl: new Uri(entity.DirectoryUrl),
            ContactEmail: entity.ContactEmail,
            Key: new AcmeAccountKey(pem),
            KeyId: entity.KeyId is null ? null : new Uri(entity.KeyId));
    }
}
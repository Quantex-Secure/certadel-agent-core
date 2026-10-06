namespace AcmeManager.Core.Storage.Entities;

/// <summary>
/// An ACME account at a specific CA. The account key is the private key used
/// to sign every request; it is stored encrypted via <c>ISecretProtector</c>.
/// </summary>
public sealed class Account
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = "";

    public string DirectoryUrl { get; set; } = "";

    public string ContactEmail { get; set; } = "";

    public byte[] AccountKeyEncrypted { get; set; } = [];

    public string? KeyId { get; set; }

    public byte[]? EabKeyIdEncrypted { get; set; }

    public byte[]? EabHmacEncrypted { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? RegisteredAt { get; set; }
}
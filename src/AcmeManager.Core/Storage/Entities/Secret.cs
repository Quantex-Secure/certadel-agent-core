namespace AcmeManager.Core.Storage.Entities;

/// <summary>
/// A named secret (API token, password, etc.) referenced from plugin options
/// by name. Always stored encrypted via <c>ISecretProtector</c>.
/// </summary>
public sealed class Secret
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = "";

    public byte[] EncryptedValue { get; set; } = [];

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastUsedAt { get; set; }
}
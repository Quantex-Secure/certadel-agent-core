namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Resolves a named secret to its plaintext value at call time. Lets plugins
/// hold only the secret <em>name</em> in their options (safe to serialize into
/// the renewal JSON in the database) while the actual credential stays
/// encrypted in the host's secret store.
/// </summary>
public interface ISecretResolver
{
    /// <summary>
    /// Returns the plaintext for the named secret, or throws
    /// <see cref="KeyNotFoundException"/> if no secret with that name exists.
    /// </summary>
    Task<string> ResolveAsync(string name, CancellationToken ct);
}
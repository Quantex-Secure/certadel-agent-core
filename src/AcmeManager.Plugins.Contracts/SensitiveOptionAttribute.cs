namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Marks a plugin-option property whose <em>value</em> is a credential (a
/// literal password, token, or key) rather than the name of a stored secret.
/// Such values are never returned by the management API — they are replaced
/// with <see cref="RedactedValue"/> on the way out and, if a client sends that
/// placeholder back, the stored value is kept. New configurations should use a
/// <see cref="SecretReferenceAttribute"/> option instead; the API refuses to
/// create a renewal that sets a sensitive literal.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
public sealed class SensitiveOptionAttribute : Attribute
{
    /// <summary>Placeholder that stands in for a redacted value on the wire.</summary>
    public const string RedactedValue = "********";
}
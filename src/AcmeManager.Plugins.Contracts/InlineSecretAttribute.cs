namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Marks a write-only credential option (e.g. a password) that forms show as a
/// masked field but that is never persisted in the renewal. When a renewal is
/// saved, a non-empty value is stored as an encrypted agent secret named
/// <c>&lt;NamePrefix&gt;: &lt;value of NameSuffixProperty&gt;</c>, the sibling
/// <see cref="SecretNameProperty"/> (a <see cref="SecretReferenceAttribute"/>
/// option) is set to that name, and the value itself is removed. Saving with the
/// field blank keeps the previously stored secret. Forms hide the sibling.
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class InlineSecretAttribute(string secretNameProperty) : Attribute
{
    /// <summary>The option that receives the stored secret's name.</summary>
    public string SecretNameProperty { get; } = secretNameProperty;

    /// <summary>First part of the generated secret name, e.g. <c>Synology DSM</c>.</summary>
    public string NamePrefix { get; init; } = "Credential";

    /// <summary>Option whose value completes the secret name (e.g. the account), so
    /// one secret is kept per account. Optional.</summary>
    public string? NameSuffixProperty { get; init; }
}

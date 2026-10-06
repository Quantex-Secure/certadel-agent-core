namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Marks a <see cref="string"/> plugin-option property that holds the <b>name</b>
/// of a stored secret (not the secret value itself). UIs render these as a picker
/// of existing secrets instead of a free-text box, and the value is resolved
/// against the secret store at runtime.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
public sealed class SecretReferenceAttribute : Attribute;
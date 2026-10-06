namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Marks a <see cref="string"/> plugin-option property that names an IIS site.
/// UIs render these as a picker of the sites present on the host (when IIS is
/// available) instead of a free-text box.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
public sealed class IisSiteReferenceAttribute : Attribute;
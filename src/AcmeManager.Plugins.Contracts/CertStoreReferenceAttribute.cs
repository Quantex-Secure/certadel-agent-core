namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Marks a <see cref="string"/> plugin-option property that names a Windows
/// certificate store (e.g. <c>My</c>, <c>WebHosting</c>). UIs render these as a
/// picker of the stores present on the host instead of a free-text box.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
public sealed class CertStoreReferenceAttribute : Attribute;
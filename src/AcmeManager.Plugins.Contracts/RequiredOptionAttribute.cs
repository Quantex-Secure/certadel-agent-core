namespace AcmeManager.Plugins.Contracts;

/// <summary>
/// Marks a plugin-option property that must be set (non-empty) for the plugin to
/// work. The agent rejects a renewal whose step leaves a required option blank
/// (instead of issuing a cert that then can't be stored/installed), and UIs mark
/// the field as required.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
public sealed class RequiredOptionAttribute : Attribute;
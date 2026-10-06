using System.Reflection;

using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Core.Plugins;

/// <summary>
/// Discovers plugin assemblies in the configured plugins directory, validates
/// the assembly-level <see cref="PluginAssemblyAttribute"/> against the host's
/// <see cref="PluginApi.Version"/>, and returns descriptors for every
/// <see cref="IPlugin"/> implementation found. Instantiation and DI
/// registration happen downstream.
/// </summary>
public interface IPluginLoader
{
    Task<IReadOnlyList<LoadedPlugin>> LoadAsync(string pluginsDirectory, CancellationToken ct);
}

/// <param name="Assembly">The loaded assembly the plugin lives in.</param>
/// <param name="ImplementationType">A concrete <see cref="IPlugin"/> type within the assembly.</param>
/// <param name="AssemblyManifest">The plugin assembly's self-declared manifest.</param>
public sealed record LoadedPlugin(
    Assembly Assembly,
    Type ImplementationType,
    PluginAssemblyAttribute AssemblyManifest);
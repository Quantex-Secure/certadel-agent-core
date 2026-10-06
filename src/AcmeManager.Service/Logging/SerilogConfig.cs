using AcmeManager.Core.Logging;
using AcmeManager.Core.Storage;

using Serilog;
using Serilog.Events;

namespace AcmeManager.Service.Logging;

public static class SerilogConfig
{
    /// <summary>
    /// Configures the shared <see cref="InMemoryLogStore"/> and wires Serilog
    /// to write to console, a rolling file under <see cref="DataPaths.LogsDir"/>,
    /// and the in-memory store. Call once before host startup.
    /// </summary>
    public static InMemoryLogStore Configure()
    {
        Directory.CreateDirectory(DataPaths.LogsDir);

        var store = new InMemoryLogStore();

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Information)
            .Enrich.FromLogContext()
            .WriteTo.Console(outputTemplate:
                "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
            .WriteTo.File(
                path: Path.Combine(DataPaths.LogsDir, "acme-manager-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                outputTemplate:
                    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
            .WriteTo.Sink(new InMemoryLogSink(store))
            .CreateLogger();

        return store;
    }
}
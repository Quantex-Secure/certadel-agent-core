using AcmeManager.Core.Logging;

using Serilog.Core;
using Serilog.Events;

namespace AcmeManager.Service.Logging;

/// <summary>
/// Serilog sink that mirrors every log event into the in-process
/// <see cref="InMemoryLogStore"/> so the Web UI can render a live tail
/// without round-tripping through the file system.
/// </summary>
public sealed class InMemoryLogSink(InMemoryLogStore store) : ILogEventSink
{
    public void Emit(LogEvent logEvent)
    {
        store.Add(new LogEntry(
            logEvent.Timestamp,
            logEvent.Level.ToString(),
            logEvent.RenderMessage(),
            logEvent.Exception?.ToString()));
    }
}
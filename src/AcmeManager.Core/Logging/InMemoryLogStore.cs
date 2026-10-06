namespace AcmeManager.Core.Logging;

/// <summary>
/// Bounded ring buffer of the most recent log entries. Drives the live log
/// pane in the Web UI without re-reading rolling log files from disk.
/// </summary>
public sealed class InMemoryLogStore(int capacity = 500)
{
    private readonly object _lock = new();
    private readonly Queue<LogEntry> _entries = new(capacity);

    public int Capacity { get; } = capacity;

    public event Action<LogEntry>? EntryAdded;

    public event Action? Cleared;

    /// <summary>Empties the live buffer (does not touch the rolling log files on disk).</summary>
    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
        }
        Cleared?.Invoke();
    }

    public void Add(LogEntry entry)
    {
        lock (_lock)
        {
            _entries.Enqueue(entry);
            while (_entries.Count > Capacity)
            {
                _entries.Dequeue();
            }
        }

        EntryAdded?.Invoke(entry);
    }

    public IReadOnlyList<LogEntry> Snapshot()
    {
        lock (_lock)
        {
            return [.. _entries];
        }
    }
}

public sealed record LogEntry(
    DateTimeOffset At,
    string Level,
    string Message,
    string? Exception);
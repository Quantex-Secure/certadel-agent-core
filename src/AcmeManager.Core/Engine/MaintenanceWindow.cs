using System.Text.Json;
using System.Text.Json.Serialization;

namespace AcmeManager.Core.Engine;

/// <summary>
/// When a renewal is allowed to run automatically: a set of weekdays and a
/// daily time range in a named time zone. The range may cross midnight
/// (<c>22:00–04:00</c>), in which case the day is the one the range starts on.
/// Manual "Renew now" ignores the window, as it ignores back-off.
/// </summary>
public sealed record MaintenanceWindow(
    IReadOnlySet<DayOfWeek> Days,
    TimeOnly Start,
    TimeOnly End,
    string? TimeZoneId)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    /// <summary>Wire/storage shape: <c>{"days":["saturday","sunday"],"start":"01:00","end":"05:00","timeZone":"UTC"}</c>.</summary>
    private sealed record Wire(string[]? Days, string? Start, string? End, string? TimeZone);

    /// <summary>Null for blank input; throws <see cref="FormatException"/> for anything unusable.</summary>
    public static MaintenanceWindow? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        Wire? wire;
        try
        {
            wire = JsonSerializer.Deserialize<Wire>(json, Json);
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Maintenance window is not valid JSON: {ex.Message}");
        }
        if (wire is null)
        {
            return null;
        }

        var days = new HashSet<DayOfWeek>();
        foreach (var name in wire.Days ?? [])
        {
            if (!Enum.TryParse<DayOfWeek>(name, ignoreCase: true, out var day))
            {
                throw new FormatException($"Maintenance window: '{name}' is not a day of the week.");
            }
            days.Add(day);
        }
        if (days.Count == 0)
        {
            throw new FormatException("Maintenance window needs at least one day.");
        }

        if (!TimeOnly.TryParseExact(wire.Start, "HH:mm", out var start)
            || !TimeOnly.TryParseExact(wire.End, "HH:mm", out var end))
        {
            throw new FormatException("Maintenance window start and end must be HH:mm (24-hour).");
        }
        if (start == end)
        {
            throw new FormatException("Maintenance window start and end must differ.");
        }

        var timeZone = string.IsNullOrWhiteSpace(wire.TimeZone) ? null : wire.TimeZone.Trim();
        if (timeZone is not null)
        {
            try
            {
                TimeZoneInfo.FindSystemTimeZoneById(timeZone);
            }
            catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
            {
                throw new FormatException($"Maintenance window: unknown time zone '{timeZone}'.");
            }
        }

        return new MaintenanceWindow(days, start, end, timeZone);
    }

    public string ToJson() => JsonSerializer.Serialize(
        new Wire(
            Days.OrderBy(d => d).Select(d => d.ToString().ToLowerInvariant()).ToArray(),
            Start.ToString("HH:mm"),
            End.ToString("HH:mm"),
            TimeZoneId),
        Json);

    // Days is a set: compare by content, not by reference, so parsed windows are equal.
    public bool Equals(MaintenanceWindow? other) =>
        other is not null
        && Days.SetEquals(other.Days)
        && Start == other.Start
        && End == other.End
        && string.Equals(TimeZoneId, other.TimeZoneId, StringComparison.Ordinal);

    public override int GetHashCode() => HashCode.Combine(Days.Count, Start, End, TimeZoneId);

    public TimeZoneInfo Zone =>
        TimeZoneId is null ? TimeZoneInfo.Local : TimeZoneInfo.FindSystemTimeZoneById(TimeZoneId);

    /// <summary>True when <paramref name="instant"/> falls inside the window.</summary>
    public bool Contains(DateTimeOffset instant)
    {
        var local = TimeZoneInfo.ConvertTime(instant, Zone);
        var time = TimeOnly.FromDateTime(local.DateTime);
        var day = local.DayOfWeek;

        if (Start < End)
        {
            return Days.Contains(day) && time >= Start && time < End;
        }

        // Overnight range: the part after Start belongs to this day, the part before
        // End belongs to the range that started the previous day.
        var previous = (DayOfWeek)(((int)day + 6) % 7);
        return (Days.Contains(day) && time >= Start) || (Days.Contains(previous) && time < End);
    }

    public string Describe()
    {
        var days = string.Join(", ", Days.OrderBy(d => d).Select(d => d.ToString()[..3]));
        var zone = TimeZoneId ?? "server local time";
        return $"{days} {Start:HH\\:mm}–{End:HH\\:mm} ({zone})";
    }
}
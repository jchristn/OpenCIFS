namespace OpenCIFS.Telemetry.Tests.Shared
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// One metric measurement captured by <see cref="TelemetryCapture" />.
    /// </summary>
    internal sealed class CapturedMeasurement
    {
        internal CapturedMeasurement(string instrumentName, double value, Dictionary<string, string?> tags)
        {
            InstrumentName = instrumentName ?? throw new ArgumentNullException(nameof(instrumentName));
            Value = value;
            Tags = tags ?? throw new ArgumentNullException(nameof(tags));
        }

        internal string InstrumentName { get; }

        internal double Value { get; }

        internal Dictionary<string, string?> Tags { get; }

        internal bool HasTag(string key, string value)
        {
            return Tags.TryGetValue(key, out string? actual) && String.Equals(actual, value, StringComparison.Ordinal);
        }

        internal string? Tag(string key)
        {
            return Tags.TryGetValue(key, out string? actual) ? actual : null;
        }
    }
}

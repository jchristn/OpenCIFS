namespace OpenCIFS.Telemetry.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Metrics;
    using System.Globalization;
    using System.Linq;
    using OpenCIFS.Protocol;

    /// <summary>
    /// In-memory listener for the OpenCIFS meters and activity sources, used to prove what the libraries emit.
    /// Thread-safe: measurement and activity callbacks can arrive from any thread.
    /// </summary>
    internal sealed class TelemetryCapture : IDisposable
    {
        internal TelemetryCapture()
        {
            _MeterListener = new MeterListener();
            _MeterListener.InstrumentPublished = (instrument, listener) =>
            {
                if (!IsOpenCifsMeter(instrument.Meter.Name))
                {
                    return;
                }

                lock (_Sync)
                {
                    _Instruments[instrument.Name] = instrument;
                }

                listener.EnableMeasurementEvents(instrument);
            };
            _MeterListener.SetMeasurementEventCallback<long>((instrument, value, tags, state) => Record(instrument, value, tags));
            _MeterListener.SetMeasurementEventCallback<int>((instrument, value, tags, state) => Record(instrument, value, tags));
            _MeterListener.SetMeasurementEventCallback<double>((instrument, value, tags, state) => Record(instrument, value, tags));
            _MeterListener.Start();

            _ActivityListener = new ActivityListener
            {
                ShouldListenTo = source => IsOpenCifsMeter(source.Name),
                Sample = (ref ActivityCreationOptions<ActivityContext> options) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStopped = activity =>
                {
                    lock (_Sync)
                    {
                        _Activities.Add(activity);
                    }
                }
            };
            ActivitySource.AddActivityListener(_ActivityListener);
        }

        internal IReadOnlyCollection<string> InstrumentNames
        {
            get
            {
                lock (_Sync)
                {
                    return _Instruments.Keys.ToList();
                }
            }
        }

        internal Instrument? Instrument(string name)
        {
            lock (_Sync)
            {
                return _Instruments.TryGetValue(name, out Instrument? instrument) ? instrument : null;
            }
        }

        internal IReadOnlyList<CapturedMeasurement> Measurements(string instrumentName)
        {
            lock (_Sync)
            {
                return _Measurements.Where(measurement => measurement.InstrumentName == instrumentName).ToList();
            }
        }

        internal IReadOnlyList<CapturedMeasurement> AllMeasurements()
        {
            lock (_Sync)
            {
                return _Measurements.ToList();
            }
        }

        internal bool Any(string instrumentName, Func<CapturedMeasurement, bool> predicate)
        {
            return Measurements(instrumentName).Any(predicate);
        }

        internal double Sum(string instrumentName, Func<CapturedMeasurement, bool> predicate)
        {
            return Measurements(instrumentName).Where(predicate).Sum(measurement => measurement.Value);
        }

        internal IReadOnlyList<Activity> Activities()
        {
            lock (_Sync)
            {
                return _Activities.ToList();
            }
        }

        internal IReadOnlyList<Activity> Activities(string displayName)
        {
            lock (_Sync)
            {
                return _Activities.Where(activity => activity.DisplayName == displayName).ToList();
            }
        }

        internal void ObserveGauges()
        {
            _MeterListener.RecordObservableInstruments();
        }

        internal void Clear()
        {
            lock (_Sync)
            {
                _Measurements.Clear();
                _Activities.Clear();
            }
        }

        internal string Describe(string instrumentName)
        {
            return String.Join(
                "; ",
                Measurements(instrumentName).Select(measurement =>
                    measurement.Value.ToString(CultureInfo.InvariantCulture) +
                    " {" +
                    String.Join(",", measurement.Tags.Select(tag => tag.Key + "=" + tag.Value)) +
                    "}"));
        }

        public void Dispose()
        {
            _ActivityListener.Dispose();
            _MeterListener.Dispose();
        }

        private static bool IsOpenCifsMeter(string name)
        {
            return name == OpenCifsTelemetryNames.ServerMeterName || name == OpenCifsTelemetryNames.ClientMeterName;
        }

        private void Record<T>(Instrument instrument, T value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
            where T : struct
        {
            Dictionary<string, string?> tagValues = new Dictionary<string, string?>(StringComparer.Ordinal);

            foreach (KeyValuePair<string, object?> tag in tags)
            {
                tagValues[tag.Key] = Convert.ToString(tag.Value, CultureInfo.InvariantCulture);
            }

            double numericValue = Convert.ToDouble(value, CultureInfo.InvariantCulture);

            lock (_Sync)
            {
                _Measurements.Add(new CapturedMeasurement(instrument.Name, numericValue, tagValues));
            }
        }

        private readonly object _Sync = new object();
        private readonly MeterListener _MeterListener;
        private readonly ActivityListener _ActivityListener;
        private readonly Dictionary<string, Instrument> _Instruments = new Dictionary<string, Instrument>(StringComparer.Ordinal);
        private readonly List<CapturedMeasurement> _Measurements = new List<CapturedMeasurement>();
        private readonly List<Activity> _Activities = new List<Activity>();
    }
}

namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Times one share-backend storage call and, when traced, wraps it in a <c>storage &lt;operation&gt;</c> span.
    /// Call <see cref="Succeed" /> after the call returns; disposing without it records an <c>error</c> outcome.
    /// Returns a shared no-op instance when nothing listens, so the unobserved path does not allocate. Not thread-safe.
    /// </summary>
    internal sealed class OpenCifsServerStorageScope : IDisposable
    {
        private OpenCifsServerStorageScope()
        {
            _Operation = String.Empty;
            _IsNoOp = true;
        }

        private OpenCifsServerStorageScope(string operation)
        {
            _Operation = operation;
            _StartTimestamp = Stopwatch.GetTimestamp();

            try
            {
                _Activity = OpenCifsServerTelemetry.Source.StartActivity("storage " + operation, ActivityKind.Internal);
                _Activity?.SetTag(OpenCifsTelemetryNames.AttributeStorageOperation, operation);
            }
            catch (Exception)
            {
                _Activity = null;
            }
        }

        internal static OpenCifsServerStorageScope Start(string operation)
        {
            if (!OpenCifsServerTelemetry.StorageDuration.Enabled && !OpenCifsServerTelemetry.IsTracing)
            {
                return _NoOp;
            }

            return new OpenCifsServerStorageScope(operation);
        }

        internal void Succeed()
        {
            _Succeeded = true;
        }

        internal void Fail(Exception exception)
        {
            if (_IsNoOp)
            {
                return;
            }

            _Exception = exception;
        }

        public void Dispose()
        {
            if (_IsNoOp || _Disposed)
            {
                return;
            }

            _Disposed = true;

            try
            {
                string outcome = _Succeeded && _Exception == null ? OpenCifsTelemetryFormat.OutcomeSuccess : OpenCifsTelemetryFormat.OutcomeError;
                OpenCifsServerTelemetry.StorageDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(_StartTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStorageOperation, _Operation),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, outcome));

                if (_Exception != null)
                {
                    OpenCifsServerTelemetry.RecordError(_Exception, "storage");
                    OpenCifsServerTelemetry.MarkFailed(_Activity, _Exception);
                }
                else if (_Activity != null)
                {
                    _Activity.SetStatus(_Succeeded ? ActivityStatusCode.Ok : ActivityStatusCode.Error);
                }

                _Activity?.Dispose();
            }
            catch (Exception)
            {
            }
        }

        private static readonly OpenCifsServerStorageScope _NoOp = new OpenCifsServerStorageScope();
        private readonly string _Operation;
        private readonly long _StartTimestamp;
        private readonly bool _IsNoOp;
        private readonly Activity? _Activity;
        private bool _Succeeded;
        private bool _Disposed;
        private Exception? _Exception;
    }
}

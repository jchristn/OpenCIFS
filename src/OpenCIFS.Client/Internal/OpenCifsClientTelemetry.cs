namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Metrics;
    using System.Text;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Client meter, activity source, and instruments. Emission is best-effort: every helper swallows its own failures and
    /// is a near-zero-cost no-op when no listener subscribes to <see cref="OpenCifsTelemetryNames.ClientMeterName" /> or
    /// <see cref="OpenCifsTelemetryNames.ClientActivitySourceName" />. Thread-safe.
    /// </summary>
    internal static class OpenCifsClientTelemetry
    {
        internal const string CompoundCommandName = "COMPOUND";

        internal static string Version { get; } = OpenCifsTelemetryFormat.AssemblyVersion(typeof(OpenCifsClientTelemetry).Assembly);

        internal static ActivitySource Source { get; } = new ActivitySource(OpenCifsTelemetryNames.ClientActivitySourceName, Version);

        internal static Meter Meter { get; } = new Meter(OpenCifsTelemetryNames.ClientMeterName, Version);

        internal static Histogram<double> OperationDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ClientOperationDuration, "s", "Public client operation time, by operation, outcome, and error type.");

        internal static Histogram<double> OperationQueueDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ClientOperationQueueDuration, "s", "Time a client operation waited for the per-connection operation lock.");

        internal static UpDownCounter<long> OperationsWaiting { get; } = Meter.CreateUpDownCounter<long>(
            OpenCifsTelemetryNames.ClientOperationsWaiting, "{operation}", "Client operations waiting for the per-connection operation lock.");

        internal static Histogram<double> RequestDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ClientRequestDuration, "s", "Client SMB2 request round-trip time, by command, NT status, and outcome.");

        internal static Histogram<double> ConnectDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ClientConnectDuration, "s", "Client connect-and-negotiate time, by outcome and error type.");

        internal static UpDownCounter<long> ConnectionsActive { get; } = Meter.CreateUpDownCounter<long>(
            OpenCifsTelemetryNames.ClientConnectionsActive, "{connection}", "Client connections currently established.");

        internal static Counter<long> TransportFailures { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ClientTransportFailures, "{failure}", "Client transport losses, by exception type.");

        internal static Counter<long> RequestsAbandoned { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ClientRequestsAbandoned, "{request}", "Client requests abandoned because the caller cancelled while awaiting the response.");

        internal static Counter<long> IoBytes { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ClientIoBytes, "By", "File data bytes read and written by the client.");

        internal static Counter<long> NetworkIo { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ClientNetworkIo, "By", "SMB transport payload bytes received and transmitted by the client.");

        internal static ObservableGauge<long> BuildInfo { get; } = Meter.CreateObservableGauge<long>(
            OpenCifsTelemetryNames.BuildInfo,
            () => new Measurement<long>(
                1,
                new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeComponent, "client"),
                new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeVersion, Version)),
            "{component}",
            "Loaded OpenCIFS component and version.");

        internal static string OperationName(string memberName)
        {
            if (String.IsNullOrEmpty(memberName))
            {
                return OpenCifsTelemetryFormat.Unknown;
            }

            return _OperationNames.GetOrAdd(
                memberName,
                static name => name.EndsWith("Async", StringComparison.Ordinal) && name.Length > 5
                    ? name.Substring(0, name.Length - 5)
                    : name);
        }

        internal static Activity? StartOperation(string operation, string serverName, int serverPort)
        {
            if (!Source.HasListeners())
            {
                return null;
            }

            try
            {
                Activity? activity = Source.StartActivity("OpenCIFS " + operation, ActivityKind.Internal);

                if (activity != null && activity.IsAllDataRequested)
                {
                    activity.SetTag(OpenCifsTelemetryNames.AttributeOperation, operation);
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeServerAddress, serverName);
                    activity.SetTag(OpenCifsTelemetryNames.AttributeServerPort, serverPort);
                }

                return activity;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal static void RecordOperationQueued(string operation, long queueStartTimestamp)
        {
            try
            {
                OperationQueueDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(queueStartTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOperation, operation));
            }
            catch (Exception)
            {
            }
        }

        internal static void CompleteOperation(string operation, long startTimestamp, Activity? activity)
        {
            try
            {
                OperationDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOperation, operation),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, OpenCifsTelemetryFormat.OutcomeSuccess));
                activity?.SetStatus(ActivityStatusCode.Ok);
            }
            catch (Exception)
            {
            }
        }

        internal static void FailOperation(string operation, Exception exception, long startTimestamp, Activity? activity)
        {
            try
            {
                string outcome = IsCancellation(exception) ? OpenCifsTelemetryFormat.OutcomeCancelled : OpenCifsTelemetryFormat.OutcomeException;
                string errorType = OpenCifsTelemetryFormat.ErrorType(exception);
                OperationDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOperation, operation),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, outcome),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeErrorType, errorType));

                if (activity != null)
                {
                    activity.SetTag(OpenCifsTelemetryNames.AttributeOutcome, outcome);

                    if (exception is OpenCifsStatusException statusException)
                    {
                        activity.SetTag(OpenCifsTelemetryNames.AttributeStatus, OpenCifsTelemetryFormat.StatusName(statusException.Status));
                    }

                    if (outcome == OpenCifsTelemetryFormat.OutcomeCancelled)
                    {
                        activity.SetTag(OpenCifsTelemetryNames.AttributeErrorType, errorType);
                    }
                    else
                    {
                        MarkFailed(activity, exception);
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        internal static Activity? StartRequest(string commandName, Smb2Header? requestHeader, string serverName, int serverPort)
        {
            if (!Source.HasListeners())
            {
                return null;
            }

            try
            {
                Activity? activity = Source.StartActivity("SMB2 " + commandName, ActivityKind.Client);

                if (activity != null && activity.IsAllDataRequested)
                {
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeNetworkTransport, "tcp");
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeServerAddress, serverName);
                    activity.SetTag(OpenCifsTelemetryNames.AttributeServerPort, serverPort);
                    activity.SetTag(OpenCifsTelemetryNames.AttributeCommand, commandName);

                    if (requestHeader != null)
                    {
                        activity.SetTag(OpenCifsTelemetryNames.SpanAttributeSessionId, requestHeader.SessionId);
                        activity.SetTag(OpenCifsTelemetryNames.SpanAttributeTreeId, requestHeader.TreeId);
                    }
                }

                return activity;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal static void CompleteRequest(string commandName, Smb2Header? requestHeader, NtStatus status, long startTimestamp, Activity? activity)
        {
            try
            {
                string outcome = OpenCifsTelemetryFormat.Outcome(status);
                string statusName = OpenCifsTelemetryFormat.StatusName(status);
                RequestDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeCommand, commandName),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStatus, statusName),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, outcome));

                if (activity != null)
                {
                    activity.SetTag(OpenCifsTelemetryNames.AttributeStatus, statusName);
                    activity.SetTag(OpenCifsTelemetryNames.AttributeOutcome, outcome);

                    if (requestHeader != null)
                    {
                        // Message identifiers are assigned while the packet is finalized, so read them after the send.
                        activity.SetTag(OpenCifsTelemetryNames.SpanAttributeMessageId, requestHeader.MessageId);
                    }

                    activity.SetStatus(outcome == OpenCifsTelemetryFormat.OutcomeError ? ActivityStatusCode.Error : ActivityStatusCode.Ok, outcome == OpenCifsTelemetryFormat.OutcomeError ? statusName : null);
                }
            }
            catch (Exception)
            {
            }
        }

        internal static void FailRequest(string commandName, Exception exception, long startTimestamp, Activity? activity)
        {
            try
            {
                string outcome = IsCancellation(exception) ? OpenCifsTelemetryFormat.OutcomeCancelled : OpenCifsTelemetryFormat.OutcomeException;
                RequestDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeCommand, commandName),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStatus, OpenCifsTelemetryFormat.Other),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, outcome));

                if (activity != null)
                {
                    activity.SetTag(OpenCifsTelemetryNames.AttributeOutcome, outcome);

                    if (outcome != OpenCifsTelemetryFormat.OutcomeCancelled)
                    {
                        MarkFailed(activity, exception);
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        internal static string DescribeCompound(Smb2CompoundPacket? requestPacket)
        {
            if (requestPacket == null || requestPacket.Entries.Count == 0)
            {
                return String.Empty;
            }

            StringBuilder builder = new StringBuilder();

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                if (index > 0)
                {
                    builder.Append(',');
                }

                builder.Append(OpenCifsTelemetryFormat.CommandName(requestPacket.Entries[index].Header.Command));
            }

            return builder.ToString();
        }

        internal static NtStatus SummarizeCompoundStatus(Smb2CompoundPacket responsePacket)
        {
            for (int index = 0; index < responsePacket.Entries.Count; index++)
            {
                NtStatus status = responsePacket.Entries[index].Header.Status;

                if (OpenCifsTelemetryFormat.Outcome(status) != OpenCifsTelemetryFormat.OutcomeSuccess)
                {
                    return status;
                }
            }

            return NtStatus.Success;
        }

        internal static long ConnectStarted()
        {
            return Stopwatch.GetTimestamp();
        }

        internal static void ConnectCompleted(long startTimestamp, Exception? exception)
        {
            try
            {
                if (exception == null)
                {
                    ConnectDuration.Record(
                        OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                        new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, OpenCifsTelemetryFormat.OutcomeSuccess));
                    return;
                }

                ConnectDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, IsCancellation(exception) ? OpenCifsTelemetryFormat.OutcomeCancelled : OpenCifsTelemetryFormat.OutcomeException),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeErrorType, OpenCifsTelemetryFormat.ErrorType(exception)));
            }
            catch (Exception)
            {
            }
        }

        internal static void ConnectionEstablished()
        {
            try
            {
                ConnectionsActive.Add(1);
            }
            catch (Exception)
            {
            }
        }

        internal static void ConnectionReleased()
        {
            try
            {
                ConnectionsActive.Add(-1);
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordTransportFailure(Exception cause)
        {
            try
            {
                TransportFailures.Add(1, new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeErrorType, OpenCifsTelemetryFormat.ErrorType(cause)));
                Activity? current = Activity.Current;

                if (current != null)
                {
                    current.AddEvent(new ActivityEvent(
                        "transport_lost",
                        tags: new ActivityTagsCollection { { "exception.type", cause.GetType().FullName } }));
                }
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordRequestAbandoned()
        {
            try
            {
                RequestsAbandoned.Add(1);
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordIoBytes(long bytes, bool write)
        {
            try
            {
                IoBytes.Add(bytes, new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeIoDirection, write ? "write" : "read"));
                Activity.Current?.SetTag(OpenCifsTelemetryNames.SpanAttributeByteCount, bytes);
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordNetworkIo(long bytes, bool transmit)
        {
            try
            {
                NetworkIo.Add(bytes, new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeNetworkIoDirection, transmit ? "transmit" : "receive"));
            }
            catch (Exception)
            {
            }
        }

        internal static void MarkFailed(Activity? activity, Exception exception)
        {
            if (activity == null)
            {
                return;
            }

            try
            {
                string errorType = OpenCifsTelemetryFormat.ErrorType(exception);
                activity.SetTag(OpenCifsTelemetryNames.AttributeErrorType, errorType);
                activity.SetStatus(ActivityStatusCode.Error, errorType);

                // Record the type only: exception messages can carry server names, share paths, or file names.
                activity.AddEvent(new ActivityEvent(
                    "exception",
                    tags: new ActivityTagsCollection { { "exception.type", exception.GetType().FullName } }));
            }
            catch (Exception)
            {
            }
        }

        private static bool IsCancellation(Exception exception)
        {
            return exception is OperationCanceledException;
        }

        private static readonly ConcurrentDictionary<string, string> _OperationNames = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
    }
}

namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Metrics;
    using System.Runtime.CompilerServices;
    using System.Threading;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Server meter, activity source, and instruments. Emission is best-effort: every helper swallows its own failures and
    /// is a near-zero-cost no-op when no listener subscribes to <see cref="OpenCifsTelemetryNames.ServerMeterName" /> or
    /// <see cref="OpenCifsTelemetryNames.ServerActivitySourceName" />.
    /// </summary>
    internal static class OpenCifsServerTelemetry
    {
        internal const string StageQueued = "queued";
        internal const string StageDecode = "decode";
        internal const string StageDispatch = "dispatch";
        internal const string StageEncode = "encode";
        internal const string StageSend = "send";
        internal const string StageConnection = "connection";

        internal const string PacketKindSmb2 = "smb2";
        internal const string PacketKindSmb2Compound = "smb2_compound";
        internal const string PacketKindSmb1Negotiate = "smb1_negotiate";

        internal const string CloseReasonClientClosed = "client_closed";
        internal const string CloseReasonTransportError = "transport_error";
        internal const string CloseReasonProtocolError = "protocol_error";
        internal const string CloseReasonServerError = "server_error";
        internal const string CloseReasonShutdown = "shutdown";

        internal const string AsyncKindOplockBreak = "oplock_break";
        internal const string AsyncKindLeaseBreak = "lease_break";
        internal const string AsyncKindChangeNotify = "change_notify";
        internal const string AsyncKindChangeNotifyCancelled = "change_notify_cancelled";
        internal const string AsyncKindOther = "other";

        internal const string StorageOpen = "open";
        internal const string StorageRead = "read";
        internal const string StorageWrite = "write";
        internal const string StorageFlush = "flush";
        internal const string StorageEnumerate = "enumerate";
        internal const string StorageStat = "stat";
        internal const string StorageCreateDirectory = "create_directory";
        internal const string StorageDelete = "delete";
        internal const string StorageRename = "rename";

        internal static string Version { get; } = OpenCifsTelemetryFormat.AssemblyVersion(typeof(OpenCifsServerTelemetry).Assembly);

        internal static ActivitySource Source { get; } = new ActivitySource(OpenCifsTelemetryNames.ServerActivitySourceName, Version);

        internal static Meter Meter { get; } = new Meter(OpenCifsTelemetryNames.ServerMeterName, Version);

        internal static Counter<long> ConnectionsAccepted { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerConnectionsAccepted, "{connection}", "TCP connections accepted by the server.");

        internal static UpDownCounter<long> ConnectionsActive { get; } = Meter.CreateUpDownCounter<long>(
            OpenCifsTelemetryNames.ServerConnectionsActive, "{connection}", "TCP connections currently open on the server.");

        internal static Counter<long> ConnectionsClosed { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerConnectionsClosed, "{connection}", "Server connections closed, by close reason.");

        internal static Histogram<double> ConnectionDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ServerConnectionDuration, "s", "Server connection lifetime, by close reason.");

        internal static UpDownCounter<long> ListenersActive { get; } = Meter.CreateUpDownCounter<long>(
            OpenCifsTelemetryNames.ServerListenersActive, "{listener}", "Server listeners currently running.");

        internal static Histogram<double> PacketDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ServerPacketDuration, "s", "End-to-end inbound packet handling time, by packet kind and outcome.");

        internal static Histogram<double> PacketStageDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ServerPacketStageDuration, "s", "Inbound packet handling time per stage (queued, decode, dispatch, encode, send).");

        internal static UpDownCounter<long> LockWaiting { get; } = Meter.CreateUpDownCounter<long>(
            OpenCifsTelemetryNames.ServerLockWaiting, "{packet}", "Inbound packets waiting for the server-wide state lock.");

        internal static Histogram<double> CommandDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ServerCommandDuration, "s", "Per-command server handling time, by command, NT status, and outcome.");

        internal static Counter<long> Errors { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerErrors, "{error}", "Server failures, by exception type and stage.");

        internal static Counter<long> Negotiations { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerNegotiations, "{negotiation}", "Completed SMB2 dialect negotiations, by dialect.");

        internal static Counter<long> AuthAttempts { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerAuthAttempts, "{attempt}", "Completed session authentication attempts, by mechanism, outcome, and session kind.");

        internal static Counter<long> DurableReconnects { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerDurableReconnects, "{reconnect}", "Durable-handle reconnect attempts, by outcome.");

        internal static Counter<long> AsyncResponsesSent { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerAsyncResponsesSent, "{response}", "Server-initiated asynchronous responses written, by kind.");

        internal static Histogram<double> AsyncResponseQueueDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ServerAsyncResponseQueueDuration, "s", "Time an asynchronous response waited between being queued and being written.");

        internal static Histogram<double> StorageDuration { get; } = Meter.CreateHistogram<double>(
            OpenCifsTelemetryNames.ServerStorageDuration, "s", "Share-backend storage call time, by operation and outcome.");

        internal static Counter<long> IoBytes { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerIoBytes, "By", "File data bytes served by READ and accepted by WRITE.");

        internal static Counter<long> NetworkIo { get; } = Meter.CreateCounter<long>(
            OpenCifsTelemetryNames.ServerNetworkIo, "By", "SMB transport payload bytes received and transmitted by the server.");

        internal static IReadOnlyList<ObservableGauge<long>> ObservableGauges { get; } = new ObservableGauge<long>[]
        {
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.BuildInfo,
                () => new Measurement<long>(
                    1,
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeComponent, "server"),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeVersion, Version)),
                "{component}",
                "Loaded OpenCIFS component and version."),
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.ServerListenerInfo, ObserveListenerInfo, "{listener}", "Running listener with its safe, bounded configuration."),
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.ServerSessionsActive, () => ObserveState(CountSessions), "{session}", "Sessions currently held by the server."),
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.ServerTreesActive, () => ObserveState(CountTrees), "{tree}", "Tree connects currently held by the server."),
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.ServerOpensActive, () => ObserveState(CountOpens), "{open}", "Opens currently held by the server."),
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.ServerChangeNotifyPending, () => ObserveState(CountPendingChangeNotify), "{request}", "Pending SMB2 CHANGE_NOTIFY subscriptions."),
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.ServerAsyncResponsesQueued, () => ObserveState(CountQueuedAsyncResponses), "{response}", "Asynchronous responses queued but not yet written."),
            Meter.CreateObservableGauge<long>(
                OpenCifsTelemetryNames.ServerDurableOpensDetached, () => ObserveState(CountDetachedDurableOpens), "{open}", "Durable opens detached from a lost connection and awaiting reconnect.")
        };

        internal static bool IsTracing
        {
            get
            {
                return Source.HasListeners();
            }
        }

        internal static void TrackSharedState(OpenCifsServerSharedState sharedState)
        {
            try
            {
                _SharedStates.AddOrUpdate(sharedState, _Marker);
            }
            catch (Exception)
            {
                // Telemetry registration must never affect server construction.
            }
        }

        internal static object? ListenerStarted(OpenCifsServerOptions options)
        {
            try
            {
                object token = new object();
                KeyValuePair<string, object?>[] tags = new KeyValuePair<string, object?>[]
                {
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeServerPort, options.BindPort),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeMinimumDialect, OpenCifsTelemetryFormat.DialectName(options.MinimumDialect)),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeMaximumDialect, OpenCifsTelemetryFormat.DialectName(options.MaximumDialect)),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeRequireSigning, options.RequireSigning),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeRequireEncryption, options.RequireEncryptionForSmb3),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeAllowAnonymous, options.AllowAnonymous),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeEnableSmb1, options.EnableSmb1)
                };
                _Listeners[token] = tags;
                ListenersActive.Add(1);
                return token;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal static void ListenerStopped(object? token)
        {
            if (token == null)
            {
                return;
            }

            try
            {
                if (_Listeners.TryRemove(token, out _))
                {
                    ListenersActive.Add(-1);
                }
            }
            catch (Exception)
            {
            }
        }

        internal static long ConnectionOpened()
        {
            try
            {
                ConnectionsAccepted.Add(1);
                ConnectionsActive.Add(1);
            }
            catch (Exception)
            {
            }

            return Stopwatch.GetTimestamp();
        }

        internal static void ConnectionClosed(long startTimestamp, string reason)
        {
            try
            {
                TagList tags = new TagList { { OpenCifsTelemetryNames.AttributeCloseReason, reason } };
                ConnectionsActive.Add(-1);
                ConnectionsClosed.Add(1, tags);
                ConnectionDuration.Record(OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp), tags);
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordError(Exception exception, string stage)
        {
            try
            {
                Errors.Add(
                    1,
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeErrorType, OpenCifsTelemetryFormat.ErrorType(exception)),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStage, stage));
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

        internal static void RecordIoBytes(long bytes, bool write)
        {
            try
            {
                IoBytes.Add(bytes, new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeIoDirection, write ? "write" : "read"));
            }
            catch (Exception)
            {
            }
        }

        internal static Activity? StartCommand(Smb2Header header)
        {
            if (!Source.HasListeners())
            {
                return null;
            }

            try
            {
                Activity? activity = Source.StartActivity("command:" + OpenCifsTelemetryFormat.CommandName(header.Command), ActivityKind.Internal);

                if (activity != null && activity.IsAllDataRequested)
                {
                    activity.SetTag(OpenCifsTelemetryNames.AttributeCommand, OpenCifsTelemetryFormat.CommandName(header.Command));
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeMessageId, header.MessageId);
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeSessionId, header.SessionId);
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeTreeId, header.TreeId);
                }

                return activity;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal static void CompleteCommand(Smb2Command command, NtStatus status, long startTimestamp, Activity? activity)
        {
            try
            {
                string outcome = OpenCifsTelemetryFormat.Outcome(status);
                string statusName = OpenCifsTelemetryFormat.StatusName(status);
                CommandDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeCommand, OpenCifsTelemetryFormat.CommandName(command)),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStatus, statusName),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, outcome));

                if (activity != null)
                {
                    activity.SetTag(OpenCifsTelemetryNames.AttributeStatus, statusName);
                    activity.SetTag(OpenCifsTelemetryNames.AttributeOutcome, outcome);

                    if (outcome == OpenCifsTelemetryFormat.OutcomeError)
                    {
                        activity.SetStatus(ActivityStatusCode.Error, statusName);
                    }
                    else
                    {
                        activity.SetStatus(ActivityStatusCode.Ok);
                    }
                }
            }
            catch (Exception)
            {
            }
        }

        internal static void FailCommand(Smb2Command command, Exception exception, long startTimestamp, Activity? activity)
        {
            try
            {
                CommandDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(startTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeCommand, OpenCifsTelemetryFormat.CommandName(command)),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStatus, OpenCifsTelemetryFormat.Other),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, OpenCifsTelemetryFormat.OutcomeException));
                RecordError(exception, StageDispatch);
                MarkFailed(activity, exception);
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordNegotiation(SmbDialect? dialect)
        {
            try
            {
                Negotiations.Add(1, new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeDialect, OpenCifsTelemetryFormat.DialectName(dialect)));
                Activity.Current?.SetTag(OpenCifsTelemetryNames.AttributeDialect, OpenCifsTelemetryFormat.DialectName(dialect));
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordAuthAttempt(string mechanism, NtStatus status, Smb2SessionFlags sessionFlags)
        {
            try
            {
                bool succeeded = status == NtStatus.Success;
                string sessionKind = !succeeded
                    ? "none"
                    : (sessionFlags & Smb2SessionFlags.IsNull) != 0
                        ? "anonymous"
                        : (sessionFlags & Smb2SessionFlags.IsGuest) != 0 ? "guest" : "user";
                AuthAttempts.Add(
                    1,
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeAuthMechanism, mechanism),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, succeeded ? OpenCifsTelemetryFormat.OutcomeSuccess : OpenCifsTelemetryFormat.OutcomeError),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeSessionKind, sessionKind));

                Activity? current = Activity.Current;

                if (current != null)
                {
                    current.SetTag(OpenCifsTelemetryNames.AttributeAuthMechanism, mechanism);
                    current.SetTag(OpenCifsTelemetryNames.AttributeSessionKind, sessionKind);
                }
            }
            catch (Exception)
            {
            }
        }

        internal static void RecordDurableReconnect(NtStatus status)
        {
            try
            {
                DurableReconnects.Add(
                    1,
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, status == NtStatus.Success ? OpenCifsTelemetryFormat.OutcomeSuccess : OpenCifsTelemetryFormat.OutcomeError),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStatus, OpenCifsTelemetryFormat.StatusName(status)));
            }
            catch (Exception)
            {
            }
        }

        internal static void MarkQueued(OpenCifsServerAsyncResponse response, string kind)
        {
            try
            {
                response.TelemetryKind = kind;
                response.TelemetryQueuedTimestamp = Stopwatch.GetTimestamp();
                Activity? current = Activity.Current;
                response.TelemetryParentContext = current != null ? current.Context : default;
            }
            catch (Exception)
            {
            }
        }

        internal static Activity? StartAsyncResponseSend(OpenCifsServerAsyncResponse response)
        {
            try
            {
                if (response.TelemetryQueuedTimestamp != 0)
                {
                    AsyncResponseQueueDuration.Record(
                        OpenCifsTelemetryFormat.ElapsedSeconds(response.TelemetryQueuedTimestamp),
                        new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeAsyncKind, response.TelemetryKind));
                }

                if (!Source.HasListeners())
                {
                    return null;
                }

                // The response was produced by another request (often on another connection). Parent the send span on
                // the producing span so the background hand-off stays inside the originating trace.
                Activity? activity = Source.StartActivity(
                    "async_response " + response.TelemetryKind,
                    ActivityKind.Producer,
                    response.TelemetryParentContext);

                if (activity != null && activity.IsAllDataRequested)
                {
                    activity.SetTag(OpenCifsTelemetryNames.AttributeAsyncKind, response.TelemetryKind);
                    activity.SetTag(OpenCifsTelemetryNames.AttributeCommand, OpenCifsTelemetryFormat.CommandName(response.Header.Command));
                    activity.SetTag(OpenCifsTelemetryNames.AttributeStatus, OpenCifsTelemetryFormat.StatusName(response.Header.Status));
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeMessageId, response.Header.MessageId);
                    activity.SetTag(OpenCifsTelemetryNames.SpanAttributeSessionId, response.Header.SessionId);
                }

                return activity;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal static void CompleteAsyncResponseSend(OpenCifsServerAsyncResponse response, Activity? activity)
        {
            try
            {
                AsyncResponsesSent.Add(1, new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeAsyncKind, response.TelemetryKind));
                activity?.SetStatus(ActivityStatusCode.Ok);
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

                // Record the type only: exception messages can carry share paths or peer-supplied names.
                activity.AddEvent(new ActivityEvent(
                    "exception",
                    tags: new ActivityTagsCollection
                    {
                        { "exception.type", exception.GetType().FullName }
                    }));
            }
            catch (Exception)
            {
            }
        }

        private static IEnumerable<Measurement<long>> ObserveListenerInfo()
        {
            List<Measurement<long>> measurements = new List<Measurement<long>>();

            try
            {
                foreach (KeyValuePair<object, KeyValuePair<string, object?>[]> entry in _Listeners)
                {
                    measurements.Add(new Measurement<long>(1, entry.Value));
                }
            }
            catch (Exception)
            {
            }

            return measurements;
        }

        private static long ObserveState(Func<OpenCifsServerSharedState, long> selector)
        {
            long total = 0;

            try
            {
                foreach (KeyValuePair<OpenCifsServerSharedState, object> entry in _SharedStates)
                {
                    OpenCifsServerSharedState sharedState = entry.Key;
                    bool lockTaken = false;

                    try
                    {
                        // Never stall a scrape behind a long request, and never stall a request behind a scrape.
                        Monitor.TryEnter(sharedState.SyncRoot, _ObserveLockTimeout, ref lockTaken);

                        if (lockTaken)
                        {
                            total += selector(sharedState);
                        }
                    }
                    finally
                    {
                        if (lockTaken)
                        {
                            Monitor.Exit(sharedState.SyncRoot);
                        }
                    }
                }
            }
            catch (Exception)
            {
            }

            return total;
        }

        private static long CountSessions(OpenCifsServerSharedState sharedState)
        {
            long count = 0;

            foreach (OpenCifsServerHost host in sharedState.Hosts)
            {
                count += host.TelemetrySessionCount;
            }

            return count;
        }

        private static long CountTrees(OpenCifsServerSharedState sharedState)
        {
            long count = 0;

            foreach (OpenCifsServerHost host in sharedState.Hosts)
            {
                count += host.TelemetryTreeCount;
            }

            return count;
        }

        private static long CountOpens(OpenCifsServerSharedState sharedState)
        {
            long count = 0;

            foreach (OpenCifsServerHost host in sharedState.Hosts)
            {
                count += host.TelemetryOpenCount;
            }

            return count;
        }

        private static long CountPendingChangeNotify(OpenCifsServerSharedState sharedState)
        {
            long count = 0;

            foreach (OpenCifsServerHost host in sharedState.Hosts)
            {
                count += host.TelemetryPendingChangeNotifyCount;
            }

            return count;
        }

        private static long CountQueuedAsyncResponses(OpenCifsServerSharedState sharedState)
        {
            long count = 0;

            foreach (OpenCifsServerHost host in sharedState.Hosts)
            {
                count += host.TelemetryQueuedAsyncResponseCount;
            }

            return count;
        }

        private static long CountDetachedDurableOpens(OpenCifsServerSharedState sharedState)
        {
            return sharedState.TelemetryDetachedDurableOpenCount;
        }

        private static readonly object _Marker = new object();
        private static readonly TimeSpan _ObserveLockTimeout = TimeSpan.FromMilliseconds(250);
        private static readonly ConditionalWeakTable<OpenCifsServerSharedState, object> _SharedStates = new ConditionalWeakTable<OpenCifsServerSharedState, object>();
        private static readonly ConcurrentDictionary<object, KeyValuePair<string, object?>[]> _Listeners = new ConcurrentDictionary<object, KeyValuePair<string, object?>[]>();

    }
}

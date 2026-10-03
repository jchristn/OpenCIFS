namespace OpenCIFS.Telemetry.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.Metrics;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Reflection;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Client.Tests.Shared;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using OpenCIFS.Server.Tests.Shared;
    using Touchstone.Core;

    /// <summary>
    /// Shared Touchstone suite that proves the OpenCIFS client and server libraries emit their documented metrics and spans,
    /// including failure paths, and that the unobserved path is safe.
    /// </summary>
    public static class TelemetryTestSuites
    {
        private const string SuiteId = "Telemetry";
        private const string SecretFileName = "telemetry-secret-payload.txt";

        /// <summary>
        /// All shared telemetry suites.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                return new List<TestSuiteDescriptor>
                {
                    TelemetrySuite()
                };
            }
        }

        /// <summary>
        /// Build the telemetry suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor TelemetrySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: SuiteId,
                displayName: "Client and server telemetry emission",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(SuiteId, "NamesAreStableAndEveryDocumentedInstrumentIsPublished", "Meter and source names are stable and every documented instrument is published with UCUM units", NamesAreStableAsync),
                    new TestCaseDescriptor(SuiteId, "LoopbackSessionEmitsServerPipelineCommandStorageAndStateTelemetry", "A loopback session emits server connection, per-stage, per-command, storage, auth, state-gauge, and byte telemetry", LoopbackServerTelemetryAsync),
                    new TestCaseDescriptor(SuiteId, "LoopbackSessionEmitsClientOperationRequestAndConnectionTelemetry", "A loopback session emits client operation, request, queue, connection, and byte telemetry with nested spans", LoopbackClientTelemetryAsync),
                    new TestCaseDescriptor(SuiteId, "MetricLabelsAreBoundedAndCarryNoPayloadsOrCredentials", "Metric labels use the documented bounded keys and never carry file names, user names, or passwords", LabelsAreBoundedAsync),
                    new TestCaseDescriptor(SuiteId, "AuthenticationFailureIsRecordedOnBothSides", "A bad password is recorded as a failed auth attempt, an error command status, and an error client span", AuthenticationFailureAsync),
                    new TestCaseDescriptor(SuiteId, "MissingFileIsRecordedWithStatusAndErrorSpans", "A missing file is recorded with its NT status, an error outcome, and error spans on both sides", MissingFileAsync),
                    new TestCaseDescriptor(SuiteId, "TransportLossAndConnectFailuresAreRecorded", "Server shutdown is recorded as a client transport failure and a closed-port connect as a failed connect", TransportFailuresAsync),
                    new TestCaseDescriptor(SuiteId, "MalformedPacketIsRecordedAsProtocolError", "A malformed packet is recorded as a server protocol error, a failed packet, and a protocol_error close", MalformedPacketAsync),
                    new TestCaseDescriptor(SuiteId, "ChangeNotifyAsyncResponseStaysInTheProducingTrace", "A CHANGE_NOTIFY completion queued by another connection is sent inside the producing request's trace", ChangeNotifyHandOffAsync),
                    new TestCaseDescriptor(SuiteId, "ScopesRecordFailuresAndTheUnobservedPathIsSafe", "Storage and packet scopes record failures, and every helper is a safe no-op when nothing listens", ScopesAndNoListenerAsync)
                });
        }

        private static Task NamesAreStableAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            TestAssertions.Equal("OpenCIFS.Server", OpenCifsTelemetryNames.ServerMeterName, "Server meter name is a public contract.");
            TestAssertions.Equal("OpenCIFS.Server", OpenCifsTelemetryNames.ServerActivitySourceName, "Server activity source name is a public contract.");
            TestAssertions.Equal("OpenCIFS.Client", OpenCifsTelemetryNames.ClientMeterName, "Client meter name is a public contract.");
            TestAssertions.Equal("OpenCIFS.Client", OpenCifsTelemetryNames.ClientActivitySourceName, "Client activity source name is a public contract.");

            using TelemetryCapture capture = new TelemetryCapture();

            // Touch both telemetry types so every static instrument exists before checking the catalog.
            TestAssertions.Equal(OpenCifsTelemetryNames.ServerMeterName, OpenCifsServerTelemetry.Meter.Name, "Server meter must use the documented name.");
            TestAssertions.Equal(OpenCifsTelemetryNames.ClientMeterName, OpenCifsClientTelemetry.Meter.Name, "Client meter must use the documented name.");
            TestAssertions.Equal(OpenCifsTelemetryNames.ServerActivitySourceName, OpenCifsServerTelemetry.Source.Name, "Server source must use the documented name.");
            TestAssertions.Equal(OpenCifsTelemetryNames.ClientActivitySourceName, OpenCifsClientTelemetry.Source.Name, "Client source must use the documented name.");

            List<string> documentedInstruments = typeof(OpenCifsTelemetryNames)
                .GetFields(BindingFlags.Public | BindingFlags.Static)
                .Where(field => field.IsLiteral && field.FieldType == typeof(string))
                .Select(field => (string)field.GetRawConstantValue()!)
                .Where(value => value.StartsWith("opencifs.", StringComparison.Ordinal) && value != OpenCifsTelemetryNames.AttributeComponent && value != OpenCifsTelemetryNames.AttributeVersion && value != OpenCifsTelemetryNames.AttributeOperation)
                .ToList();
            IReadOnlyCollection<string> published = capture.InstrumentNames;

            foreach (string instrumentName in documentedInstruments)
            {
                TestAssertions.True(published.Contains(instrumentName), "Expected documented instrument '" + instrumentName + "' to be published.");
                Instrument instrument = capture.Instrument(instrumentName)!;

                if (instrumentName.EndsWith(".duration", StringComparison.Ordinal))
                {
                    TestAssertions.Equal("s", instrument.Unit, "Expected duration instrument '" + instrumentName + "' to use seconds.");
                    TestAssertions.True(instrument is Histogram<double>, "Expected duration instrument '" + instrumentName + "' to be a histogram.");
                }

                if (instrumentName.EndsWith(".bytes", StringComparison.Ordinal) || instrumentName.EndsWith(".network.io", StringComparison.Ordinal))
                {
                    TestAssertions.Equal("By", instrument.Unit, "Expected byte instrument '" + instrumentName + "' to use bytes.");
                }

                TestAssertions.True(!String.IsNullOrWhiteSpace(instrument.Description), "Expected instrument '" + instrumentName + "' to carry a description.");
            }

            capture.ObserveGauges();
            TestAssertions.True(
                capture.Any(OpenCifsTelemetryNames.BuildInfo, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeComponent, "server") && !String.IsNullOrEmpty(measurement.Tag(OpenCifsTelemetryNames.AttributeVersion))),
                "Expected a server build-info gauge with a version.");
            TestAssertions.True(
                capture.Any(OpenCifsTelemetryNames.BuildInfo, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeComponent, "client")),
                "Expected a client build-info gauge.");
            return Task.CompletedTask;
        }

        private static async Task LoopbackServerTelemetryAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();
            await using OpenCifsClient client = server.BuildClient();
            await client.ConnectAsync(ClientTestSupport.CreateCredential(), token).ConfigureAwait(false);
            await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
            await share.Files.WriteAllBytesAsync(SecretFileName, Encoding.ASCII.GetBytes("hello telemetry"), token).ConfigureAwait(false);
            byte[] read = await share.Files.ReadAllBytesAsync(SecretFileName, token).ConfigureAwait(false);
            TestAssertions.Equal(15, read.Length, "Expected the loopback round trip to succeed.");
            await share.Directories.EnumerateAsync(String.Empty, cancellationToken: token).ConfigureAwait(false);

            // Gauges are sampled while the session and tree are still held.
            capture.ObserveGauges();
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerSessionsActive, measurement => measurement.Value >= 1), "Expected at least one active server session. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerSessionsActive));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerTreesActive, measurement => measurement.Value >= 1), "Expected at least one active server tree.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerOpensActive, measurement => measurement.Value >= 0), "Expected the opens gauge to report.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerChangeNotifyPending, measurement => measurement.Value >= 0), "Expected the change-notify gauge to report.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerAsyncResponsesQueued, measurement => measurement.Value >= 0), "Expected the async-queue gauge to report.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerDurableOpensDetached, measurement => measurement.Value >= 0), "Expected the detached-durable gauge to report.");
            TestAssertions.True(
                capture.Any(OpenCifsTelemetryNames.ServerListenerInfo, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeServerPort, server.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)) && measurement.Tag(OpenCifsTelemetryNames.AttributeRequireSigning) != null),
                "Expected listener info with the bound port and safe configuration.");

            await share.DisposeAsync().ConfigureAwait(false);
            await client.DisconnectAsync(token).ConfigureAwait(false);
            await WaitUntilAsync(() => capture.Any(OpenCifsTelemetryNames.ServerConnectionsClosed, measurement => true), token).ConfigureAwait(false);

            // Connection lifecycle.
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ServerConnectionsAccepted, measurement => true) >= 1, "Expected an accepted connection.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerConnectionsActive, measurement => measurement.Value == 1), "Expected the active-connection counter to rise.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerConnectionsClosed, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCloseReason, "client_closed")), "Expected a client_closed close. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerConnectionsClosed));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerConnectionDuration, measurement => measurement.Value >= 0), "Expected a connection duration sample.");
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ServerListenersActive, measurement => true) >= 0, "Listener counter must not go negative.");

            // Per-stage pipeline, including the queued (global lock) stage.
            foreach (string stage in new[] { "queued", "decode", "dispatch", "encode", "send" })
            {
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerPacketStageDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStage, stage)), "Expected a '" + stage + "' stage sample.");
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerPacketDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "success") && measurement.HasTag(OpenCifsTelemetryNames.AttributePacketKind, "smb2")), "Expected a successful smb2 packet sample.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerLockWaiting, measurement => measurement.Value == 1) && capture.Any(OpenCifsTelemetryNames.ServerLockWaiting, measurement => measurement.Value == -1), "Expected lock-waiting increments and decrements.");
            TestAssertions.Equal(0d, capture.Sum(OpenCifsTelemetryNames.ServerLockWaiting, measurement => true), "Expected lock-waiting to return to zero.");

            // Per-command latency and outcome.
            foreach (string command in new[] { "NEGOTIATE", "SESSION_SETUP", "TREE_CONNECT", "CREATE", "WRITE", "READ", "CLOSE", "QUERY_DIRECTORY" })
            {
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerCommandDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, command) && measurement.Tag(OpenCifsTelemetryNames.AttributeStatus) != null && measurement.Tag(OpenCifsTelemetryNames.AttributeOutcome) != null), "Expected a server command sample for " + command + ".");
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerCommandDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, "SESSION_SETUP") && measurement.HasTag(OpenCifsTelemetryNames.AttributeStatus, "MORE_PROCESSING_REQUIRED") && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "success")), "Expected MORE_PROCESSING_REQUIRED to count as success.");

            // Domain counters.
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerNegotiations, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeDialect, "2.1")), "Expected a 2.1 negotiation. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerNegotiations));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerAuthAttempts, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "success") && measurement.HasTag(OpenCifsTelemetryNames.AttributeSessionKind, "user") && measurement.Tag(OpenCifsTelemetryNames.AttributeAuthMechanism) != "unknown"), "Expected a successful user auth attempt. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerAuthAttempts));

            // Storage (outbound integration) and byte counters.
            foreach (string operation in new[] { "open", "write", "read", "enumerate" })
            {
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerStorageDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStorageOperation, operation) && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "success")), "Expected a successful storage '" + operation + "' sample. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerStorageDuration));
            }

            TestAssertions.Equal(15d, capture.Sum(OpenCifsTelemetryNames.ServerIoBytes, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeIoDirection, "write")), "Expected 15 written bytes.");
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ServerIoBytes, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeIoDirection, "read")) >= 15, "Expected at least 15 read bytes.");
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ServerNetworkIo, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeNetworkIoDirection, "receive")) > 0, "Expected received network bytes.");
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ServerNetworkIo, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeNetworkIoDirection, "transmit")) > 0, "Expected transmitted network bytes.");

            // Span tree: root server span -> stage spans -> command span -> storage span. READ may arrive alone or in a
            // compound, so walk up from the command span instead of assuming the root name.
            IReadOnlyList<Activity> activities = capture.Activities();
            Activity? commandSpan = activities.FirstOrDefault(activity => activity.DisplayName == "command:READ" && activities.Any(child => child.ParentSpanId == activity.SpanId && child.DisplayName == "storage read"));
            TestAssertions.True(commandSpan != null, "Expected a command:READ span with a 'storage read' child. Spans: " + String.Join(", ", activities.Select(activity => activity.DisplayName).Distinct()));
            Activity? dispatch = activities.FirstOrDefault(activity => activity.SpanId == commandSpan!.ParentSpanId);
            TestAssertions.True(dispatch != null && dispatch.DisplayName == "stage:dispatch", "Expected command:READ to sit under stage:dispatch.");
            Activity? root = activities.FirstOrDefault(activity => activity.SpanId == dispatch!.ParentSpanId);
            TestAssertions.True(root != null && root.Kind == ActivityKind.Server, "Expected stage:dispatch to sit under a server root span.");
            TestAssertions.True(root!.DisplayName == "SMB2 READ" || root.DisplayName == "SMB2 COMPOUND", "Expected the root to be named for its SMB2 command, got '" + root.DisplayName + "'.");
            TestAssertions.True(root.ParentSpanId == default, "Expected the server root span to start a new trace.");
            TestAssertions.Equal(ActivityStatusCode.Ok, root.Status, "Expected the READ root span to be OK.");
            TestAssertions.True(root.GetTagItem(OpenCifsTelemetryNames.SpanAttributePeerAddress) != null, "Expected the peer address on the server span.");
            List<Activity> rootChildren = activities.Where(activity => activity.ParentSpanId == root.SpanId).ToList();

            foreach (string stage in new[] { "stage:queued", "stage:decode", "stage:dispatch", "stage:encode", "stage:send" })
            {
                TestAssertions.True(rootChildren.Any(activity => activity.DisplayName == stage), "Expected a '" + stage + "' child span under the server root.");
            }

            TestAssertions.True(activities.Any(activity => activity.DisplayName == "SMB2 NEGOTIATE" && activity.Kind == ActivityKind.Server), "Expected an 'SMB2 NEGOTIATE' server root span.");
        }

        private static async Task LoopbackClientTelemetryAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();
            await using (OpenCifsClient client = server.BuildClient())
            {
                await client.ConnectAsync(ClientTestSupport.CreateCredential(), token).ConfigureAwait(false);
                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                await share.Files.WriteAllBytesAsync("client.txt", new byte[] { 1, 2, 3, 4 }, token).ConfigureAwait(false);
                await share.Files.ReadAllBytesAsync("client.txt", token).ConfigureAwait(false);
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientConnectDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "success")), "Expected a successful connect sample.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientConnectionsActive, measurement => measurement.Value == 1), "Expected the client connection counter to rise.");
            TestAssertions.Equal(0d, capture.Sum(OpenCifsTelemetryNames.ClientConnectionsActive, measurement => true), "Expected the client connection counter to return to zero after dispose.");

            // The share facade uses related compounds for whole-file reads and writes.
            foreach (string operation in new[] { "Connect", "Authenticate", "ConnectAndAuthenticate", "TreeConnect", "CompoundCreateWriteFlushClose", "CompoundOpenReadClose", "TreeDisconnect" })
            {
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientOperationDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOperation, operation) && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "success")), "Expected a successful client '" + operation + "' operation. Got: " + capture.Describe(OpenCifsTelemetryNames.ClientOperationDuration));
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientOperationQueueDuration, measurement => measurement.Value >= 0), "Expected an operation queue sample.");
            TestAssertions.Equal(0d, capture.Sum(OpenCifsTelemetryNames.ClientOperationsWaiting, measurement => true), "Expected operations-waiting to return to zero.");

            foreach (string command in new[] { "NEGOTIATE", "SESSION_SETUP", "TREE_CONNECT", "COMPOUND", "TREE_DISCONNECT" })
            {
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientRequestDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, command)), "Expected a client request sample for " + command + ". Got: " + capture.Describe(OpenCifsTelemetryNames.ClientRequestDuration));
            }

            TestAssertions.Equal(4d, capture.Sum(OpenCifsTelemetryNames.ClientIoBytes, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeIoDirection, "write")), "Expected 4 client written bytes.");
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ClientIoBytes, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeIoDirection, "read")) >= 4, "Expected client read bytes.");
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ClientNetworkIo, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeNetworkIoDirection, "transmit")) > 0, "Expected client transmitted bytes.");
            TestAssertions.True(capture.Sum(OpenCifsTelemetryNames.ClientNetworkIo, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeNetworkIoDirection, "receive")) > 0, "Expected client received bytes.");

            IReadOnlyList<Activity> activities = capture.Activities();
            Activity? readOperation = activities.FirstOrDefault(activity => activity.DisplayName == "OpenCIFS CompoundOpenReadClose");
            TestAssertions.True(readOperation != null, "Expected an 'OpenCIFS CompoundOpenReadClose' operation span. Spans: " + String.Join(", ", activities.Select(activity => activity.DisplayName).Distinct()));
            Activity? readRequest = activities.FirstOrDefault(activity => activity.DisplayName == "SMB2 COMPOUND" && activity.Kind == ActivityKind.Client && activity.ParentSpanId == readOperation!.SpanId);
            TestAssertions.True(readRequest != null, "Expected an 'SMB2 COMPOUND' client span under the operation span.");
            TestAssertions.Equal("CREATE,READ,CLOSE", readRequest!.GetTagItem("smb.compound.commands") as string, "Expected the compound command list on the client span.");
            TestAssertions.True(activities.Any(activity => activity.DisplayName == "SMB2 NEGOTIATE" && activity.Kind == ActivityKind.Client), "Expected an 'SMB2 NEGOTIATE' client span.");
            TestAssertions.True(readRequest!.GetTagItem(OpenCifsTelemetryNames.SpanAttributeMessageId) != null, "Expected the message id on the client span for cross-side correlation.");
            TestAssertions.Equal("127.0.0.1", readRequest.GetTagItem(OpenCifsTelemetryNames.SpanAttributeServerAddress) as string, "Expected the server address on the client span.");
            TestAssertions.True(activities.Any(activity => activity.DisplayName == "stage:tcp_connect"), "Expected a TCP connect stage span.");
        }

        private static async Task LabelsAreBoundedAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();
            await using (OpenCifsClient client = server.BuildClient())
            {
                await client.ConnectAsync(ClientTestSupport.CreateCredential(), token).ConfigureAwait(false);
                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                await share.Files.WriteAllBytesAsync(SecretFileName, new byte[] { 9 }, token).ConfigureAwait(false);
                await share.Files.DeleteAsync(SecretFileName, token).ConfigureAwait(false);
                await ExpectFailureAsync(() => share.Files.ReadAllBytesAsync("missing-" + SecretFileName, token)).ConfigureAwait(false);
            }

            capture.ObserveGauges();
            HashSet<string> allowedKeys = new HashSet<string>(StringComparer.Ordinal)
            {
                OpenCifsTelemetryNames.AttributeComponent, OpenCifsTelemetryNames.AttributeVersion, OpenCifsTelemetryNames.AttributeCommand,
                OpenCifsTelemetryNames.AttributeStatus, OpenCifsTelemetryNames.AttributeDialect, OpenCifsTelemetryNames.AttributeOutcome,
                OpenCifsTelemetryNames.AttributeErrorType, OpenCifsTelemetryNames.AttributeStage, OpenCifsTelemetryNames.AttributeCloseReason,
                OpenCifsTelemetryNames.AttributePacketKind, OpenCifsTelemetryNames.AttributeAuthMechanism, OpenCifsTelemetryNames.AttributeSessionKind,
                OpenCifsTelemetryNames.AttributeAsyncKind, OpenCifsTelemetryNames.AttributeStorageOperation, OpenCifsTelemetryNames.AttributeIoDirection,
                OpenCifsTelemetryNames.AttributeNetworkIoDirection, OpenCifsTelemetryNames.AttributeOperation, OpenCifsTelemetryNames.AttributeServerPort,
                OpenCifsTelemetryNames.AttributeMinimumDialect, OpenCifsTelemetryNames.AttributeMaximumDialect, OpenCifsTelemetryNames.AttributeRequireSigning,
                OpenCifsTelemetryNames.AttributeRequireEncryption, OpenCifsTelemetryNames.AttributeAllowAnonymous, OpenCifsTelemetryNames.AttributeEnableSmb1
            };
            string[] forbiddenFragments = new[] { SecretFileName, TestEnvironmentDefaults.DefaultUserName, TestEnvironmentDefaults.DefaultPassword, server.SharePath, "127.0.0.1" };
            IReadOnlyList<CapturedMeasurement> measurements = capture.AllMeasurements();
            TestAssertions.True(measurements.Count > 50, "Expected a representative set of measurements.");

            foreach (CapturedMeasurement measurement in measurements)
            {
                foreach (KeyValuePair<string, string?> tag in measurement.Tags)
                {
                    TestAssertions.True(allowedKeys.Contains(tag.Key), "Metric '" + measurement.InstrumentName + "' carries undocumented label '" + tag.Key + "'.");
                    TestAssertions.False(tag.Key.StartsWith("smb.message_id", StringComparison.Ordinal) || tag.Key == OpenCifsTelemetryNames.SpanAttributeSessionId, "Identifiers belong on spans, never on metrics.");

                    foreach (string fragment in forbiddenFragments)
                    {
                        TestAssertions.False(
                            tag.Value != null && tag.Value.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0,
                            "Metric '" + measurement.InstrumentName + "' label '" + tag.Key + "' leaked '" + fragment + "'.");
                    }
                }
            }

            foreach (Activity activity in capture.Activities())
            {
                foreach (KeyValuePair<string, string?> tag in activity.Tags)
                {
                    foreach (string fragment in new[] { SecretFileName, TestEnvironmentDefaults.DefaultPassword, server.SharePath })
                    {
                        TestAssertions.False(
                            tag.Value != null && tag.Value.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0,
                            "Span '" + activity.DisplayName + "' tag '" + tag.Key + "' leaked a payload, path, or credential.");
                    }
                }

                foreach (ActivityEvent activityEvent in activity.Events)
                {
                    foreach (KeyValuePair<string, object?> tag in activityEvent.Tags)
                    {
                        TestAssertions.False(tag.Key == "exception.message" || tag.Key == "exception.stacktrace", "Span events must not carry exception messages or stack traces.");
                    }
                }
            }
        }

        private static async Task AuthenticationFailureAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();
            await using (OpenCifsClient client = server.BuildClient())
            {
                OpenCifsClientCredential badCredential = new OpenCifsClientCredential
                {
                    UserName = TestEnvironmentDefaults.DefaultUserName,
                    UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                    Password = "definitely-wrong"
                };
                Exception failure = await ExpectFailureAsync(() => client.ConnectAsync(badCredential, token)).ConfigureAwait(false);
                TestAssertions.True(failure is OpenCifsClientException, "Expected a typed client exception for a bad password, got " + failure.GetType().Name + ".");
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerAuthAttempts, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error") && measurement.HasTag(OpenCifsTelemetryNames.AttributeSessionKind, "none")), "Expected a failed auth attempt. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerAuthAttempts));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerCommandDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, "SESSION_SETUP") && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error")), "Expected an error SESSION_SETUP command sample.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientRequestDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, "SESSION_SETUP") && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error")), "Expected an error SESSION_SETUP client request sample.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientOperationDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "exception") && measurement.Tag(OpenCifsTelemetryNames.AttributeErrorType) != null), "Expected a failed client operation with error.type.");
            TestAssertions.True(capture.Activities().Any(activity => activity.Source.Name == OpenCifsTelemetryNames.ClientActivitySourceName && activity.Status == ActivityStatusCode.Error), "Expected an error client span.");
            TestAssertions.True(capture.Activities().Any(activity => activity.DisplayName == "command:SESSION_SETUP" && activity.Status == ActivityStatusCode.Error), "Expected an error server command span.");
        }

        private static async Task MissingFileAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();
            await using (OpenCifsClient client = server.BuildClient())
            {
                await client.ConnectAsync(ClientTestSupport.CreateCredential(), token).ConfigureAwait(false);
                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                Exception failure = await ExpectFailureAsync(() => share.Files.ReadAllBytesAsync("does-not-exist.bin", token)).ConfigureAwait(false);
                TestAssertions.True(failure is OpenCifsClientException, "Expected a typed client exception for a missing file.");
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerCommandDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, "CREATE") && measurement.HasTag(OpenCifsTelemetryNames.AttributeStatus, "OBJECT_NAME_NOT_FOUND") && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error")), "Expected CREATE OBJECT_NAME_NOT_FOUND. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerCommandDuration));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientRequestDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStatus, "OBJECT_NAME_NOT_FOUND") && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error")), "Expected the client to record the NT status. Got: " + capture.Describe(OpenCifsTelemetryNames.ClientRequestDuration));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientOperationDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "exception") && measurement.HasTag(OpenCifsTelemetryNames.AttributeErrorType, nameof(OpenCifsStatusException))), "Expected a failed client operation typed as OpenCifsStatusException. Got: " + capture.Describe(OpenCifsTelemetryNames.ClientOperationDuration));
            Activity? createRoot = capture.Activities().FirstOrDefault(activity => activity.DisplayName == "command:CREATE" && activity.Status == ActivityStatusCode.Error);
            TestAssertions.True(createRoot != null, "Expected an error command:CREATE span.");
            TestAssertions.Equal("OBJECT_NAME_NOT_FOUND", createRoot!.GetTagItem(OpenCifsTelemetryNames.AttributeStatus) as string, "Expected the status on the error span.");
            TestAssertions.True(capture.Activities().Any(activity => activity.Kind == ActivityKind.Client && activity.Status == ActivityStatusCode.Error && (activity.GetTagItem(OpenCifsTelemetryNames.AttributeStatus) as string) == "OBJECT_NAME_NOT_FOUND"), "Expected an error client request span carrying the status.");
        }

        private static async Task TransportFailuresAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();
            await using (OpenCifsClient client = server.BuildClient())
            {
                await client.ConnectAsync(ClientTestSupport.CreateCredential(), token).ConfigureAwait(false);
                await server.StopListenerAsync().ConfigureAwait(false);
                await WaitUntilAsync(() => capture.Any(OpenCifsTelemetryNames.ServerConnectionsClosed, measurement => true), token).ConfigureAwait(false);
                Exception failure = await ExpectFailureAsync(() => client.EchoAsync(token)).ConfigureAwait(false);
                TestAssertions.True(failure is OpenCifsClientTransportException, "Expected a transport exception after the server stopped, got " + failure.GetType().Name + ".");
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerConnectionsClosed, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCloseReason, "shutdown")), "Expected a shutdown close. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerConnectionsClosed));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientTransportFailures, measurement => measurement.Tag(OpenCifsTelemetryNames.AttributeErrorType) != null), "Expected a client transport failure.");
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientOperationDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOperation, "Echo") && measurement.HasTag(OpenCifsTelemetryNames.AttributeErrorType, nameof(OpenCifsClientTransportException))), "Expected the failed Echo typed as a transport exception. Got: " + capture.Describe(OpenCifsTelemetryNames.ClientOperationDuration));
            TestAssertions.Equal(0d, capture.Sum(OpenCifsTelemetryNames.ClientConnectionsActive, measurement => true), "Expected the client connection counter to be released after transport loss.");

            capture.Clear();
            int closedPort = ReserveClosedPort();
            await using (OpenCifsClient client = new OpenCifsClientBuilder().WithServer("127.0.0.1", closedPort).WithConnectTimeoutMs(5000).Build())
            {
                await ExpectFailureAsync(() => client.ConnectAsync(ClientTestSupport.CreateCredential(), token)).ConfigureAwait(false);
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ClientConnectDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "exception") && measurement.Tag(OpenCifsTelemetryNames.AttributeErrorType) != null), "Expected a failed connect sample. Got: " + capture.Describe(OpenCifsTelemetryNames.ClientConnectDuration));
            TestAssertions.Equal(0d, capture.Sum(OpenCifsTelemetryNames.ClientConnectionsActive, measurement => true), "A failed connect must not leak an active connection.");
            TestAssertions.True(capture.Activities().Any(activity => activity.DisplayName == "stage:tcp_connect"), "Expected the TCP connect stage span on a failed connect.");
        }

        private static async Task MalformedPacketAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();

            using (TcpClient rawClient = new TcpClient())
            {
                await rawClient.ConnectAsync(IPAddress.Loopback, server.Port, token).ConfigureAwait(false);
                NetworkStream stream = rawClient.GetStream();

                // An SMB2 protocol id followed by a truncated header.
                byte[] malformed = new byte[] { 0xFE, (byte)'S', (byte)'M', (byte)'B', 0x40, 0x00, 0x00, 0x00, 0x00, 0x00 };
                await ServerDirectTcpTestSupport.WriteDirectTcpFrameAsync(stream, malformed, token).ConfigureAwait(false);
                await WaitUntilAsync(() => capture.Any(OpenCifsTelemetryNames.ServerConnectionsClosed, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCloseReason, "protocol_error")), token).ConfigureAwait(false);
            }

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerConnectionsClosed, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCloseReason, "protocol_error")), "Expected a protocol_error close. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerConnectionsClosed));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerErrors, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStage, "decode") && measurement.Tag(OpenCifsTelemetryNames.AttributeErrorType) != null), "Expected a decode-stage server error. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerErrors));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerPacketDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "exception")), "Expected a failed packet sample.");
            Activity? root = capture.Activities().FirstOrDefault(activity => activity.Kind == ActivityKind.Server && activity.Status == ActivityStatusCode.Error);
            TestAssertions.True(root != null, "Expected an error server root span.");
            TestAssertions.Equal("decode", root!.GetTagItem(OpenCifsTelemetryNames.AttributeStage) as string, "Expected the failing stage on the root span.");
            TestAssertions.True(root.Events.Any(activityEvent => activityEvent.Name == "exception"), "Expected an exception event on the root span.");
        }

        private static async Task ChangeNotifyHandOffAsync(CancellationToken token)
        {
            await using TelemetryLoopbackServer server = await TelemetryLoopbackServer.StartAsync(token).ConfigureAwait(false);
            using TelemetryCapture capture = new TelemetryCapture();
            await using OpenCifsClient watcher = server.BuildClient();
            await using OpenCifsClient writer = server.BuildClient();
            await watcher.ConnectAsync(ClientTestSupport.CreateCredential(), token).ConfigureAwait(false);
            await writer.ConnectAsync(ClientTestSupport.CreateCredential(), token).ConfigureAwait(false);
            await using OpenCifsShareSession watcherShare = await watcher.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
            await using OpenCifsShareSession writerShare = await writer.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
            await writerShare.Directories.CreateAsync("watched", token).ConfigureAwait(false);

            using CancellationTokenSource waitTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            waitTimeout.CancelAfter(TimeSpan.FromSeconds(20));
            Task<OpenCifsClientChangeNotification[]> waitTask = watcherShare.Directories.WaitForChangeAsync("watched", FileNotifyChangeFilter.FileName, cancellationToken: waitTimeout.Token);
            await WaitUntilAsync(() => capture.Any(OpenCifsTelemetryNames.ServerCommandDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, "CHANGE_NOTIFY")), token).ConfigureAwait(false);

            await writerShare.Files.WriteAllBytesAsync("watched/new.txt", new byte[] { 1 }, token).ConfigureAwait(false);
            OpenCifsClientChangeNotification[] changes = await waitTask.ConfigureAwait(false);
            TestAssertions.True(changes.Length > 0, "Expected a change notification.");
            await WaitUntilAsync(() => capture.Any(OpenCifsTelemetryNames.ServerAsyncResponsesSent, measurement => true), token).ConfigureAwait(false);

            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerCommandDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeCommand, "CHANGE_NOTIFY") && measurement.HasTag(OpenCifsTelemetryNames.AttributeStatus, "PENDING")), "Expected the interim PENDING CHANGE_NOTIFY sample. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerCommandDuration));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerAsyncResponsesSent, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeAsyncKind, "change_notify")), "Expected a change_notify async response. Got: " + capture.Describe(OpenCifsTelemetryNames.ServerAsyncResponsesSent));
            TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerAsyncResponseQueueDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeAsyncKind, "change_notify")), "Expected an async queue-duration sample.");

            IReadOnlyList<Activity> activities = capture.Activities();
            Activity? send = activities.FirstOrDefault(activity => activity.DisplayName == "async_response change_notify");
            TestAssertions.True(send != null, "Expected an async_response send span.");
            TestAssertions.Equal(ActivityKind.Producer, send!.Kind, "Expected the async send span to be a producer span.");
            Activity? producer = activities.FirstOrDefault(activity => activity.SpanId == send.ParentSpanId);
            TestAssertions.True(producer != null, "Expected the async send span to be parented on the span that produced the notification.");
            TestAssertions.Equal(producer!.TraceId, send.TraceId, "Expected the background hand-off to stay inside the producing trace.");
            TestAssertions.True(producer.DisplayName.StartsWith("command:", StringComparison.Ordinal) || producer.DisplayName.StartsWith("storage ", StringComparison.Ordinal), "Expected the producer to be the writer's command or storage span, got '" + producer.DisplayName + "'.");
        }

        private static Task ScopesAndNoListenerAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            using (TelemetryCapture capture = new TelemetryCapture())
            {
                using (OpenCifsServerStorageScope storage = OpenCifsServerStorageScope.Start(OpenCifsServerTelemetry.StorageDelete))
                {
                    storage.Fail(new System.IO.IOException("disk full"));
                }

                using (OpenCifsServerStorageScope storage = OpenCifsServerStorageScope.Start(OpenCifsServerTelemetry.StorageRename))
                {
                    // Disposed without Succeed: an exception escaped the backend call.
                }

                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerStorageDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStorageOperation, "delete") && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error")), "Expected a failed storage delete.");
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerStorageDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStorageOperation, "rename") && measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error")), "Expected an unconfirmed storage rename to count as an error.");
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerErrors, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStage, "storage") && measurement.HasTag(OpenCifsTelemetryNames.AttributeErrorType, "IOException")), "Expected a storage-stage error typed IOException.");
                TestAssertions.True(capture.Activities("storage delete").Any(activity => activity.Status == ActivityStatusCode.Error), "Expected an error storage span.");

                using (OpenCifsServerPacketScope packet = new OpenCifsServerPacketScope(new IPEndPoint(IPAddress.Loopback, 50000), 445, 64))
                {
                    packet.BeginStage(OpenCifsServerTelemetry.StageQueued);
                    packet.BeginStage(OpenCifsServerTelemetry.StageDecode);
                    packet.Fail(new ProtocolEncodingException("truncated"));
                }

                using (OpenCifsServerPacketScope abandoned = new OpenCifsServerPacketScope(null, 445, 64))
                {
                    abandoned.BeginStage(OpenCifsServerTelemetry.StageQueued);
                }

                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerErrors, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeStage, "decode") && measurement.HasTag(OpenCifsTelemetryNames.AttributeErrorType, nameof(ProtocolEncodingException))), "Expected a decode-stage packet error.");
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerPacketDuration, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error")), "Expected an abandoned packet to count as an error.");
                TestAssertions.True(capture.Activities("stage:decode").Any(activity => activity.Status == ActivityStatusCode.Error), "Expected the failing stage span to be marked as an error.");

                OpenCifsServerTelemetry.RecordDurableReconnect(NtStatus.Success);
                OpenCifsServerTelemetry.RecordDurableReconnect(NtStatus.ObjectNameNotFound);
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerDurableReconnects, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "success")), "Expected a successful durable reconnect.");
                TestAssertions.True(capture.Any(OpenCifsTelemetryNames.ServerDurableReconnects, measurement => measurement.HasTag(OpenCifsTelemetryNames.AttributeOutcome, "error") && measurement.HasTag(OpenCifsTelemetryNames.AttributeStatus, "OBJECT_NAME_NOT_FOUND")), "Expected a failed durable reconnect with status.");
            }

            // With no listener attached, every helper must be a safe, allocation-light no-op.
            TestAssertions.False(OpenCifsServerTelemetry.Source.HasListeners(), "Expected no server listeners once the capture is disposed.");
            TestAssertions.False(OpenCifsClientTelemetry.Source.HasListeners(), "Expected no client listeners once the capture is disposed.");
            // .NET 8 leaves Instrument.Enabled set after the last MeterListener is disposed (fixed in later runtimes), so
            // the shared no-op scope is only guaranteed once the runtime reports the instrument disabled.
            if (!OpenCifsServerTelemetry.StorageDuration.Enabled)
            {
                TestAssertions.True(ReferenceEquals(OpenCifsServerStorageScope.Start(OpenCifsServerTelemetry.StorageRead), OpenCifsServerStorageScope.Start(OpenCifsServerTelemetry.StorageWrite)), "Expected the unobserved storage scope to be a shared no-op.");
            }
            TestAssertions.True(OpenCifsServerTelemetry.StartCommand(new Smb2Header { Command = Smb2Command.Read }) == null, "Expected no command span when unobserved.");
            TestAssertions.True(OpenCifsClientTelemetry.StartRequest("READ", null, "127.0.0.1", 445) == null, "Expected no client span when unobserved.");
            TestAssertions.True(OpenCifsClientTelemetry.StartOperation("Read", "127.0.0.1", 445) == null, "Expected no operation span when unobserved.");

            using (OpenCifsServerStorageScope storage = OpenCifsServerStorageScope.Start(OpenCifsServerTelemetry.StorageRead))
            {
                storage.Fail(new InvalidOperationException("ignored"));
                storage.Succeed();
            }

            using (OpenCifsServerPacketScope packet = new OpenCifsServerPacketScope(null, 445, 10))
            {
                packet.BeginStage(OpenCifsServerTelemetry.StageDecode);
                packet.Describe(OpenCifsServerTelemetry.PacketKindSmb2, new Smb2Header { Command = Smb2Command.Echo }, 1, wasEncrypted: false);
                packet.Fail(new InvalidOperationException("ignored"));
            }

            OpenCifsServerTelemetry.CompleteCommand(Smb2Command.Read, NtStatus.Success, Stopwatch.GetTimestamp(), null);
            OpenCifsServerTelemetry.FailCommand(Smb2Command.Read, new InvalidOperationException("ignored"), Stopwatch.GetTimestamp(), null);
            OpenCifsServerTelemetry.MarkFailed(null, new InvalidOperationException("ignored"));
            OpenCifsServerTelemetry.ListenerStopped(null);
            OpenCifsServerTelemetry.ListenerStopped(new object());
            OpenCifsClientTelemetry.CompleteRequest("READ", null, NtStatus.AccessDenied, Stopwatch.GetTimestamp(), null);
            OpenCifsClientTelemetry.FailRequest("READ", new OperationCanceledException(), Stopwatch.GetTimestamp(), null);
            OpenCifsClientTelemetry.FailOperation("Read", new InvalidOperationException("ignored"), Stopwatch.GetTimestamp(), null);
            OpenCifsClientTelemetry.RecordTransportFailure(new System.IO.IOException("ignored"));
            OpenCifsServerAsyncResponse asyncResponse = new OpenCifsServerAsyncResponse { Header = new Smb2Header { Command = Smb2Command.OplockBreak } };
            OpenCifsServerTelemetry.MarkQueued(asyncResponse, OpenCifsServerTelemetry.AsyncKindOplockBreak);
            TestAssertions.True(OpenCifsServerTelemetry.StartAsyncResponseSend(asyncResponse) == null, "Expected no async span when unobserved.");
            OpenCifsServerTelemetry.CompleteAsyncResponseSend(asyncResponse, null);

            // Label vocabulary stays bounded for unknown peer input.
            TestAssertions.Equal("OTHER", OpenCifsTelemetryFormat.StatusName((NtStatus)0xC0DEC0DE), "Unknown NT statuses must collapse to OTHER.");
            TestAssertions.Equal("OTHER", OpenCifsTelemetryFormat.CommandName((Smb2Command)0x7777), "Unknown commands must collapse to OTHER.");
            TestAssertions.Equal("QUERY_DIRECTORY", OpenCifsTelemetryFormat.CommandName(Smb2Command.QueryDirectory), "Commands use upper snake case.");
            TestAssertions.Equal("warning", OpenCifsTelemetryFormat.Outcome(NtStatus.NoMoreFiles), "Warning-severity statuses map to warning.");
            TestAssertions.Equal("error", OpenCifsTelemetryFormat.Outcome(NtStatus.AccessDenied), "Error-severity statuses map to error.");
            return Task.CompletedTask;
        }

        private static async Task<Exception> ExpectFailureAsync(Func<Task> action)
        {
            try
            {
                await action().ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                return exception;
            }

            throw new InvalidOperationException("Expected the operation to fail, but it succeeded.");
        }

        private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken token)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            while (!condition() && stopwatch.Elapsed < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(20, token).ConfigureAwait(false);
            }
        }

        private static int ReserveClosedPort()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}

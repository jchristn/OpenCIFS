# OpenCIFS Telemetry

`OpenCIFS.Server` and `OpenCIFS.Client` emit metrics and traces so an operator can see, from dashboards and traces alone, where time goes inside an SMB server or client and what failed. This document is the contract: every meter, activity source, instrument, label, and span the libraries emit, how a host subscribes to them, recommended alerts, and a dashboard layout.

## Contents

1. [Design](#design)
2. [Names](#names)
3. [Enabling and subscribing](#enabling-and-subscribing)
4. [Metrics catalog](#metrics-catalog)
5. [Label vocabulary](#label-vocabulary)
6. [Spans catalog](#spans-catalog)
7. [Trace context and correlation](#trace-context-and-correlation)
8. [Cardinality, privacy, and safety](#cardinality-privacy-and-safety)
9. [Recommended PromQL alerts](#recommended-promql-alerts)
10. [Dashboard map](#dashboard-map)
11. [Known limits](#known-limits)

## Design

OpenCIFS is a set of libraries, so it emits and the host collects:

- Emission uses only the base-class-library `System.Diagnostics.Metrics.Meter` and `System.Diagnostics.ActivitySource` types. The packages take no dependency on OpenTelemetry, Radiant, Prometheus, or any exporter, and never open a connection to a backend.
- Nothing is recorded unless a listener subscribes. Unobserved instruments are no-ops, span helpers return `null` without allocating, and the storage scope returns a shared no-op instance.
- Instrumentation is best-effort. Every telemetry helper catches its own failures, so a broken listener or exporter can never fail an SMB request, a connection, or a client call.
- All names live in one public constants class, `OpenCIFS.Protocol.OpenCifsTelemetryNames`, so a host can reference them without string literals.
- Durations are histograms in seconds (UCUM `s`); byte counts use `By`. Quantiles (p50, p95, p99) are computed in the backend from histogram buckets, never in process.

## Names

| Kind | Name | Constant |
| --- | --- | --- |
| Meter | `OpenCIFS.Server` | `OpenCifsTelemetryNames.ServerMeterName` |
| Activity source | `OpenCIFS.Server` | `OpenCifsTelemetryNames.ServerActivitySourceName` |
| Meter | `OpenCIFS.Client` | `OpenCifsTelemetryNames.ClientMeterName` |
| Activity source | `OpenCIFS.Client` | `OpenCifsTelemetryNames.ClientActivitySourceName` |

The meter and activity-source version is the package version (for example `0.2.1-alpha`). Treat these names as a public API; they will not change without a breaking-change note in `CHANGELOG.md`.

## Enabling and subscribing

There is nothing to enable in OpenCIFS and no OpenCIFS configuration keys: telemetry is always emitted and costs effectively nothing until a host subscribes. To turn it off, do not subscribe. Sampling, export endpoints, and resource attributes are host concerns.

### Radiant

```csharp
RadiantSettings settings = new RadiantSettings("my-file-service");
settings.Sources.AddMeter(OpenCifsTelemetryNames.ServerMeterName);
settings.Sources.AddActivitySource(OpenCifsTelemetryNames.ServerActivitySourceName);
settings.Sources.AddMeter(OpenCifsTelemetryNames.ClientMeterName);
settings.Sources.AddActivitySource(OpenCifsTelemetryNames.ClientActivitySourceName);

using (RadiantHost host = RadiantHost.Start(settings))
{
    await serverApplication.RunAsync(cancellationToken);
}
```

If the host also runs Watson, add `"Watson"` to the same settings so HTTP spans and SMB spans land in one Tempo instance.

### OpenTelemetry .NET SDK

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics
        .AddMeter(OpenCifsTelemetryNames.ServerMeterName, OpenCifsTelemetryNames.ClientMeterName)
        .AddRuntimeInstrumentation()
        .AddOtlpExporter(options => options.Endpoint = new Uri("http://127.0.0.1:4317")))
    .WithTracing(tracing => tracing
        .AddSource(OpenCifsTelemetryNames.ServerActivitySourceName, OpenCifsTelemetryNames.ClientActivitySourceName)
        .AddOtlpExporter(options => options.Endpoint = new Uri("http://127.0.0.1:4317")));
```

### Ad hoc inspection

```
dotnet-counters monitor --process-id <pid> --counters OpenCIFS.Server,OpenCIFS.Client
dotnet-trace collect --process-id <pid> --providers Microsoft-Diagnostics-DiagnosticSource
```

An in-process `MeterListener` and `ActivityListener` also work; the test suite (`src/OpenCIFS.Test.Shared/Telemetry`) uses exactly that.

## Metrics catalog

Prometheus names assume the standard OpenTelemetry Prometheus mapping (dots to underscores, unit suffix, `_total` on counters, `_bucket` / `_sum` / `_count` on histograms). A histogram's `_count` series is its event counter, so every duration histogram below doubles as an operation counter.

### Server (`OpenCIFS.Server`)

| Instrument | Prometheus name | Type | Unit | Labels | Description |
| --- | --- | --- | --- | --- | --- |
| `opencifs.build.info` | `opencifs_build_info` | Observable gauge | `{component}` | `opencifs.component`=`server`, `opencifs.version` | Always 1; identifies the loaded server version. |
| `opencifs.server.listeners.active` | `opencifs_server_listeners_active` | UpDownCounter | `{listener}` | none | Running direct-TCP listeners. |
| `opencifs.server.listener.info` | `opencifs_server_listener_info` | Observable gauge | `{listener}` | `server.port`, `smb.dialect.min`, `smb.dialect.max`, `smb.signing.required`, `smb.encryption.required`, `smb.anonymous.allowed`, `smb.smb1.enabled` | Always 1 per running listener; safe configuration. |
| `opencifs.server.connections.accepted` | `opencifs_server_connections_accepted_total` | Counter | `{connection}` | none | TCP connections accepted. |
| `opencifs.server.connections.active` | `opencifs_server_connections_active` | UpDownCounter | `{connection}` | none | TCP connections currently open. |
| `opencifs.server.connections.closed` | `opencifs_server_connections_closed_total` | Counter | `{connection}` | `reason` | Connections closed, by reason. |
| `opencifs.server.connection.duration` | `opencifs_server_connection_duration_seconds` | Histogram | `s` | `reason` | Connection lifetime. |
| `opencifs.server.packet.duration` | `opencifs_server_packet_duration_seconds` | Histogram | `s` | `smb.packet.kind`, `outcome` | End-to-end inbound packet time (queued + decode + dispatch + encode + send). |
| `opencifs.server.packet.stage.duration` | `opencifs_server_packet_stage_duration_seconds` | Histogram | `s` | `stage` | Time per packet stage: `queued`, `decode`, `dispatch`, `encode`, `send`. |
| `opencifs.server.lock.waiting` | `opencifs_server_lock_waiting` | UpDownCounter | `{packet}` | none | Packets currently waiting for the server-wide state lock. |
| `opencifs.server.command.duration` | `opencifs_server_command_duration_seconds` | Histogram | `s` | `smb.command`, `smb.status`, `outcome` | Per-SMB2-command handling time and result. |
| `opencifs.server.errors` | `opencifs_server_errors_total` | Counter | `{error}` | `error.type`, `stage` | Exceptions raised while handling packets, commands, or storage calls. |
| `opencifs.server.negotiations` | `opencifs_server_negotiations_total` | Counter | `{negotiation}` | `smb.dialect` | Completed dialect negotiations. |
| `opencifs.server.auth.attempts` | `opencifs_server_auth_attempts_total` | Counter | `{attempt}` | `auth.mechanism`, `outcome`, `smb.session.kind` | Completed session authentication handshakes. |
| `opencifs.server.sessions.active` | `opencifs_server_sessions_active` | Observable gauge | `{session}` | none | Sessions held (authenticated or mid-handshake). |
| `opencifs.server.trees.active` | `opencifs_server_trees_active` | Observable gauge | `{tree}` | none | Tree connects held. |
| `opencifs.server.opens.active` | `opencifs_server_opens_active` | Observable gauge | `{open}` | none | File, directory, and named-pipe opens held. |
| `opencifs.server.durable_opens.detached` | `opencifs_server_durable_opens_detached` | Observable gauge | `{open}` | none | Durable opens detached from a lost connection, awaiting reconnect. |
| `opencifs.server.durable_reconnects` | `opencifs_server_durable_reconnects_total` | Counter | `{reconnect}` | `outcome`, `smb.status` | Durable-handle reconnect attempts. |
| `opencifs.server.change_notify.pending` | `opencifs_server_change_notify_pending` | Observable gauge | `{request}` | none | Pending CHANGE_NOTIFY subscriptions. |
| `opencifs.server.async_responses.queued` | `opencifs_server_async_responses_queued` | Observable gauge | `{response}` | none | Server-initiated responses (breaks, notifications) queued but not yet written. |
| `opencifs.server.async_responses.sent` | `opencifs_server_async_responses_sent_total` | Counter | `{response}` | `smb.async.kind` | Server-initiated responses written. |
| `opencifs.server.async_response.queue.duration` | `opencifs_server_async_response_queue_duration_seconds` | Histogram | `s` | `smb.async.kind` | Time from queueing an async response to writing it. |
| `opencifs.server.storage.duration` | `opencifs_server_storage_duration_seconds` | Histogram | `s` | `storage.operation`, `outcome` | Share-backend storage call time. |
| `opencifs.server.io.bytes` | `opencifs_server_io_bytes_total` | Counter | `By` | `smb.io.direction` | File data bytes served by READ and accepted by WRITE. |
| `opencifs.server.network.io` | `opencifs_server_network_io_bytes_total` | Counter | `By` | `network.io.direction` | SMB transport payload bytes received and transmitted. |

The observable gauges sample live state under the server-wide lock with a bounded 250 ms `TryEnter`, so a scrape never stalls a request and a long request never stalls a scrape (a contended sample is skipped, not blocked).

### Client (`OpenCIFS.Client`)

| Instrument | Prometheus name | Type | Unit | Labels | Description |
| --- | --- | --- | --- | --- | --- |
| `opencifs.build.info` | `opencifs_build_info` | Observable gauge | `{component}` | `opencifs.component`=`client`, `opencifs.version` | Always 1; identifies the loaded client version. |
| `opencifs.client.operation.duration` | `opencifs_client_operation_duration_seconds` | Histogram | `s` | `opencifs.operation`, `outcome`, `error.type` (failures only) | Public `OpenCifsClientConnection` operation time. |
| `opencifs.client.operation.queue.duration` | `opencifs_client_operation_queue_duration_seconds` | Histogram | `s` | `opencifs.operation` | Wait for the per-connection operation lock (callers sharing one client). |
| `opencifs.client.operations.waiting` | `opencifs_client_operations_waiting` | UpDownCounter | `{operation}` | none | Operations currently waiting for a connection's operation lock. |
| `opencifs.client.request.duration` | `opencifs_client_request_duration_seconds` | Histogram | `s` | `smb.command`, `smb.status`, `outcome` | SMB2 request round trip (`COMPOUND` for related compounds). |
| `opencifs.client.connect.duration` | `opencifs_client_connect_duration_seconds` | Histogram | `s` | `outcome`, `error.type` (failures only) | TCP connect plus NEGOTIATE. |
| `opencifs.client.connections.active` | `opencifs_client_connections_active` | UpDownCounter | `{connection}` | none | Established client transports. |
| `opencifs.client.transport.failures` | `opencifs_client_transport_failures_total` | Counter | `{failure}` | `error.type` | Transport losses (peer close, reset, write failure). |
| `opencifs.client.requests.abandoned` | `opencifs_client_requests_abandoned_total` | Counter | `{request}` | none | Requests whose caller cancelled while awaiting the response (drained later). |
| `opencifs.client.io.bytes` | `opencifs_client_io_bytes_total` | Counter | `By` | `smb.io.direction` | File data bytes read and written. |
| `opencifs.client.network.io` | `opencifs_client_network_io_bytes_total` | Counter | `By` | `network.io.direction` | SMB transport payload bytes received and transmitted. |

### Runtime metrics

The libraries do not emit runtime metrics themselves. Add the host's runtime instrumentation (Radiant's built-in runtime metrics, or `AddRuntimeInstrumentation()` in the OpenTelemetry SDK, or the .NET 9+ built-in `System.Runtime` meter).

## Label vocabulary

Every label value comes from a fixed set, including when a peer sends unknown values.

| Label | Values |
| --- | --- |
| `outcome` | `success`, `warning` (NT warning severity, for example `NO_MORE_FILES`), `error` (NT error severity), `exception` (a thrown exception), `cancelled` (client: the caller's token fired). `MORE_PROCESSING_REQUIRED` counts as `success`. |
| `smb.command` | SMB2 command in upper snake case: `NEGOTIATE`, `SESSION_SETUP`, `LOGOFF`, `TREE_CONNECT`, `TREE_DISCONNECT`, `CREATE`, `CLOSE`, `FLUSH`, `READ`, `WRITE`, `LOCK`, `IOCTL`, `CANCEL`, `ECHO`, `QUERY_DIRECTORY`, `CHANGE_NOTIFY`, `QUERY_INFO`, `SET_INFO`, `OPLOCK_BREAK`, client-only `COMPOUND`, or `OTHER`. |
| `smb.status` | NT status name in upper snake case for every status OpenCIFS defines (`SUCCESS`, `PENDING`, `ACCESS_DENIED`, `LOGON_FAILURE`, `OBJECT_NAME_NOT_FOUND`, `SHARING_VIOLATION`, `DISK_FULL`, ...), otherwise `OTHER`. |
| `smb.dialect`, `smb.dialect.min`, `smb.dialect.max` | `1.0`, `2.0.2`, `2.1`, `3.0`, `3.0.2`, `3.1.1`, `unknown`. |
| `stage` | Packet stages `queued`, `decode`, `dispatch`, `encode`, `send`; error-only stage `storage`. |
| `reason` | `client_closed`, `transport_error`, `protocol_error`, `server_error`, `shutdown`. |
| `smb.packet.kind` | `smb2`, `smb2_compound`, `smb1_negotiate`. |
| `auth.mechanism` | `ntlm`, `spnego_ntlm`, `legacy_ntlm`, `kerberos` (rejected as unsupported), `unknown` (malformed first leg). |
| `smb.session.kind` | `user`, `guest`, `anonymous`, `none` (failed). |
| `smb.async.kind` | `oplock_break`, `lease_break`, `change_notify`, `change_notify_cancelled`, `other`. |
| `storage.operation` | `open`, `read`, `write`, `flush`, `enumerate`, `stat`, `create_directory`, `delete`, `rename`. |
| `smb.io.direction` | `read`, `write`. |
| `network.io.direction` | `receive`, `transmit`. |
| `opencifs.operation` | The public `OpenCifsClientConnection` method name without `Async` (for example `ConnectAndAuthenticate`, `TreeConnect`, `CompoundOpenReadClose`, `Read`, `Write`, `QueryDirectory`, `ChangeNotify`, `Echo`), about 40 values. |
| `error.type` | Exception type name (for example `ProtocolEncodingException`, `IOException`, `OpenCifsStatusException`, `OpenCifsClientTransportException`). Never the message. |

## Spans catalog

### Server

Each inbound packet is its own trace. The waterfall for one request looks like this:

```
SMB2 READ                       (Server)    root span per inbound packet
  stage:queued                  (Internal)  waiting for the server-wide state lock
  stage:decode                  (Internal)  decrypt, parse, signature and credit validation
  stage:dispatch                (Internal)
    command:READ                (Internal)  one per SMB2 command (several in a compound)
      storage read              (Internal)  one per share-backend call
  stage:encode                  (Internal)  sign, encrypt, frame
  stage:send                    (Internal)  socket write
```

| Span | Kind | Attributes | Status |
| --- | --- | --- | --- |
| `SMB2 <COMMAND>`, `SMB2 COMPOUND`, `SMB1 NEGOTIATE` (starts as `SMB2 request` until decoded) | Server | `network.transport`, `network.peer.address`, `network.peer.port`, `server.port`, `smb.packet.kind`, `smb.command`, `smb.compound.count`, `smb.encrypted`, `smb.message_id`, `smb.session_id`, `smb.tree_id`, `outcome`; on failure `stage`, `error.type` and an `exception` event | `Error` when a stage throws; otherwise `Ok` |
| `stage:<queued\|decode\|dispatch\|encode\|send>` | Internal | `stage` | `Error` on the stage that threw |
| `command:<COMMAND>` | Internal | `smb.command`, `smb.status`, `outcome`, `smb.message_id`, `smb.session_id`, `smb.tree_id`; `smb.dialect` on NEGOTIATE; `auth.mechanism` and `smb.session.kind` on a completed SESSION_SETUP | `Error` on NT error severity or exception |
| `storage <operation>` | Internal | `storage.operation` | `Error` when the backend call threw |
| `async_response <kind>` | Producer | `smb.async.kind`, `smb.command`, `smb.status`, `smb.message_id`, `smb.session_id` | `Error` when the write fails |

### Client

```
OpenCIFS CompoundOpenReadClose  (Internal)  one per public operation; nests under the caller's span
  SMB2 COMPOUND                 (Client)    one per SMB2 request on the wire
```

```
OpenCIFS ConnectAndAuthenticate (Internal)
  OpenCIFS Connect              (Internal)
    stage:tcp_connect           (Client)    TCP connect only
    SMB2 NEGOTIATE              (Client)
  OpenCIFS Authenticate         (Internal)
    SMB2 SESSION_SETUP          (Client)    one per handshake leg
```

| Span | Kind | Attributes | Status |
| --- | --- | --- | --- |
| `OpenCIFS <Operation>` | Internal | `opencifs.operation`, `server.address`, `server.port`, `smb.io.bytes` (reads and writes), `outcome`, `smb.status` (status failures), `error.type` | `Error` on exception; cancellations are tagged, not marked as errors |
| `SMB2 <COMMAND>`, `SMB2 COMPOUND` | Client | `network.transport`, `server.address`, `server.port`, `smb.command`, `smb.status`, `outcome`, `smb.message_id`, `smb.session_id`, `smb.tree_id`; compounds add `smb.compound.count` and `smb.compound.commands` (for example `CREATE,READ,CLOSE`) | `Error` on NT error severity or exception |
| `stage:tcp_connect` | Client | `server.address`, `server.port` | Unset on failure (the parent operation span carries the error) |

A transport loss adds a `transport_lost` event (with `exception.type`) to the active span.

Composite operations record their nested public operations too: `ConnectAndAuthenticate` also records `Connect` and `Authenticate`, each with its own sample and child span. Do not sum `opencifs.client.operation.duration` across operation names; compare names individually. Only the outermost operation waits for the connection lock, so `opencifs.client.operation.queue.duration` is never double counted.

## Trace context and correlation

- **In process.** Client operation spans nest under whatever `Activity.Current` the caller has (for example a Watson HTTP request span), so an HTTP request that reads a file over SMB is one trace from the HTTP root to the `SMB2 READ` leaf.
- **Background hand-offs.** Oplock breaks, lease breaks, and CHANGE_NOTIFY completions are produced by one request (often on another connection) and written later by the owning connection's loop. OpenCIFS captures the producing span's context when the response is queued and parents the `async_response <kind>` span on it, so the break or notification stays inside the trace of the request that caused it. The queue wait is `opencifs.server.async_response.queue.duration`.
- **Over the wire.** SMB2 has no field for W3C trace context, so a client trace and the server trace for the same request cannot be joined automatically, and every server packet starts a new trace. To correlate across the wire, both sides put `smb.session_id` and `smb.message_id` on their spans; in Tempo, search the other side with TraceQL, for example `{ span.smb.session_id = 12345 && span.smb.message_id = 42 }`, narrowed by `network.peer.address` / `network.peer.port` on the server and the time window.
- **Logs.** The libraries write no logs of their own. `OpenCifsServerOptions.DiagnosticLogger` callbacks run inside the active server span, so a host logger (for example `ILogger` to Loki) stamps them with the trace and span id automatically.

## Cardinality, privacy, and safety

- Metric labels are bounded (see [Label vocabulary](#label-vocabulary)). Session, tree, and message identifiers, peer addresses, server names, and compound command lists appear only on spans, never on metrics.
- No payloads, file names, paths, share names, user names, domains, or credentials are recorded on metrics or spans. Exception events record only `exception.type`; messages are omitted because they can contain paths or peer input. The test suite asserts this.
- The listener-info gauge carries only booleans, dialect bounds, and the bound port.
- Instrumentation does not change locking or request ordering. The server-wide lock that every packet takes is measured, not altered.

## Recommended PromQL alerts

```yaml
groups:
  - name: opencifs
    rules:
      - alert: OpenCifsServerCommandErrorRatioHigh
        expr: |
          sum(rate(opencifs_server_command_duration_seconds_count{outcome=~"error|exception", smb_status!~"OBJECT_NAME_NOT_FOUND|NO_SUCH_FILE|OBJECT_PATH_NOT_FOUND|END_OF_FILE"}[5m]))
            / clamp_min(sum(rate(opencifs_server_command_duration_seconds_count[5m])), 1e-9) > 0.05
        for: 10m
        annotations:
          summary: More than 5% of SMB2 commands are failing (excluding normal not-found probes).

      - alert: OpenCifsServerLockContention
        expr: |
          histogram_quantile(0.95, sum by (le) (rate(opencifs_server_packet_stage_duration_seconds_bucket{stage="queued"}[5m]))) > 0.1
        for: 10m
        annotations:
          summary: p95 wait for the server-wide state lock exceeds 100 ms; a slow command or storage call is blocking every connection.

      - alert: OpenCifsServerStorageSlow
        expr: |
          histogram_quantile(0.95, sum by (le, storage_operation) (rate(opencifs_server_storage_duration_seconds_bucket[5m]))) > 0.5
        for: 10m
        annotations:
          summary: p95 share-backend {{ $labels.storage_operation }} latency exceeds 500 ms.

      - alert: OpenCifsServerStorageErrors
        expr: sum by (storage_operation) (rate(opencifs_server_storage_duration_seconds_count{outcome="error"}[5m])) > 0.1
        for: 5m
        annotations:
          summary: Share-backend {{ $labels.storage_operation }} calls are failing.

      - alert: OpenCifsServerAuthFailures
        expr: sum(rate(opencifs_server_auth_attempts_total{outcome="error"}[5m])) > 1
        for: 5m
        annotations:
          summary: Sustained failed SMB authentication attempts (bad credentials or a brute-force attempt).

      - alert: OpenCifsServerProtocolErrors
        expr: sum(rate(opencifs_server_connections_closed_total{reason=~"protocol_error|server_error"}[5m])) > 0
        for: 10m
        annotations:
          summary: Connections are being dropped for malformed packets or server faults.

      - alert: OpenCifsServerAsyncResponsesBacklogged
        expr: max_over_time(opencifs_server_async_responses_queued[5m]) > 100
        for: 5m
        annotations:
          summary: Oplock or lease breaks and change notifications are queuing faster than connections drain them.

      - alert: OpenCifsServerListenerDown
        expr: sum(opencifs_server_listeners_active) < 1
        for: 2m
        annotations:
          summary: No OpenCIFS listener is running in a process that exports OpenCIFS server metrics.

      - alert: OpenCifsClientTransportFailures
        expr: sum(rate(opencifs_client_transport_failures_total[5m])) > 0
        for: 5m
        annotations:
          summary: SMB client connections are being lost.

      - alert: OpenCifsClientConnectFailures
        expr: sum(rate(opencifs_client_connect_duration_seconds_count{outcome="exception"}[5m])) > 0
        for: 5m
        annotations:
          summary: SMB client connects are failing (refused, unreachable, or timing out).

      - alert: OpenCifsClientRequestLatencyHigh
        expr: |
          histogram_quantile(0.95, sum by (le, smb_command) (rate(opencifs_client_request_duration_seconds_bucket[5m]))) > 1
        for: 10m
        annotations:
          summary: p95 SMB2 {{ $labels.smb_command }} round trip exceeds 1 s.
```

Tune thresholds to the deployment. Label names follow the Prometheus mapping (`smb.status` becomes `smb_status`).

## Dashboard map

OpenCIFS ships libraries, not a deployable service, so it does not ship a `compose.yaml` or Grafana provisioning. A host that embeds the server or client should add these domain dashboards to its own Grafana product folder:

| Dashboard | Panels (PromQL) | Question it answers |
| --- | --- | --- |
| **SMB Overview** | `opencifs_server_listeners_active`; `opencifs_server_connections_active`; `opencifs_server_sessions_active`; `sum(rate(opencifs_server_packet_duration_seconds_count[5m]))`; command error ratio (see alert); `opencifs_build_info` table | Is the server up, busy, and healthy? |
| **SMB Server Pipeline** | `histogram_quantile(0.95, sum by (le, stage) (rate(opencifs_server_packet_stage_duration_seconds_bucket[5m])))`; `opencifs_server_lock_waiting`; `sum by (reason) (rate(opencifs_server_connections_closed_total[5m]))`; `sum by (error_type, stage) (rate(opencifs_server_errors_total[5m]))` | Is time going to lock contention, crypto, dispatch, or the network? |
| **SMB Commands** | `sum by (smb_command) (rate(opencifs_server_command_duration_seconds_count[5m]))`; p95 by `smb_command`; `topk(10, sum by (smb_command, smb_status) (rate(opencifs_server_command_duration_seconds_count{outcome="error"}[5m])))`; `sum by (outcome, auth_mechanism) (rate(opencifs_server_auth_attempts_total[5m]))`; `sum by (smb_dialect) (rate(opencifs_server_negotiations_total[1h]))` | Which command is slow or failing, with which status? |
| **SMB Storage and State** | p95 and error rate by `storage_operation`; `sum by (smb_io_direction) (rate(opencifs_server_io_bytes_total[5m]))`; `opencifs_server_trees_active`, `opencifs_server_opens_active`, `opencifs_server_durable_opens_detached`, `opencifs_server_change_notify_pending`, `opencifs_server_async_responses_queued`; `sum by (smb_async_kind) (rate(opencifs_server_async_responses_sent_total[5m]))` | Is the backing store the bottleneck? Are handles or breaks piling up? |
| **SMB Client** | p95 by `opencifs_operation`; `sum by (smb_command, smb_status) (rate(opencifs_client_request_duration_seconds_count{outcome!="success"}[5m]))`; `opencifs_client_connections_active`; `rate(opencifs_client_transport_failures_total[5m])`; connect p95 and failures; `opencifs_client_operations_waiting` and queue p95; byte rates | Is the remote SMB server (the downstream) the cause? |

Link each panel's exemplars or a Tempo data link to `{ resource.service.name = "<service>" && name =~ "SMB2 .*" }` so an operator can jump from a slow bucket to a representative trace. A host with a product dashboard should list Grafana in its External Services card as described in its own telemetry standard.

## Known limits

- Server spans cannot continue a client's trace because SMB2 carries no trace context (see [Trace context and correlation](#trace-context-and-correlation)).
- Every server packet holds one server-wide lock for decode, dispatch, and encode. `stage:queued` and `opencifs.server.lock.waiting` make that contention visible; they do not remove it.
- The legacy `OpenCifsServerHost` methods that tests and advanced hosts call directly (outside `OpenCifsDirectTcpServer`) still emit command, storage, auth, and domain telemetry, but no packet, stage, connection, or network metrics, because those belong to the direct-TCP loop.
- On .NET 8 the runtime keeps `Instrument.Enabled` set after the last `MeterListener` is disposed (fixed in later runtimes). Recording stays a no-op with nobody listening, but the storage scope allocates a small object per backend call instead of returning its shared no-op instance until the process restarts.
- Storage failures that the server maps to an NT status (for example `IOException` to `ACCESS_DENIED`) are recorded with `outcome=error`; the exception type is recorded where the server already catches it (read, write, flush), and otherwise appears on the command's `smb.status`.

namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Net;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Telemetry for one inbound packet: a root server span, one child span and histogram sample per stage
    /// (queued, decode, dispatch, encode, send), and the end-to-end duration. Not thread-safe; one instance is owned by
    /// the connection loop that handles the packet. Every member is best-effort and never throws.
    /// </summary>
    internal sealed class OpenCifsServerPacketScope : IDisposable
    {
        internal OpenCifsServerPacketScope(IPEndPoint? peerEndPoint, int localPort, int requestBytes)
        {
            _StartTimestamp = Stopwatch.GetTimestamp();
            OpenCifsServerTelemetry.RecordNetworkIo(requestBytes, transmit: false);

            if (!OpenCifsServerTelemetry.IsTracing)
            {
                return;
            }

            try
            {
                // SMB2 carries no trace context, so every inbound packet starts a new trace. The display name is refined
                // to the SMB2 command once the packet has been decoded.
                _Activity = OpenCifsServerTelemetry.Source.StartActivity("SMB2 request", ActivityKind.Server, default(ActivityContext));

                if (_Activity != null && _Activity.IsAllDataRequested)
                {
                    _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributeNetworkTransport, "tcp");
                    _Activity.SetTag(OpenCifsTelemetryNames.AttributeServerPort, localPort);

                    if (peerEndPoint != null)
                    {
                        _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributePeerAddress, peerEndPoint.Address.ToString());
                        _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributePeerPort, peerEndPoint.Port);
                    }
                }
            }
            catch (Exception)
            {
                _Activity = null;
            }
        }

        internal string PacketKind
        {
            get
            {
                return _PacketKind;
            }
        }

        internal void BeginStage(string stage)
        {
            EndStage();
            _Stage = stage;
            _StageStartTimestamp = Stopwatch.GetTimestamp();

            if (_Activity == null)
            {
                return;
            }

            try
            {
                _StageActivity = OpenCifsServerTelemetry.Source.StartActivity("stage:" + stage, ActivityKind.Internal);
                _StageActivity?.SetTag(OpenCifsTelemetryNames.AttributeStage, stage);
            }
            catch (Exception)
            {
                _StageActivity = null;
            }
        }

        internal void EndStage()
        {
            if (_Stage == null)
            {
                return;
            }

            try
            {
                OpenCifsServerTelemetry.PacketStageDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(_StageStartTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeStage, _Stage));

                if (_StageActivity != null)
                {
                    if (_StageActivity.Status == ActivityStatusCode.Unset)
                    {
                        _StageActivity.SetStatus(ActivityStatusCode.Ok);
                    }

                    _StageActivity.Dispose();
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                _Stage = null;
                _StageActivity = null;
            }
        }

        internal void Describe(string packetKind, Smb2Header? firstHeader, int entryCount, bool wasEncrypted)
        {
            _PacketKind = packetKind;

            if (_Activity == null)
            {
                return;
            }

            try
            {
                if (packetKind == OpenCifsServerTelemetry.PacketKindSmb1Negotiate)
                {
                    _Activity.DisplayName = "SMB1 NEGOTIATE";
                }
                else if (entryCount > 1)
                {
                    _Activity.DisplayName = "SMB2 COMPOUND";
                }
                else if (firstHeader != null)
                {
                    _Activity.DisplayName = "SMB2 " + OpenCifsTelemetryFormat.CommandName(firstHeader.Command);
                }

                if (!_Activity.IsAllDataRequested)
                {
                    return;
                }

                _Activity.SetTag(OpenCifsTelemetryNames.AttributePacketKind, packetKind);
                _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributeCompoundCount, entryCount);
                _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributeEncrypted, wasEncrypted);

                if (firstHeader != null)
                {
                    _Activity.SetTag(OpenCifsTelemetryNames.AttributeCommand, OpenCifsTelemetryFormat.CommandName(firstHeader.Command));
                    _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributeMessageId, firstHeader.MessageId);
                    _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributeSessionId, firstHeader.SessionId);
                    _Activity.SetTag(OpenCifsTelemetryNames.SpanAttributeTreeId, firstHeader.TreeId);
                }
            }
            catch (Exception)
            {
            }
        }

        internal void ResponseWritten(int responseBytes)
        {
            OpenCifsServerTelemetry.RecordNetworkIo(responseBytes, transmit: true);
        }

        internal void Complete()
        {
            Finish(OpenCifsTelemetryFormat.OutcomeSuccess, null);
        }

        internal void Fail(Exception exception)
        {
            Finish(OpenCifsTelemetryFormat.OutcomeException, exception);
        }

        public void Dispose()
        {
            if (!_Finished)
            {
                // Reached only when the loop exits without completing the packet, for example on shutdown.
                Finish(OpenCifsTelemetryFormat.OutcomeError, null);
            }
        }

        private void Finish(string outcome, Exception? exception)
        {
            if (_Finished)
            {
                return;
            }

            _Finished = true;
            string? failedStage = _Stage;

            try
            {
                if (exception != null)
                {
                    OpenCifsServerTelemetry.MarkFailed(_StageActivity, exception);
                    OpenCifsServerTelemetry.RecordError(exception, failedStage ?? OpenCifsServerTelemetry.StageDispatch);
                }

                EndStage();
                OpenCifsServerTelemetry.PacketDuration.Record(
                    OpenCifsTelemetryFormat.ElapsedSeconds(_StartTimestamp),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributePacketKind, _PacketKind),
                    new KeyValuePair<string, object?>(OpenCifsTelemetryNames.AttributeOutcome, outcome));

                if (_Activity != null)
                {
                    _Activity.SetTag(OpenCifsTelemetryNames.AttributeOutcome, outcome);

                    if (exception != null)
                    {
                        _Activity.SetTag(OpenCifsTelemetryNames.AttributeStage, failedStage);
                        OpenCifsServerTelemetry.MarkFailed(_Activity, exception);
                    }
                    else if (outcome == OpenCifsTelemetryFormat.OutcomeSuccess)
                    {
                        _Activity.SetStatus(ActivityStatusCode.Ok);
                    }
                    else
                    {
                        _Activity.SetStatus(ActivityStatusCode.Error, outcome);
                    }

                    _Activity.Dispose();
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                _Activity = null;
            }
        }

        private readonly long _StartTimestamp;
        private Activity? _Activity;
        private Activity? _StageActivity;
        private string? _Stage;
        private long _StageStartTimestamp;
        private string _PacketKind = OpenCifsServerTelemetry.PacketKindSmb2;
        private bool _Finished;
    }
}

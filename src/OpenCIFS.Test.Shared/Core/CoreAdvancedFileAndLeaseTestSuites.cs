namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Touchstone.Core;
    using static OpenCIFS.Core.Tests.Shared.CoreTestSupport;
    internal static class CoreAdvancedFileAndLeaseTestSuites
    {
        internal static TestSuiteDescriptor Smb2DurableHandleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Durable",
                displayName: "SMB2 durable-handle create contexts",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Durable",
                        caseId: "DurableCreateContextsRoundTripAndValidate",
                        displayName: "Durable create request, reconnect, and response contexts round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CreateRequest durableRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    Smb2DurableHandleRequestContext.Create()
                                })
                            };
                            Smb2CreateRequestValidator.Validate(durableRequest);
                            Smb2CreateRequest parsedDurableRequest = Smb2CreateRequest.ReadFrom(durableRequest.ToByteArray());
                            Smb2CreateContext[] durableRequestContexts = Smb2CreateContextCodec.Decode(parsedDurableRequest.CreateContexts);
                            TestAssertions.Equal(1, durableRequestContexts.Length, "Expected one durable request context.");
                            TestAssertions.True(Smb2DurableHandleRequestContext.IsMatch(durableRequestContexts[0]), "Expected the request context to be DHnQ.");

                            Smb2DurableHandleReconnectContext reconnectContext = new Smb2DurableHandleReconnectContext
                            {
                                PersistentFileId = 7,
                                VolatileFileId = 11
                            };
                            Smb2CreateRequest reconnectRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    reconnectContext.ToCreateContext()
                                })
                            };
                            Smb2CreateRequestValidator.Validate(reconnectRequest);
                            Smb2CreateRequest parsedReconnectRequest = Smb2CreateRequest.ReadFrom(reconnectRequest.ToByteArray());
                            Smb2CreateContext[] reconnectRequestContexts = Smb2CreateContextCodec.Decode(parsedReconnectRequest.CreateContexts);
                            TestAssertions.Equal(1, reconnectRequestContexts.Length, "Expected one durable reconnect context.");
                            Smb2DurableHandleReconnectContext parsedReconnectContext = Smb2DurableHandleReconnectContext.ReadFrom(reconnectRequestContexts[0]);
                            TestAssertions.Equal(7UL, parsedReconnectContext.PersistentFileId, "Unexpected durable reconnect persistent file identifier.");
                            TestAssertions.Equal(11UL, parsedReconnectContext.VolatileFileId, "Unexpected durable reconnect volatile file identifier.");

                            Smb2CreateResponse durableResponse = new Smb2CreateResponse
                            {
                                OplockLevel = Smb2OplockLevel.Batch,
                                CreateAction = Smb2CreateAction.Opened,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                PersistentFileId = 7,
                                VolatileFileId = 13,
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    Smb2DurableHandleResponseContext.Create()
                                })
                            };
                            Smb2CreateResponseValidator.Validate(durableResponse);
                            Smb2CreateResponse parsedDurableResponse = Smb2CreateResponse.ReadFrom(durableResponse.ToByteArray());
                            Smb2CreateContext[] durableResponseContexts = Smb2CreateContextCodec.Decode(parsedDurableResponse.CreateContexts);
                            TestAssertions.Equal(1, durableResponseContexts.Length, "Expected one durable response context.");
                            Smb2DurableHandleResponseContext.Validate(durableResponseContexts[0]);

                            byte[] paddedResponseContexts = new byte[parsedDurableResponse.CreateContexts.Length + 8];
                            Buffer.BlockCopy(parsedDurableResponse.CreateContexts, 0, paddedResponseContexts, 0, parsedDurableResponse.CreateContexts.Length);
                            Smb2CreateContext[] paddedDurableResponseContexts = Smb2CreateContextCodec.Decode(paddedResponseContexts);
                            TestAssertions.Equal(1, paddedDurableResponseContexts.Length, "Expected the durable create-context decoder to tolerate trailing zero padding after the final context.");

                            LittleEndianWriter windowsStyleContextWriter = new LittleEndianWriter();
                            windowsStyleContextWriter.WriteUInt32(0);
                            windowsStyleContextWriter.WriteUInt16(16);
                            windowsStyleContextWriter.WriteUInt16(4);
                            windowsStyleContextWriter.WriteUInt16(0);
                            windowsStyleContextWriter.WriteUInt16(24);
                            windowsStyleContextWriter.WriteUInt32(0);
                            windowsStyleContextWriter.WriteBytes(Encoding.ASCII.GetBytes("MxAc"));

                            while (windowsStyleContextWriter.Length < 24)
                            {
                                windowsStyleContextWriter.WriteByte(0);
                            }

                            Smb2CreateContext[] windowsStyleContexts = Smb2CreateContextCodec.Decode(windowsStyleContextWriter.ToArray());
                            TestAssertions.Equal(1, windowsStyleContexts.Length, "Expected the durable create-context decoder to accept zero-length Windows-style create contexts that carry a padded data offset.");
                            TestAssertions.Equal("MxAc", Encoding.ASCII.GetString(windowsStyleContexts[0].Name), "Unexpected Windows-style create-context name.");
                            TestAssertions.Equal(0, windowsStyleContexts[0].Data.Length, "Expected the Windows-style create context to preserve an empty payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Durable",
                        caseId: "DurableCreateContextValidationRejectsMalformedAndUnsupportedContexts",
                        displayName: "Durable create-context validation rejects malformed, duplicate, and durable reconnect contexts",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CreateRequest malformedRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = new byte[] { 0x01, 0x02, 0x03 }
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(malformedRequest),
                                "Expected malformed durable create-context buffers to be rejected.");

                            Smb2CreateRequest duplicateDurableRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    Smb2DurableHandleRequestContext.Create(),
                                    Smb2DurableHandleRequestContext.Create()
                                })
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(duplicateDurableRequest),
                                "Expected duplicate durable-handle request contexts to be rejected.");

                            byte[] durableRequestBytes = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                            {
                                Smb2DurableHandleRequestContext.Create()
                            });
                            byte[] malformedTrailingContextBytes = new byte[durableRequestBytes.Length + 8];
                            Buffer.BlockCopy(durableRequestBytes, 0, malformedTrailingContextBytes, 0, durableRequestBytes.Length);
                            malformedTrailingContextBytes[durableRequestBytes.Length] = 0x7F;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CreateContextCodec.Decode(malformedTrailingContextBytes),
                                "Expected the durable create-context decoder to reject non-zero trailing bytes after the final context.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 locking suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>

        internal static TestSuiteDescriptor Smb2LockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Locking",
                displayName: "SMB2 byte-range lock messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Locking",
                        caseId: "LockMessagesRoundTrip",
                        displayName: "SMB2 lock messages round-trip and trim compounded padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2LockRequest lockRequest = new Smb2LockRequest
                            {
                                LockSequence = 0,
                                PersistentFileId = 91,
                                VolatileFileId = 92,
                                Locks = new Smb2LockElement[]
                                {
                                    new Smb2LockElement
                                    {
                                        Offset = 128,
                                        Length = 64,
                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                    }
                                }
                            };
                            byte[] lockRequestBytes = lockRequest.ToByteArray();
                            Smb2LockRequest parsedLockRequest = Smb2LockRequest.ReadFrom(lockRequestBytes);
                            Smb2LockRequestValidator.Validate(parsedLockRequest);
                            TestAssertions.Equal(1, parsedLockRequest.Locks.Length, "Expected a single parsed lock element.");
                            TestAssertions.Equal(128UL, parsedLockRequest.Locks[0].Offset, "Unexpected lock-element offset.");
                            TestAssertions.Equal(64UL, parsedLockRequest.Locks[0].Length, "Unexpected lock-element length.");
                            TestAssertions.Equal(
                                Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately,
                                parsedLockRequest.Locks[0].Flags,
                                "Unexpected lock-element flags.");

                            Smb2LockResponse lockResponse = Smb2LockResponse.ReadFrom(new Smb2LockResponse().ToByteArray());
                            Smb2LockResponseValidator.Validate(lockResponse);

                            byte[] paddedLockRequest = new byte[lockRequestBytes.Length + 8];
                            lockRequestBytes.CopyTo(paddedLockRequest, 0);
                            byte[] trimmedLockRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Lock, paddedLockRequest);
                            TestAssertions.SequenceEqual(lockRequestBytes, trimmedLockRequest, "Unexpected trimmed compounded lock request payload.");

                            byte[] lockResponseBytes = new Smb2LockResponse().ToByteArray();
                            byte[] paddedLockResponse = new byte[lockResponseBytes.Length + 8];
                            lockResponseBytes.CopyTo(paddedLockResponse, 0);
                            byte[] trimmedLockResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Lock, paddedLockResponse);
                            TestAssertions.SequenceEqual(lockResponseBytes, trimmedLockResponse, "Unexpected trimmed compounded lock response payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Locking",
                        caseId: "LockValidatorsRejectUnsupportedInputs",
                        displayName: "SMB2 lock validators reject malformed ranges and unsupported flag combinations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    LockSequence = 1,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 1,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    }
                                }),
                                "SMB2.0.2 lock requests should reject non-zero lock-sequence values.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = Array.Empty<Smb2LockElement>()
                                }),
                                "Lock requests should require at least one lock element.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 0,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    }
                                }),
                                "Lock requests should reject zero-length ranges.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 8,
                                            Flags = Smb2LockFlags.SharedLock | Smb2LockFlags.ExclusiveLock
                                        }
                                    }
                                }),
                                "Lock requests should reject conflicting shared and exclusive flags.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 8,
                                            Flags = Smb2LockFlags.Unlock | Smb2LockFlags.FailImmediately
                                        }
                                    }
                                }),
                                "Unlock lock elements should reject lock-acquisition flags.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LockElement.ReadFrom(new byte[23]),
                                "A truncated SMB2 lock element should fail to parse.");

                            byte[] malformedLockRequestBytes = new Smb2LockRequest
                            {
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                Locks = new Smb2LockElement[]
                                {
                                    new Smb2LockElement
                                    {
                                        Offset = 0,
                                        Length = 8,
                                        Flags = Smb2LockFlags.ExclusiveLock
                                    }
                                }
                            }.ToByteArray();
                            malformedLockRequestBytes[2] = 0x02;
                            malformedLockRequestBytes[3] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LockRequest.ReadFrom(malformedLockRequestBytes),
                                "SMB2 lock requests should reject buffers whose encoded lock count exceeds the available payload.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 oplock-break suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>

        internal static TestSuiteDescriptor Smb2OplockBreakSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2OplockBreak",
                displayName: "SMB2 oplock-break messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2OplockBreak",
                        caseId: "OplockBreakMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 oplock-break messages round-trip and trim compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2OplockBreakNotification notification = new Smb2OplockBreakNotification
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            };
                            byte[] notificationBytes = notification.ToByteArray();
                            Smb2OplockBreakNotification parsedNotification = Smb2OplockBreakNotification.ReadFrom(notificationBytes);
                            Smb2OplockBreakNotificationValidator.Validate(parsedNotification);
                            TestAssertions.Equal(Smb2OplockLevel.None, parsedNotification.OplockLevel, "Unexpected oplock-break notification level.");
                            TestAssertions.Equal(17UL, parsedNotification.PersistentFileId, "Unexpected oplock-break notification persistent file identifier.");
                            TestAssertions.Equal(18UL, parsedNotification.VolatileFileId, "Unexpected oplock-break notification volatile file identifier.");

                            Smb2OplockBreakAcknowledgment acknowledgment = new Smb2OplockBreakAcknowledgment
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            };
                            byte[] acknowledgmentBytes = acknowledgment.ToByteArray();
                            Smb2OplockBreakAcknowledgment parsedAcknowledgment = Smb2OplockBreakAcknowledgment.ReadFrom(acknowledgmentBytes);
                            Smb2OplockBreakAcknowledgmentValidator.Validate(parsedAcknowledgment);
                            byte[] trimmedAcknowledgment = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.OplockBreak, Combine(acknowledgmentBytes, new byte[4]));
                            TestAssertions.SequenceEqual(acknowledgmentBytes, trimmedAcknowledgment, "Unexpected compounded SMB2 oplock-break acknowledgment trimming result.");

                            Smb2OplockBreakResponse response = new Smb2OplockBreakResponse
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb2OplockBreakResponse parsedResponse = Smb2OplockBreakResponse.ReadFrom(responseBytes);
                            Smb2OplockBreakResponseValidator.Validate(parsedResponse);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.OplockBreak, Combine(responseBytes, new byte[4]));
                            TestAssertions.SequenceEqual(responseBytes, trimmedResponse, "Unexpected compounded SMB2 oplock-break response trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2OplockBreak",
                        caseId: "OplockBreakMessagesRejectMalformedInputs",
                        displayName: "SMB2 oplock-break messages reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] malformedNotification = new Smb2OplockBreakNotification
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            }.ToByteArray();
                            malformedNotification[0] = 0x17;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2OplockBreakNotification.ReadFrom(malformedNotification),
                                "Malformed SMB2 oplock-break notifications should be rejected.");

                            byte[] malformedAcknowledgment = new Smb2OplockBreakAcknowledgment
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            }.ToByteArray();
                            malformedAcknowledgment[0] = 0x17;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2OplockBreakAcknowledgment.ReadFrom(malformedAcknowledgment),
                                "Malformed SMB2 oplock-break acknowledgments should be rejected.");

                            byte[] malformedResponse = new Smb2OplockBreakResponse
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            }.ToByteArray();
                            malformedResponse[0] = 0x17;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2OplockBreakResponse.ReadFrom(malformedResponse),
                                "Malformed SMB2 oplock-break responses should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakNotificationValidator.Validate(null!),
                                "A null SMB2 oplock-break notification should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakAcknowledgmentValidator.Validate(null!),
                                "A null SMB2 oplock-break acknowledgment should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakResponseValidator.Validate(null!),
                                "A null SMB2 oplock-break response should fail validation.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakNotificationValidator.Validate(new Smb2OplockBreakNotification
                                {
                                    OplockLevel = Smb2OplockLevel.Batch,
                                    PersistentFileId = 17,
                                    VolatileFileId = 18
                                }),
                                "Unsupported bounded oplock levels should be rejected for unsolicited oplock-break notifications.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakAcknowledgmentValidator.Validate(new Smb2OplockBreakAcknowledgment
                                {
                                    OplockLevel = Smb2OplockLevel.Lease,
                                    PersistentFileId = 17,
                                    VolatileFileId = 18
                                }),
                                "Unsupported bounded oplock levels should be rejected for oplock-break acknowledgments.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakResponseValidator.Validate(new Smb2OplockBreakResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    PersistentFileId = 0,
                                    VolatileFileId = 0
                                }),
                                "SMB2 oplock-break responses without tracked file identifiers should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 lease suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>

        internal static TestSuiteDescriptor Smb2LeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Lease",
                displayName: "SMB2 lease messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Lease",
                        caseId: "LeaseContextsAndBreakMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 lease contexts and break messages round-trip and trim compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] leaseKey = new byte[16];

                            for (int index = 0; index < leaseKey.Length; index++)
                            {
                                leaseKey[index] = (byte)(index + 1);
                            }

                            Smb2CreateRequestLeaseContext requestContext = new Smb2CreateRequestLeaseContext
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                            };
                            Smb2CreateRequestLeaseContext parsedRequestContext = Smb2CreateRequestLeaseContext.ReadFrom(requestContext.ToCreateContext());
                            TestAssertions.SequenceEqual(leaseKey, parsedRequestContext.LeaseKey, "Unexpected SMB2 lease request context lease key.");
                            TestAssertions.Equal(requestContext.LeaseState, parsedRequestContext.LeaseState, "Unexpected SMB2 lease request context lease state.");

                            Smb2CreateResponseLeaseContext responseContext = new Smb2CreateResponseLeaseContext
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching,
                                LeaseFlags = Smb2LeaseFlags.BreakInProgress
                            };
                            Smb2CreateResponseLeaseContext parsedResponseContext = Smb2CreateResponseLeaseContext.ReadFrom(responseContext.ToCreateContext());
                            TestAssertions.SequenceEqual(leaseKey, parsedResponseContext.LeaseKey, "Unexpected SMB2 lease response context lease key.");
                            TestAssertions.Equal(responseContext.LeaseState, parsedResponseContext.LeaseState, "Unexpected SMB2 lease response context lease state.");
                            TestAssertions.Equal(responseContext.LeaseFlags, parsedResponseContext.LeaseFlags, "Unexpected SMB2 lease response context flags.");

                            Smb2LeaseBreakNotification notification = new Smb2LeaseBreakNotification
                            {
                                Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                                LeaseKey = leaseKey,
                                CurrentLeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                NewLeaseState = Smb2LeaseState.None
                            };
                            byte[] notificationBytes = notification.ToByteArray();
                            Smb2LeaseBreakNotification parsedNotification = Smb2LeaseBreakNotification.ReadFrom(notificationBytes);
                            Smb2LeaseBreakNotificationValidator.Validate(parsedNotification);
                            TestAssertions.Equal(notification.CurrentLeaseState, parsedNotification.CurrentLeaseState, "Unexpected SMB2 lease-break notification current state.");
                            TestAssertions.Equal(notification.NewLeaseState, parsedNotification.NewLeaseState, "Unexpected SMB2 lease-break notification new state.");
                            byte[] trimmedNotification = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.OplockBreak, Combine(notificationBytes, new byte[4]));
                            TestAssertions.SequenceEqual(notificationBytes, trimmedNotification, "Unexpected compounded SMB2 lease-break notification trimming result.");

                            Smb2LeaseBreakAcknowledgment acknowledgment = new Smb2LeaseBreakAcknowledgment
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.None
                            };
                            byte[] acknowledgmentBytes = acknowledgment.ToByteArray();
                            Smb2LeaseBreakAcknowledgment parsedAcknowledgment = Smb2LeaseBreakAcknowledgment.ReadFrom(acknowledgmentBytes);
                            Smb2LeaseBreakAcknowledgmentValidator.Validate(parsedAcknowledgment);
                            byte[] trimmedAcknowledgment = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.OplockBreak, Combine(acknowledgmentBytes, new byte[4]));
                            TestAssertions.SequenceEqual(acknowledgmentBytes, trimmedAcknowledgment, "Unexpected compounded SMB2 lease-break acknowledgment trimming result.");

                            Smb2LeaseBreakResponse response = new Smb2LeaseBreakResponse
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.None
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb2LeaseBreakResponse parsedResponse = Smb2LeaseBreakResponse.ReadFrom(responseBytes);
                            Smb2LeaseBreakResponseValidator.Validate(parsedResponse);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.OplockBreak, Combine(responseBytes, new byte[4]));
                            TestAssertions.SequenceEqual(responseBytes, trimmedResponse, "Unexpected compounded SMB2 lease-break response trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Lease",
                        caseId: "LeaseContextsAndBreakMessagesRejectMalformedInputs",
                        displayName: "SMB2 lease contexts and break messages reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestLeaseContext.Validate(new Smb2CreateRequestLeaseContext
                                {
                                    LeaseKey = new byte[16],
                                    LeaseState = (Smb2LeaseState)0x80
                                }),
                                "Unsupported SMB2 lease request state bits should be rejected.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateResponseLeaseContext.Validate(new Smb2CreateResponseLeaseContext
                                {
                                    LeaseKey = new byte[16],
                                    LeaseState = Smb2LeaseState.ReadCaching,
                                    LeaseFlags = (Smb2LeaseFlags)0x80
                                }),
                                "Unsupported SMB2 lease response flags should be rejected.");

                            byte[] malformedNotification = new Smb2LeaseBreakNotification
                            {
                                LeaseKey = new byte[16],
                                CurrentLeaseState = Smb2LeaseState.ReadCaching,
                                NewLeaseState = Smb2LeaseState.None
                            }.ToByteArray();
                            malformedNotification[0] = 0x2B;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LeaseBreakNotification.ReadFrom(malformedNotification),
                                "Malformed SMB2 lease-break notifications should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LeaseBreakAcknowledgmentValidator.Validate(new Smb2LeaseBreakAcknowledgment
                                {
                                    LeaseKey = new byte[8],
                                    LeaseState = Smb2LeaseState.None
                                }),
                                "Malformed SMB2 lease-break acknowledgment lease keys should be rejected.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LeaseBreakResponseValidator.Validate(new Smb2LeaseBreakResponse
                                {
                                    LeaseKey = new byte[16],
                                    LeaseState = (Smb2LeaseState)0x80
                                }),
                                "Unsupported SMB2 lease-break response lease states should be rejected.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    RequestedOplockLevel = Smb2OplockLevel.Lease,
                                    ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                    DesiredAccess = 0x80000000U,
                                    FileAttributes = ProtocolFileAttributes.Normal,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.OpenIf,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    Name = "dup.txt",
                                    CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                    {
                                        new Smb2CreateRequestLeaseContext
                                        {
                                            LeaseKey = new byte[16],
                                            LeaseState = Smb2LeaseState.ReadCaching
                                        }.ToCreateContext(),
                                        new Smb2CreateRequestLeaseContext
                                        {
                                            LeaseKey = new byte[16],
                                            LeaseState = Smb2LeaseState.ReadCaching
                                        }.ToCreateContext()
                                    })
                                }),
                                "Duplicate SMB2 lease request contexts should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}

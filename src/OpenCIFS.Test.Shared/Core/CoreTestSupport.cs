namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal static class CoreTestSupport
    {
        internal static void AssertDialectPresent(string[] names, string expectedName)
        {
            for (int index = 0; index < names.Length; index++)
            {
                if (StringComparer.Ordinal.Equals(names[index], expectedName))
                {
                    return;
                }
            }

            throw new InvalidOperationException("Expected dialect name was not present: " + expectedName + ".");
        }

        internal static Smb1Header CreateValidSmb1Header()
        {
            return new Smb1Header
            {
                Command = Smb1Command.WriteAndX,
                Status = NtStatus.AccessDenied,
                Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                ProcessIdHigh = 0x1234,
                Signature = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
                TreeId = 0x4567,
                ProcessIdLow = 0x89AB,
                UserId = 0xCDEF,
                MultiplexId = 0x2468
            };
        }

        internal static Smb2Header CreateValidSmb2Header()
        {
            return new Smb2Header
            {
                CreditCharge = 2,
                Status = NtStatus.BufferTooSmall,
                Command = Smb2Command.QueryInfo,
                CreditRequest = 7,
                Flags = Smb2HeaderFlags.Signed | Smb2HeaderFlags.ServerToRedir,
                NextCommand = 16,
                MessageId = 0x0102030405060708UL,
                ProcessId = 0x0A0B0C0DU,
                TreeId = 0x10203040U,
                SessionId = 0x1122334455667788UL,
                Signature = new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F }
            };
        }

        internal static Smb2Header CreateCompoundHeader(Smb2Command command, ulong messageId, Smb2HeaderFlags flags = Smb2HeaderFlags.None)
        {
            return new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Success,
                Command = command,
                CreditRequest = 1,
                Flags = flags,
                NextCommand = 0,
                MessageId = messageId,
                ProcessId = 0,
                TreeId = 0,
                SessionId = 0,
                Signature = new byte[16]
            };
        }

        internal static byte[] CreateDirectTcpFrame(ReadOnlySpan<byte> payload)
        {
            DirectTcpFrameHeader header = new DirectTcpFrameHeader
            {
                Length = payload.Length
            };

            return Combine(header.ToByteArray(), payload);
        }

        internal static byte[] CreateNetBiosFrame(NetBiosSessionMessageType messageType, ReadOnlySpan<byte> payload)
        {
            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
            {
                MessageType = messageType,
                Length = payload.Length
            };

            return Combine(header.ToByteArray(), payload);
        }

        internal static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
        {
            byte[] combined = new byte[first.Length + second.Length];
            first.CopyTo(combined.AsSpan(0, first.Length));
            second.CopyTo(combined.AsSpan(first.Length, second.Length));
            return combined;
        }

        internal static byte[] CreateMicrosoftNtlmV2ClientChallengeBytes()
        {
            return Hex("01010000000000000000000000000000AAAAAAAAAAAAAAAA0000000002000C0044006F006D00610069006E0001000C005300650072007600650072000000000000000000");
        }

        internal static NtlmV2ClientChallenge CreateMicrosoftNtlmV2ClientChallenge()
        {
            return NtlmV2ClientChallenge.ReadFrom(CreateMicrosoftNtlmV2ClientChallengeBytes());
        }

        internal static byte[] CreateRepeatedByteArray(byte value, int length)
        {
            byte[] buffer = new byte[length];

            for (int index = 0; index < buffer.Length; index++)
            {
                buffer[index] = value;
            }

            return buffer;
        }

        internal static byte[] CreateSequentialByteArray(int length)
        {
            byte[] buffer = new byte[length];

            for (int index = 0; index < buffer.Length; index++)
            {
                buffer[index] = (byte)index;
            }

            return buffer;
        }

        internal static byte[] CreateMutatedCopy(ReadOnlySpan<byte> value)
        {
            byte[] buffer = value.ToArray();

            if (buffer.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Cannot mutate an empty byte sequence.");
            }

            buffer[buffer.Length - 1] ^= 0x01;
            return buffer;
        }

        internal static IReadOnlyList<ProtocolMutationCorpusEntry> BuildProtocolMutationCorpus()
        {
            Smb2Header smb2Header = new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Success,
                Command = Smb2Command.Negotiate,
                CreditRequest = 1,
                Flags = Smb2HeaderFlags.None,
                NextCommand = 0,
                MessageId = 1,
                TreeId = 0,
                SessionId = 0,
                Signature = new byte[16]
            };

            Smb2NegotiateRequest negotiateRequest = new Smb2NegotiateRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled,
                ClientGuid = Guid.Parse("6D8F66FA-6D20-4D4C-B016-A3B3AC02D40F"),
                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
            };

            Smb2CreateRequest createRequest = new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.None,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0000000U,
                FileAttributes = ProtocolFileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.OpenIf,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = "folder\\notes.txt",
                CreateContexts = Array.Empty<byte>()
            };

            Smb2ChangeNotifyRequest changeNotifyRequest = new Smb2ChangeNotifyRequest
            {
                Flags = Smb2ChangeNotifyFlags.WatchTree,
                OutputBufferLength = 4096,
                PersistentFileId = 10,
                VolatileFileId = 11,
                CompletionFilter = FileNotifyChangeFilter.FileName | FileNotifyChangeFilter.LastWrite
            };

            Smb2IoctlRequest ioctlRequest = new Smb2IoctlRequest
            {
                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                PersistentFileId = 301,
                VolatileFileId = 302,
                MaxInputResponse = 0,
                MaxOutputResponse = 4096,
                Flags = Smb2IoctlFlags.IsFsctl,
                InputBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 }
            };

            Smb2LeaseBreakAcknowledgment leaseAcknowledgment = new Smb2LeaseBreakAcknowledgment
            {
                LeaseKey = CreateRepeatedByteArray(0x11, 16),
                LeaseState = Smb2LeaseState.None
            };

            Smb2QueryInfoRequest queryInfoRequest = new Smb2QueryInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = FileInformationClass.BasicInformation,
                OutputBufferLength = 128,
                PersistentFileId = 1,
                VolatileFileId = 2,
                InputBuffer = Array.Empty<byte>()
            };

            FileBothDirectoryInformationEntry[] directoryEntries = new[]
            {
                new FileBothDirectoryInformationEntry
                {
                    FileName = "alpha.txt"
                },
                new FileBothDirectoryInformationEntry
                {
                    FileName = "nested"
                }
            };

            Smb2CompoundPacket negotiatePacket = new Smb2CompoundPacket(new[]
            {
                new Smb2CompoundPacketEntry(smb2Header, negotiateRequest.ToByteArray())
            });

            return new List<ProtocolMutationCorpusEntry>
            {
                new ProtocolMutationCorpusEntry(
                    "DirectTcpFrameHeader",
                    new DirectTcpFrameHeader { Length = 64 }.ToByteArray(),
                    bytes =>
                    {
                        DirectTcpFrameHeader parsedHeader = DirectTcpFrameHeader.ReadFrom(bytes);
                        DirectTcpFrameValidator.Validate(parsedHeader);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2Header",
                    smb2Header.ToByteArray(),
                    bytes =>
                    {
                        Smb2Header parsedHeader = Smb2Header.ReadFrom(bytes);
                        Smb2HeaderValidator.Validate(parsedHeader);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2NegotiateRequest",
                    negotiateRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(bytes);
                        Smb2NegotiateRequestValidator.Validate(parsedRequest);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2CreateRequest",
                    createRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2CreateRequest parsedRequest = Smb2CreateRequest.ReadFrom(bytes);
                        Smb2CreateRequestValidator.Validate(parsedRequest);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2ChangeNotifyRequest",
                    changeNotifyRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2ChangeNotifyRequest parsedRequest = Smb2ChangeNotifyRequest.ReadFrom(bytes);
                        Smb2ChangeNotifyRequestValidator.Validate(parsedRequest);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2IoctlRequest",
                    ioctlRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2IoctlRequest parsedRequest = Smb2IoctlRequest.ReadFrom(bytes);
                        Smb2IoctlRequestValidator.Validate(parsedRequest);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2LeaseBreakAcknowledgment",
                    leaseAcknowledgment.ToByteArray(),
                    bytes =>
                    {
                        Smb2LeaseBreakAcknowledgment parsedAcknowledgment = Smb2LeaseBreakAcknowledgment.ReadFrom(bytes);
                        Smb2LeaseBreakAcknowledgmentValidator.Validate(parsedAcknowledgment);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2QueryInfoRequest",
                    queryInfoRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2QueryInfoRequest parsedRequest = Smb2QueryInfoRequest.ReadFrom(bytes);
                        Smb2QueryInfoRequestValidator.Validate(parsedRequest);
                    }),
                new ProtocolMutationCorpusEntry(
                    "FileBothDirectoryInformationEntry",
                    FileBothDirectoryInformationEntry.EncodeEntries(directoryEntries),
                    bytes =>
                    {
                        FileBothDirectoryInformationEntry.DecodeEntries(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb2CompoundPacket",
                    negotiatePacket.ToByteArray(),
                    bytes =>
                    {
                        Smb2CompoundPacket.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "DfsReferralRequest",
                    new DfsReferralRequest
                    {
                        MaxReferralLevel = 2,
                        RequestPath = @"\labserver\namespace\link"
                    }.ToByteArray(),
                    bytes =>
                    {
                        DfsReferralRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "DfsReferralResponse",
                    new DfsReferralResponse
                    {
                        PathConsumed = 24,
                        HeaderFlags = DfsReferralHeaderFlags.StorageServers,
                        Entries = new[]
                        {
                            new DfsReferralEntryV2
                            {
                                IsRootTarget = false,
                                TimeToLive = 600,
                                DfsPath = @"\labserver\namespace",
                                NetworkAddress = @"\target\share"
                            }
                        }
                    }.ToByteArray(),
                    bytes =>
                    {
                        DfsReferralResponse.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb311NegotiateContextList",
                    Smb2NegotiateContextList.Encode(new[]
                    {
                        new Smb2NegotiateContextEntry
                        {
                            ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities,
                            Payload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x11, 0x22, 0x33, 0x44 }
                            }.ToByteArray()
                        },
                        new Smb2NegotiateContextEntry
                        {
                            ContextType = Smb2NegotiateContextType.EncryptionCapabilities,
                            Payload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            }.ToByteArray()
                        }
                    }),
                    bytes =>
                    {
                        Smb2NegotiateContextList.Decode(bytes, 2);
                    }),
                new ProtocolMutationCorpusEntry(
                    "DfsReferralEntryV3Response",
                    BuildDfsReferralResponseV3Baseline(),
                    bytes =>
                    {
                        DfsReferralResponse.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "DfsReferralEntryV3NameListResponse",
                    BuildDfsReferralResponseV3NameListBaseline(),
                    bytes =>
                    {
                        DfsReferralResponse.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "DfsReferralRequestEx",
                    new DfsReferralRequestEx
                    {
                        MaxReferralLevel = 4,
                        IncludeSiteName = true,
                        PathConsumed = 0,
                        RequestFileName = "\\\\dfs.contoso.test\\namespace\\path",
                        SiteName = "Default-First-Site-Name"
                    }.ToByteArray(),
                    bytes =>
                    {
                        DfsReferralRequestEx.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1NegotiateResponse",
                    BuildSmb1NegotiateResponseBaseline(),
                    bytes =>
                    {
                        Smb1NegotiateResponse.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1SessionSetupAndXRequest",
                    BuildSmb1SessionSetupAndXRequestBaseline(),
                    bytes =>
                    {
                        Smb1SessionSetupAndXRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1TreeConnectAndXRequest",
                    BuildSmb1TreeConnectAndXRequestBaseline(),
                    bytes =>
                    {
                        Smb1TreeConnectAndXRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1NtCreateAndXRequest",
                    BuildSmb1NtCreateAndXRequestBaseline(),
                    bytes =>
                    {
                        Smb1NtCreateAndXRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1ReadAndXRequest",
                    BuildSmb1ReadAndXRequestBaseline(),
                    bytes =>
                    {
                        Smb1ReadAndXRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1WriteAndXRequest",
                    BuildSmb1WriteAndXRequestBaseline(),
                    bytes =>
                    {
                        Smb1WriteAndXRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1LockingAndXRequest",
                    BuildSmb1LockingAndXRequestBaseline(),
                    bytes =>
                    {
                        Smb1LockingAndXRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1Transaction2Request",
                    BuildSmb1Transaction2RequestBaseline(),
                    bytes =>
                    {
                        Smb1Transaction2Request.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "Smb1NtTransactRequest",
                    BuildSmb1NtTransactRequestBaseline(),
                    bytes =>
                    {
                        Smb1NtTransactRequest.ReadFrom(bytes);
                    }),
                new ProtocolMutationCorpusEntry(
                    "NetBiosSessionRequest",
                    new NetBiosSessionRequest
                    {
                        CalledName = NetBiosEncodedName.FromServiceName("FILESERVER", NetBiosEncodedName.FileServerServiceSuffix),
                        CallingName = NetBiosEncodedName.FromServiceName("WORKSTATION", NetBiosEncodedName.WorkstationServiceSuffix)
                    }.ToByteArray(),
                    bytes =>
                    {
                        NetBiosSessionRequest.ReadFrom(bytes);
                    })
            };
        }

        internal static byte[] BuildDfsReferralResponseV3Baseline()
        {
            DfsReferralResponse response = new DfsReferralResponse
            {
                PathConsumed = 24,
                HeaderFlags = DfsReferralHeaderFlags.StorageServers
            };
            response.EntriesV3.Add(new DfsReferralEntryV3
            {
                VersionNumber = 4,
                IsRootTarget = true,
                ReferralEntryFlags = DfsReferralEntryFlags.TargetSetBoundary,
                TimeToLive = 600,
                DfsPath = "\\\\dfs.contoso.test\\share",
                DfsAlternatePath = "\\\\dfs.contoso.test\\share",
                NetworkAddress = "\\\\fileserver.contoso.test\\share",
                ServiceSiteGuid = new byte[16]
            });
            return response.ToByteArray();
        }

        internal static byte[] BuildDfsReferralResponseV3NameListBaseline()
        {
            DfsReferralResponse response = new DfsReferralResponse
            {
                PathConsumed = 16,
                HeaderFlags = DfsReferralHeaderFlags.ReferralServers
            };
            response.EntriesV3.Add(new DfsReferralEntryV3
            {
                VersionNumber = 3,
                IsRootTarget = false,
                ReferralEntryFlags = DfsReferralEntryFlags.NameListReferral,
                TimeToLive = 600,
                SpecialName = "\\\\contoso.test",
                ExpandedNames = new[]
                {
                    "\\\\dc1.contoso.test"
                }
            });
            return response.ToByteArray();
        }

        internal static Smb1Header BuildSmb1MutationHeader(Smb1Command command)
        {
            return new Smb1Header
            {
                Command = command,
                Flags = Smb1HeaderFlags.CaseInsensitive,
                Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                Signature = new byte[8],
                TreeId = 0xCAFE,
                UserId = 0x1234,
                MultiplexId = 0x4242
            };
        }

        internal static byte[] BuildSmb1NegotiateResponseBaseline()
        {
            return new Smb1NegotiateResponse
            {
                Header = new Smb1Header
                {
                    Command = Smb1Command.Negotiate,
                    Status = NtStatus.Success,
                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                    Signature = new byte[8]
                },
                DialectIndex = 0,
                SecurityMode = Smb1SecurityMode.UserSecurity | Smb1SecurityMode.EncryptPasswords | Smb1SecurityMode.SigningEnabled,
                MaxMpxCount = 50,
                MaxNumberVcs = 1,
                MaxBufferSize = 0x00010000U,
                MaxRawSize = 0x00010000U,
                SessionKey = 0,
                Capabilities = Smb1Capabilities.NtSmbs | Smb1Capabilities.Status32 | Smb1Capabilities.ExtendedSecurity,
                SystemTime = 0x01D89AB000000000L,
                ServerTimeZoneMinutes = 0,
                ServerGuid = Guid.Empty,
                SecurityBlob = new byte[] { 0x60, 0x16, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 }
            }.ToByteArray();
        }

        internal static byte[] BuildSmb1SessionSetupAndXRequestBaseline()
        {
            return new Smb1SessionSetupAndXRequest
            {
                Header = BuildSmb1MutationHeader(Smb1Command.SessionSetupAndX),
                MaxBufferSize = (ushort)0xFFFF,
                MaxMpxCount = 50,
                VcNumber = 1,
                SessionKey = 0,
                Capabilities = Smb1Capabilities.NtSmbs | Smb1Capabilities.Status32 | Smb1Capabilities.ExtendedSecurity,
                SecurityBlob = new byte[] { 0x60, 0x10, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 },
                NativeOS = "Windows",
                NativeLanMan = "Windows"
            }.ToByteArray();
        }

        internal static byte[] BuildSmb1TreeConnectAndXRequestBaseline()
        {
            return new Smb1TreeConnectAndXRequest
            {
                Header = BuildSmb1MutationHeader(Smb1Command.TreeConnectAndX),
                Flags = 0,
                Password = new byte[] { 0x00 },
                Path = "\\\\fileserver.contoso.test\\share",
                Service = "?????"
            }.ToByteArray();
        }

        internal static byte[] BuildSmb1NtCreateAndXRequestBaseline()
        {
            return new Smb1NtCreateAndXRequest
            {
                Header = BuildSmb1MutationHeader(Smb1Command.NtCreateAndX),
                DesiredAccess = 0x00120089U,
                ShareAccess = 0x00000007U,
                CreateDisposition = 0x00000001U,
                CreateOptions = 0x00000040U,
                ImpersonationLevel = 0x00000002U,
                FileName = "docs\\readme.txt"
            }.ToByteArray();
        }

        internal static byte[] BuildSmb1ReadAndXRequestBaseline()
        {
            return new Smb1ReadAndXRequest
            {
                Header = BuildSmb1MutationHeader(Smb1Command.ReadAndX),
                FileId = 0x4242,
                FileOffset = 0x0000_0001_0000_0010UL,
                MaxCountOfBytesToReturn = 4096,
                MinCountOfBytesToReturn = 1,
                TimeoutOrMaxCountHigh = 0xFFFFFFFFU,
                Remaining = 0
            }.ToByteArray();
        }

        internal static byte[] BuildSmb1WriteAndXRequestBaseline()
        {
            return new Smb1WriteAndXRequest
            {
                Header = BuildSmb1MutationHeader(Smb1Command.WriteAndX),
                FileId = 0x4242,
                FileOffset = 0x0000_0002_0000_0030UL,
                WriteMode = 0x0008,
                Remaining = 0,
                Data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 }
            }.ToByteArray();
        }

        internal static byte[] BuildSmb1LockingAndXRequestBaseline()
        {
            Smb1LockingAndXRequest request = new Smb1LockingAndXRequest
            {
                Header = BuildSmb1MutationHeader(Smb1Command.LockingAndX),
                FileId = 0x4242,
                LockType = Smb1LockingAndXRequest.LockTypeLargeFiles,
                OplockLevel = 0,
                Timeout = 5000
            };
            request.Locks.Add(new Smb1LockingAndXRequest.LockRange
            {
                ProcessId = 0x0042,
                Offset = 0x0000_0001_0000_0010UL,
                Length = 0x0000_0000_0000_1000UL
            });
            request.Unlocks.Add(new Smb1LockingAndXRequest.LockRange
            {
                ProcessId = 0x0042,
                Offset = 0x0000_0002_0000_0000UL,
                Length = 0x0000_0000_0000_2000UL
            });
            return request.ToByteArray();
        }

        internal static byte[] BuildSmb1Transaction2RequestBaseline()
        {
            return new Smb1Transaction2Request
            {
                Header = BuildSmb1MutationHeader(Smb1Command.Transaction2),
                SubCommand = Smb1Transaction2SubCommand.QueryPathInformation,
                TotalParameterCount = 6,
                TotalDataCount = 10,
                MaxParameterCount = 0x0040,
                MaxDataCount = 0x4000,
                MaxSetupCount = 0,
                Flags = 0,
                Timeout = 0,
                Parameters = new byte[] { 0x05, 0x01, 0x00, 0x00, 0x07, 0x01 },
                Data = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 }
            }.ToByteArray();
        }

        internal static byte[] BuildSmb1NtTransactRequestBaseline()
        {
            return new Smb1NtTransactRequest
            {
                Header = BuildSmb1MutationHeader(Smb1Command.NtTransact),
                MaxSetupCount = 0,
                TotalParameterCount = 6,
                TotalDataCount = 8,
                MaxParameterCount = 0x0000_FFFFU,
                MaxDataCount = 0x0010_0000U,
                Function = 0x0004,
                Setup = new ushort[] { 0x4242, 0x0001, 0x0040 },
                Parameters = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 },
                Data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 }
            }.ToByteArray();
        }

        internal static byte[] Hex(string value)
        {
            return Convert.FromHexString(value.Replace(" ", string.Empty));
        }

        internal static async Task<byte[]> ReadFrameFromPipeAsync(PipeReader reader, IFrameProtocol frameProtocol, CancellationToken cancellationToken)
        {
            while (true)
            {
                ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                ReadOnlySequence<byte> buffer = readResult.Buffer;

                if (frameProtocol.TryReadFrame(buffer, out byte[]? payload, out long bytesConsumed))
                {
                    if (payload == null)
                    {
                        throw new InvalidOperationException("The frame protocol returned a null payload.");
                    }

                    SequencePosition consumedPosition = buffer.GetPosition(bytesConsumed);
                    reader.AdvanceTo(consumedPosition, buffer.End);
                    return payload;
                }

                reader.AdvanceTo(buffer.Start, buffer.End);

                if (readResult.IsCompleted)
                {
                    throw new InvalidOperationException("The pipe completed before a full frame was available.");
                }
            }
        }

    }
}

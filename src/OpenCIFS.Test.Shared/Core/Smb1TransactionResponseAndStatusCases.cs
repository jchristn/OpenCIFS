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
    internal static class Smb1TransactionResponseAndStatusCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1StatusMappingRoundTripsCommonNtStatusValuesAndPreservesUnknownAsGenericFailure",
                        displayName: "Bounded SMB1 status mapping round-trips common NTSTATUS values and preserves unknown as generic failure",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1StatusToDosCase[] cases = new[]
                            {
                                new Smb1StatusToDosCase(NtStatus.Success, Smb1DosErrorClass.Success, (ushort)0x0000),
                                new Smb1StatusToDosCase(NtStatus.ObjectNameNotFound, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.BadFile),
                                new Smb1StatusToDosCase(NtStatus.ObjectPathNotFound, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.BadPath),
                                new Smb1StatusToDosCase(NtStatus.AccessDenied, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.NoAccess),
                                new Smb1StatusToDosCase(NtStatus.InvalidHandle, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.BadFid),
                                new Smb1StatusToDosCase(NtStatus.InvalidParameter, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.InvalidParameter),
                                new Smb1StatusToDosCase(NtStatus.SharingViolation, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.BadShare),
                                new Smb1StatusToDosCase(NtStatus.FileLockConflict, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.Lock),
                                new Smb1StatusToDosCase(NtStatus.ObjectNameCollision, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.FileExists),
                                new Smb1StatusToDosCase(NtStatus.NoMoreFiles, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.NoFiles),
                                new Smb1StatusToDosCase(NtStatus.BufferOverflow, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.MoreData),
                                new Smb1StatusToDosCase(NtStatus.RangeNotLocked, Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.NotLocked),
                                new Smb1StatusToDosCase(NtStatus.NetworkNameDeleted, Smb1DosErrorClass.ErrSrv, Smb1DosErrorCode.InvalidTid),
                                new Smb1StatusToDosCase(NtStatus.BadNetworkName, Smb1DosErrorClass.ErrSrv, Smb1DosErrorCode.InvalidNetworkName),
                                new Smb1StatusToDosCase(NtStatus.LogonFailure, Smb1DosErrorClass.ErrSrv, Smb1DosErrorCode.BadPassword),
                                new Smb1StatusToDosCase(NtStatus.NotSupported, Smb1DosErrorClass.ErrSrv, Smb1DosErrorCode.UnsupportedCommand),
                                new Smb1StatusToDosCase(NtStatus.UserSessionDeleted, Smb1DosErrorClass.ErrSrv, Smb1DosErrorCode.BadUid),
                                new Smb1StatusToDosCase(NtStatus.DiskFull, Smb1DosErrorClass.ErrHrd, Smb1DosErrorCode.DiskFull)
                            };

                            foreach (Smb1StatusToDosCase testCase in cases)
                            {
                                Smb1StatusMapping.NtStatusToDosError(testCase.Status, out Smb1DosErrorClass actualClass, out ushort actualCode);
                                TestAssertions.Equal(testCase.ExpectedClass, actualClass, "Unexpected DOS class for NTSTATUS " + testCase.Status + ".");
                                TestAssertions.Equal(testCase.ExpectedCode, actualCode, "Unexpected DOS code for NTSTATUS " + testCase.Status + ".");

                                uint packed = Smb1StatusMapping.PackNtStatusToLegacyStatusField(testCase.Status);
                                TestAssertions.Equal((byte)testCase.ExpectedClass, (byte)(packed & 0xFF), "Unexpected packed class byte for NTSTATUS " + testCase.Status + ".");
                                TestAssertions.Equal(testCase.ExpectedCode, (ushort)((packed >> 16) & 0xFFFF), "Unexpected packed code bytes for NTSTATUS " + testCase.Status + ".");
                            }

                            Smb1DosToNtStatusCase[] reverseCases = new[]
                            {
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.Success, (ushort)0x0000, NtStatus.Success),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.BadFile, NtStatus.ObjectNameNotFound),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.BadPath, NtStatus.ObjectPathNotFound),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.NoAccess, NtStatus.AccessDenied),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.BadFid, NtStatus.InvalidHandle),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.NoFids, NtStatus.TooManyOpenedFiles),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.NoMemory, NtStatus.InsufficientResources),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrDos, Smb1DosErrorCode.FileExists, NtStatus.ObjectNameCollision),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrSrv, Smb1DosErrorCode.BadPassword, NtStatus.LogonFailure),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrSrv, Smb1DosErrorCode.BadUid, NtStatus.UserSessionDeleted),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrHrd, Smb1DosErrorCode.DiskFull, NtStatus.DiskFull),
                                new Smb1DosToNtStatusCase(Smb1DosErrorClass.ErrCmd, (ushort)0x0000, NtStatus.NotSupported)
                            };

                            foreach (Smb1DosToNtStatusCase reverseCase in reverseCases)
                            {
                                NtStatus actual = Smb1StatusMapping.DosErrorToNtStatus(reverseCase.DosErrorClass, reverseCase.Code);
                                TestAssertions.Equal(reverseCase.Expected, actual, "Unexpected NTSTATUS for DOS class " + reverseCase.DosErrorClass + " code 0x" + reverseCase.Code.ToString("X4") + ".");
                            }

                            NtStatus unknownNtStatus = (NtStatus)0xC0DEFEEDU;
                            Smb1StatusMapping.NtStatusToDosError(unknownNtStatus, out Smb1DosErrorClass unknownClass, out ushort unknownCode);
                            TestAssertions.Equal(Smb1DosErrorClass.ErrSrv, unknownClass, "Unknown NTSTATUS should map to ERRSRV class.");
                            TestAssertions.Equal(Smb1DosErrorCode.Error, unknownCode, "Unknown NTSTATUS should map to generic ERRSRV/ERRerror.");

                            NtStatus unknownDosCombo = Smb1StatusMapping.DosErrorToNtStatus(Smb1DosErrorClass.ErrDos, 0xFFFE);
                            TestAssertions.Equal(NtStatus.Unsuccessful, unknownDosCombo, "Unknown DOS combo should map to STATUS_UNSUCCESSFUL.");

                            uint roundTripPacked = Smb1StatusMapping.PackNtStatusToLegacyStatusField(NtStatus.AccessDenied);
                            NtStatus roundTripped = Smb1StatusMapping.UnpackLegacyStatusFieldToNtStatus(roundTripPacked);
                            TestAssertions.Equal(NtStatus.AccessDenied, roundTripped, "Pack-then-unpack should preserve a representable NTSTATUS.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TransactionAndNtTransactResponseCodecsRoundTripParameterAndDataBlocks",
                        displayName: "Bounded SMB1 TRANSACTION and NT_TRANSACT response codecs round-trip parameter and data blocks",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] transParams = new byte[] { 0x10, 0x20 };
                            byte[] transData = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };

                            Smb1TransactionResponse transResponse = new Smb1TransactionResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = (ushort)transParams.Length,
                                TotalDataCount = (ushort)transData.Length,
                                Setup = new ushort[] { 0x0001 },
                                Parameters = transParams,
                                Data = transData
                            };
                            byte[] transBytes = transResponse.ToByteArray();
                            Smb1TransactionResponse parsedTransResponse = Smb1TransactionResponse.ReadFrom(transBytes);
                            TestAssertions.SequenceEqual(transParams, parsedTransResponse.Parameters, "Unexpected SMB1 TRANSACTION response Parameters.");
                            TestAssertions.SequenceEqual(transData, parsedTransResponse.Data, "Unexpected SMB1 TRANSACTION response Data.");
                            TestAssertions.Equal(1, parsedTransResponse.Setup.Length, "Unexpected SMB1 TRANSACTION response Setup count.");

                            byte[] ntParams = new byte[] { 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00 };
                            byte[] ntData = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };

                            Smb1NtTransactResponse ntResponse = new Smb1NtTransactResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtTransact,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = (uint)ntParams.Length,
                                TotalDataCount = (uint)ntData.Length,
                                Setup = new ushort[] { 0x4242, 0x0001 },
                                Parameters = ntParams,
                                Data = ntData
                            };
                            byte[] ntBytes = ntResponse.ToByteArray();
                            Smb1NtTransactResponse parsedNtResponse = Smb1NtTransactResponse.ReadFrom(ntBytes);
                            TestAssertions.SequenceEqual(ntParams, parsedNtResponse.Parameters, "Unexpected SMB1 NT_TRANSACT response Parameters.");
                            TestAssertions.SequenceEqual(ntData, parsedNtResponse.Data, "Unexpected SMB1 NT_TRANSACT response Data.");
                            TestAssertions.Equal(2, parsedNtResponse.Setup.Length, "Unexpected SMB1 NT_TRANSACT response Setup count.");
                            TestAssertions.Equal(ntResponse.Setup[0], parsedNtResponse.Setup[0], "Unexpected SMB1 NT_TRANSACT response Setup[0].");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TransactionFamilySecondaryFragmentsRoundTripDisplacementAndPayloadAcrossAllThreeShapes",
                        displayName: "Bounded SMB1 transaction-family secondary fragments round-trip displacement and payload across all three shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] params1 = new byte[] { 0x05, 0x06, 0x07, 0x08 };
                            byte[] data1 = new byte[] { 0xA1, 0xA2, 0xA3 };

                            Smb1TransactionSecondary transSec = new Smb1TransactionSecondary
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.TransactionSecondary,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = 16,
                                TotalDataCount = 32,
                                ParameterDisplacement = 8,
                                DataDisplacement = 16,
                                Parameters = params1,
                                Data = data1
                            };
                            byte[] transSecBytes = transSec.ToByteArray();
                            Smb1TransactionSecondary parsedTransSec = Smb1TransactionSecondary.ReadFrom(transSecBytes);
                            TestAssertions.Equal((ushort)8, parsedTransSec.ParameterDisplacement, "Unexpected TRANSACTION_SECONDARY ParameterDisplacement.");
                            TestAssertions.Equal((ushort)16, parsedTransSec.DataDisplacement, "Unexpected TRANSACTION_SECONDARY DataDisplacement.");
                            TestAssertions.SequenceEqual(params1, parsedTransSec.Parameters, "Unexpected TRANSACTION_SECONDARY Parameters.");
                            TestAssertions.SequenceEqual(data1, parsedTransSec.Data, "Unexpected TRANSACTION_SECONDARY Data.");

                            Smb1Transaction2Secondary trans2Sec = new Smb1Transaction2Secondary
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction2Secondary,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = 16,
                                TotalDataCount = 32,
                                ParameterDisplacement = 4,
                                DataDisplacement = 8,
                                FileId = 0x4242,
                                Parameters = params1,
                                Data = data1
                            };
                            byte[] trans2SecBytes = trans2Sec.ToByteArray();
                            Smb1Transaction2Secondary parsedTrans2Sec = Smb1Transaction2Secondary.ReadFrom(trans2SecBytes);
                            TestAssertions.Equal((ushort)0x4242, parsedTrans2Sec.FileId, "Unexpected TRANSACTION2_SECONDARY FileId.");
                            TestAssertions.SequenceEqual(params1, parsedTrans2Sec.Parameters, "Unexpected TRANSACTION2_SECONDARY Parameters.");
                            TestAssertions.SequenceEqual(data1, parsedTrans2Sec.Data, "Unexpected TRANSACTION2_SECONDARY Data.");

                            Smb1NtTransactSecondary ntSec = new Smb1NtTransactSecondary
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtTransactSecondary,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = 0x0001_0000U,
                                TotalDataCount = 0x0002_0000U,
                                ParameterDisplacement = 0x0000_0100U,
                                DataDisplacement = 0x0000_0200U,
                                Parameters = params1,
                                Data = data1
                            };
                            byte[] ntSecBytes = ntSec.ToByteArray();
                            Smb1NtTransactSecondary parsedNtSec = Smb1NtTransactSecondary.ReadFrom(ntSecBytes);
                            TestAssertions.Equal(0x0000_0100U, parsedNtSec.ParameterDisplacement, "Unexpected NT_TRANSACT_SECONDARY ParameterDisplacement.");
                            TestAssertions.Equal(0x0000_0200U, parsedNtSec.DataDisplacement, "Unexpected NT_TRANSACT_SECONDARY DataDisplacement.");
                            TestAssertions.Equal(0x0001_0000U, parsedNtSec.TotalParameterCount, "Unexpected NT_TRANSACT_SECONDARY TotalParameterCount.");
                            TestAssertions.SequenceEqual(params1, parsedNtSec.Parameters, "Unexpected NT_TRANSACT_SECONDARY Parameters.");
                            TestAssertions.SequenceEqual(data1, parsedNtSec.Data, "Unexpected NT_TRANSACT_SECONDARY Data.");
                            return Task.CompletedTask;
                        }),
            };
        }
    }
}


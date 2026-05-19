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
    internal static class Smb2FileIoSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2FileIo",
                displayName: "SMB2 create, read, write, flush, and close messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2FileIo",
                        caseId: "CreateAndCloseMessagesRoundTrip",
                        displayName: "SMB2 create, flush, and close messages round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

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

                            byte[] encodedCreateRequest = createRequest.ToByteArray();
                            Smb2CreateRequest parsedCreateRequest = Smb2CreateRequest.ReadFrom(encodedCreateRequest);
                            Smb2CreateRequestValidator.Validate(parsedCreateRequest);
                            TestAssertions.Equal("folder\\notes.txt", parsedCreateRequest.Name, "Unexpected create-request path.");
                            TestAssertions.Equal(0xC0000000U, parsedCreateRequest.DesiredAccess, "Unexpected create-request access mask.");
                            TestAssertions.Equal(Smb2CreateDisposition.OpenIf, parsedCreateRequest.CreateDisposition, "Unexpected create-request disposition.");

                            Smb2CreateResponse createResponse = new Smb2CreateResponse
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                Flags = 0,
                                CreateAction = Smb2CreateAction.Created,
                                CreationTime = 0x0102030405060708UL,
                                LastAccessTime = 0x1112131415161718UL,
                                LastWriteTime = 0x2122232425262728UL,
                                ChangeTime = 0x3132333435363738UL,
                                AllocationSize = 4096,
                                EndOfFile = 17,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                PersistentFileId = 9,
                                VolatileFileId = 10,
                                CreateContexts = Array.Empty<byte>()
                            };

                            byte[] encodedCreateResponse = createResponse.ToByteArray();
                            Smb2CreateResponse parsedCreateResponse = Smb2CreateResponse.ReadFrom(encodedCreateResponse);
                            Smb2CreateResponseValidator.Validate(parsedCreateResponse);
                            TestAssertions.Equal(9UL, parsedCreateResponse.PersistentFileId, "Unexpected persistent file identifier.");
                            TestAssertions.Equal(10UL, parsedCreateResponse.VolatileFileId, "Unexpected volatile file identifier.");
                            TestAssertions.Equal(17UL, parsedCreateResponse.EndOfFile, "Unexpected create-response EOF size.");

                            Smb2FlushRequest flushRequest = new Smb2FlushRequest
                            {
                                PersistentFileId = 9,
                                VolatileFileId = 10
                            };
                            Smb2FlushRequest parsedFlushRequest = Smb2FlushRequest.ReadFrom(flushRequest.ToByteArray());
                            Smb2FlushRequestValidator.Validate(parsedFlushRequest);
                            TestAssertions.Equal(10UL, parsedFlushRequest.VolatileFileId, "Unexpected flush-request volatile file identifier.");

                            Smb2FlushResponse flushResponse = Smb2FlushResponse.ReadFrom(new Smb2FlushResponse().ToByteArray());
                            Smb2FlushResponseValidator.Validate(flushResponse);

                            Smb2CloseRequest closeRequest = new Smb2CloseRequest
                            {
                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                PersistentFileId = 9,
                                VolatileFileId = 10
                            };
                            Smb2CloseRequest parsedCloseRequest = Smb2CloseRequest.ReadFrom(closeRequest.ToByteArray());
                            Smb2CloseRequestValidator.Validate(parsedCloseRequest);
                            TestAssertions.Equal(Smb2CloseFlags.PostQueryAttributes, parsedCloseRequest.Flags, "Unexpected close-request flags.");

                            Smb2CloseResponse closeResponse = new Smb2CloseResponse
                            {
                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                CreationTime = 0x0102030405060708UL,
                                LastAccessTime = 0x1112131415161718UL,
                                LastWriteTime = 0x2122232425262728UL,
                                ChangeTime = 0x3132333435363738UL,
                                AllocationSize = 4096,
                                EndOfFile = 17,
                                FileAttributes = ProtocolFileAttributes.Archive
                            };
                            Smb2CloseResponse parsedCloseResponse = Smb2CloseResponse.ReadFrom(closeResponse.ToByteArray());
                            Smb2CloseResponseValidator.Validate(parsedCloseResponse);
                            TestAssertions.Equal(ProtocolFileAttributes.Archive, parsedCloseResponse.FileAttributes, "Unexpected close-response file attributes.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2FileIo",
                        caseId: "ReadAndWriteMessagesRoundTrip",
                        displayName: "SMB2 read and write messages round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2WriteRequest writeRequest = new Smb2WriteRequest
                            {
                                Offset = 128,
                                PersistentFileId = 17,
                                VolatileFileId = 18,
                                Channel = 0,
                                RemainingBytes = 0,
                                Flags = Smb2WriteFlags.None,
                                DataBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 },
                                WriteChannelInfo = Array.Empty<byte>()
                            };

                            Smb2WriteRequest parsedWriteRequest = Smb2WriteRequest.ReadFrom(writeRequest.ToByteArray());
                            Smb2WriteRequestValidator.Validate(parsedWriteRequest);
                            TestAssertions.Equal(128UL, parsedWriteRequest.Offset, "Unexpected write-request offset.");
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x20, 0x30, 0x40 }, parsedWriteRequest.DataBuffer, "Unexpected write-request data.");

                            Smb2WriteResponse writeResponse = new Smb2WriteResponse
                            {
                                Count = 4
                            };
                            Smb2WriteResponse parsedWriteResponse = Smb2WriteResponse.ReadFrom(writeResponse.ToByteArray());
                            Smb2WriteResponseValidator.Validate(parsedWriteResponse);
                            TestAssertions.Equal(4U, parsedWriteResponse.Count, "Unexpected write-response count.");

                            Smb2ReadRequest readRequest = new Smb2ReadRequest
                            {
                                Length = 4,
                                Offset = 128,
                                PersistentFileId = 17,
                                VolatileFileId = 18,
                                MinimumCount = 2,
                                Channel = 0,
                                RemainingBytes = 0,
                                ReadChannelInfo = Array.Empty<byte>()
                            };

                            Smb2ReadRequest parsedReadRequest = Smb2ReadRequest.ReadFrom(readRequest.ToByteArray());
                            Smb2ReadRequestValidator.Validate(parsedReadRequest);
                            TestAssertions.Equal(4U, parsedReadRequest.Length, "Unexpected read-request length.");
                            TestAssertions.Equal(2U, parsedReadRequest.MinimumCount, "Unexpected read-request minimum count.");

                            Smb2ReadResponse readResponse = new Smb2ReadResponse
                            {
                                DataBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 },
                                DataRemaining = 0,
                                Flags = 0
                            };

                            Smb2ReadResponse parsedReadResponse = Smb2ReadResponse.ReadFrom(readResponse.ToByteArray());
                            Smb2ReadResponseValidator.Validate(parsedReadResponse);
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x20, 0x30, 0x40 }, parsedReadResponse.DataBuffer, "Unexpected read-response data.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2FileIo",
                        caseId: "FileIoValidatorsRejectUnsupportedCurrentSliceFeatures",
                        displayName: "SMB2 file-I/O validators allow bounded delete-on-close semantics and reject unsupported combinations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CreateRequest deleteOnCloseRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                Name = "temp\\transient.txt",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(deleteOnCloseRequest);

                            Smb2CreateRequest directoryOpenRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80000000U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.DirectoryFile,
                                Name = "directory",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(directoryOpenRequest);

                            Smb2CreateRequest directoryCreateRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80000000U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Create,
                                CreateOptions = Smb2CreateOptions.DirectoryFile,
                                Name = "directory-created",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(directoryCreateRequest);

                            Smb2CreateRequest directoryDeleteOnCloseRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80010000U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateOptions = Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                Name = "directory-transient",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(directoryDeleteOnCloseRequest);

                            Smb2CreateRequest shareRootOpenRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80000080U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.OpenReparsePoint,
                                Name = string.Empty,
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(shareRootOpenRequest);

                            Smb2CreateRequest createContextRequest = new Smb2CreateRequest
                            {
                                Name = "notes.txt",
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    new Smb2CreateContext
                                    {
                                        Name = Encoding.ASCII.GetBytes("ExtA"),
                                        Data = new byte[] { 0x01, 0x02, 0x03, 0x04 }
                                    }
                                })
                            };
                            Smb2CreateRequestValidator.Validate(createContextRequest);

                            LittleEndianWriter unpaddedCreateContextWriter = new LittleEndianWriter();
                            unpaddedCreateContextWriter.WriteUInt32(0);
                            unpaddedCreateContextWriter.WriteUInt16(16);
                            unpaddedCreateContextWriter.WriteUInt16(4);
                            unpaddedCreateContextWriter.WriteUInt16(0);
                            unpaddedCreateContextWriter.WriteUInt16(24);
                            unpaddedCreateContextWriter.WriteUInt32(12);
                            unpaddedCreateContextWriter.WriteBytes(Encoding.ASCII.GetBytes("ExtA"));
                            while (unpaddedCreateContextWriter.Length < 24)
                            {
                                unpaddedCreateContextWriter.WriteByte(0);
                            }

                            unpaddedCreateContextWriter.WriteBytes(new byte[]
                            {
                                0x01, 0x02, 0x03, 0x04,
                                0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0A, 0x0B, 0x0C
                            });
                            Smb2CreateRequest unpaddedCreateContextRequest = new Smb2CreateRequest
                            {
                                Name = "notes.txt",
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateContexts = unpaddedCreateContextWriter.ToArray()
                            };
                            Smb2CreateRequestValidator.Validate(unpaddedCreateContextRequest);

                            Smb2CreateRequest toleratedSmb3HintContextRequest = new Smb2CreateRequest
                            {
                                Name = "directory",
                                DesiredAccess = 0x00100081U,
                                ShareAccess = 0x00000003U,
                                CreateDisposition = Smb2CreateDisposition.Create,
                                CreateOptions = Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.OpenReparsePoint,
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    new Smb2DurableHandleRequestV2Context
                                    {
                                        Timeout = 0,
                                        Flags = Smb2DurableHandleFlags.None,
                                        CreateGuid = Guid.NewGuid()
                                    }.ToCreateContext(),
                                    new Smb2CreateRequestLeaseContext
                                    {
                                        LeaseKey = new byte[16],
                                        LeaseState = Smb2LeaseState.ReadCaching
                                    }.ToCreateContext()
                                })
                            };
                            Smb2CreateRequestValidator.Validate(toleratedSmb3HintContextRequest);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = string.Empty,
                                    DesiredAccess = 0x80000080U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Open,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Empty create names should reject non-directory share-root requests.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "directory",
                                    DesiredAccess = 0x80000000U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Overwrite,
                                    CreateOptions = Smb2CreateOptions.DirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Directory opens should reject unsupported create dispositions for the current SMB 2.0.2 directory slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "temp.txt",
                                    DesiredAccess = 0xC0000000U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.OpenIf,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Delete-on-close should require DELETE access.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "temp.txt",
                                    DesiredAccess = 0xC0010000U,
                                    ShareAccess = 0x00000008U,
                                    CreateDisposition = Smb2CreateDisposition.OpenIf,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Unsupported share-access bits should be rejected.");

                            Smb2CreateRequest supersedeRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Supersede,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "replace.txt",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(supersedeRequest);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "replace.txt",
                                    DesiredAccess = 0xC0000000U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Supersede,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "FILE_SUPERSEDE should require DELETE access.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "notes.txt",
                                    DesiredAccess = 0x80000080U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Open,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2CreateContext
                                        {
                                            Name = Encoding.ASCII.GetBytes("DH2C"),
                                            Data = new byte[32]
                                        }
                                    })
                                }),
                                "Malformed durable-handle v2 reconnect hints should be rejected when the payload does not match the bounded SMB 3.x wire shape.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ReadResponseValidator.Validate(new Smb2ReadResponse
                                {
                                    DataBuffer = Array.Empty<byte>(),
                                    DataRemaining = 0,
                                    Flags = 0
                                }),
                                "Successful read responses should not carry an empty data buffer.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2WriteRequestValidator.Validate(new Smb2WriteRequest
                                {
                                    Offset = 0,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Channel = 0,
                                    RemainingBytes = 0,
                                    Flags = Smb2WriteFlags.WriteThrough,
                                    DataBuffer = new byte[] { 0x01 },
                                    WriteChannelInfo = Array.Empty<byte>()
                                }),
                                "Write flags that are not valid for SMB 2.0.2 should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}

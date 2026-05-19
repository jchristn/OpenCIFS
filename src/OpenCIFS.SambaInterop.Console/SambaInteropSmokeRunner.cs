namespace OpenCIFS.SambaInterop.Console
{
    using System;
    using System.Collections.Generic;
    using System.Reflection;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Protocol;
    using SmbFileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal static class SambaInteropSmokeRunner
    {
        private const uint GenericReadAccess = 0x80000000U;
        private const uint GenericWriteAccess = 0x40000000U;
        private const uint DeleteAccess = 0x00010000U;
        private const uint ShareAccess = 0x00000007U;
        private const string PayloadText = "hello from opencifs client";
        private const ulong TruncatedLength = 6;
        private const string DirectoryName = "opencifs-samba-smoke";
        private const string RenamedDirectoryName = "opencifs-samba-smoke-renamed";
        private const string NestedDirectoryName = "nested";
        private const string FileName = "smoke.txt";
        private const string LargeFileName = "large.bin";
        private const string RenamedFileName = "renamed-smoke.txt";

        internal static async Task<SambaInteropSmokeResult> RunAsync(SambaInteropOptions options)
        {
            CancellationToken cancellationToken = CancellationToken.None;
            string nestedDirectoryPath = DirectoryName + "\\" + NestedDirectoryName;
            string relativeFilePath = DirectoryName + "\\" + FileName;
            string largeRelativeFilePath = DirectoryName + "\\" + LargeFileName;
            string renamedFilePath = DirectoryName + "\\" + RenamedFileName;
            string renamedDirectoryPath = RenamedDirectoryName;
            string renamedNestedDirectoryPath = RenamedDirectoryName + "\\" + NestedDirectoryName;
            string renamedFileInRenamedDirectoryPath = RenamedDirectoryName + "\\" + RenamedFileName;
            byte[] payloadBytes = Encoding.UTF8.GetBytes(PayloadText);
            byte[] largePayloadBytes = CreateLargePayloadBytes(options.LargePayloadLength);
            ulong mutatedLastWriteTime = unchecked((ulong)new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc());
            string dialectLabel = SambaInteropArgumentParser.GetDialectLabel(options.Dialect);

            OpenCifsClientOptions clientOptions = new OpenCifsClientOptions
            {
                ServerName = options.Server,
                ServerPort = options.Port,
                RequireSigning = true,
                PreferEncryption = options.Dialect >= SmbDialect.Smb30,
                MinimumDialect = options.Dialect,
                MaximumDialect = options.Dialect,
                EnableSmb311Preview = options.Dialect == SmbDialect.Smb311
            };
            OpenCifsClientCredential credential = new OpenCifsClientCredential
            {
                UserName = options.UserName,
                UserDomain = options.Domain,
                Password = options.Password
            };

            await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(clientOptions);
            await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(clientOptions);

            OpenCifsClientTreeHandle? firstTree = null;
            OpenCifsClientTreeHandle? secondTree = null;
            OpenCifsClientOpenHandle? directoryHandle = null;
            OpenCifsClientOpenHandle? nestedDirectoryHandle = null;
            OpenCifsClientOpenHandle? firstFileHandle = null;
            OpenCifsClientOpenHandle? largeFileHandle = null;
            OpenCifsClientOpenHandle? secondFileHandle = null;
            OpenCifsClientOpenHandle? renameHandle = null;
            OpenCifsClientOpenHandle? queryHandle = null;
            OpenCifsClientOpenHandle? deleteFileHandle = null;
            OpenCifsClientOpenHandle? deleteLargeFileHandle = null;
            OpenCifsClientOpenHandle? deleteDirectoryHandle = null;
            OpenCifsClientOpenHandle? renameDirectoryHandle = null;
            OpenCifsClientOpenHandle? deleteNestedDirectoryHandle = null;

            try
            {
                await firstClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                await secondClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                OpenCifsRemoteShareInfo[] browsedShares = await firstClient.EnumerateRemoteSharesAsync(cancellationToken).ConfigureAwait(false);
                OpenCifsRemoteShareInfo browsedShareInfo = await firstClient.GetRemoteShareInfoAsync(options.Share, cancellationToken).ConfigureAwait(false);

                if (!ContainsRemoteShare(browsedShares, options.Share))
                {
                    throw new InvalidOperationException("Expected OpenCIFS remote share browsing to find the requested Samba share.");
                }

                if (!StringComparer.OrdinalIgnoreCase.Equals(browsedShareInfo.Name, options.Share))
                {
                    throw new InvalidOperationException("Expected OpenCIFS SRVSVC share-info browsing to return the requested Samba share.");
                }

                firstTree = await firstClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);
                secondTree = await secondClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);

                directoryHandle = await OpenDirectoryCreateCompatAsync(
                    firstClient,
                    firstTree,
                    DirectoryName,
                    cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(directoryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                directoryHandle = null;

                nestedDirectoryHandle = await OpenDirectoryCreateCompatAsync(
                    firstClient,
                    firstTree,
                    nestedDirectoryPath,
                    cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(nestedDirectoryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                nestedDirectoryHandle = null;

                firstFileHandle = await firstClient.OpenAsync(
                    firstTree,
                    relativeFilePath,
                    GenericReadAccess | GenericWriteAccess,
                    SmbFileAttributes.Normal,
                    ShareAccess,
                    Smb2CreateDisposition.OverwriteIf,
                    Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken).ConfigureAwait(false);

                uint writtenCount = await firstClient.WriteAsync(firstFileHandle, payloadBytes, 0, cancellationToken).ConfigureAwait(false);
                byte[] roundTripBytes = await firstClient.ReadAsync(firstFileHandle, (uint)payloadBytes.Length, 0, cancellationToken: cancellationToken).ConfigureAwait(false);
                byte[] standardInfoBytes = await firstClient.QueryInfoAsync(firstFileHandle, FileInformationClass.StandardInformation, cancellationToken: cancellationToken).ConfigureAwait(false);
                FileStandardInformation standardInfo = FileStandardInformation.ReadFrom(standardInfoBytes);
                FileNetworkOpenInformation initialNetworkInfo = FileNetworkOpenInformation.ReadFrom(
                    await firstClient.QueryInfoAsync(firstFileHandle, FileInformationClass.NetworkOpenInformation, cancellationToken: cancellationToken).ConfigureAwait(false));

                Smb2LockElement exclusiveLock = new Smb2LockElement
                {
                    Offset = 0,
                    Length = 8,
                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                };
                await firstClient.LockAsync(firstFileHandle, new[] { exclusiveLock }, cancellationToken).ConfigureAwait(false);

                secondFileHandle = await secondClient.OpenAsync(
                    secondTree,
                    relativeFilePath,
                    GenericReadAccess | GenericWriteAccess,
                    SmbFileAttributes.Normal,
                    ShareAccess,
                    Smb2CreateDisposition.Open,
                    Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken).ConfigureAwait(false);

                bool lockConflictRejected = false;

                try
                {
                    await secondClient.LockAsync(secondFileHandle, new[] { exclusiveLock }, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.LockNotGranted)
                {
                    lockConflictRejected = true;
                }

                if (!lockConflictRejected)
                {
                    throw new InvalidOperationException("Expected Samba to reject the conflicting byte-range lock request.");
                }

                Smb2LockElement unlockElement = new Smb2LockElement
                {
                    Offset = 0,
                    Length = 8,
                    Flags = Smb2LockFlags.Unlock
                };
                await firstClient.LockAsync(firstFileHandle, new[] { unlockElement }, cancellationToken).ConfigureAwait(false);

                await firstClient.SetBasicInfoAsync(
                    firstFileHandle,
                    new FileBasicInformation
                    {
                        LastWriteTime = mutatedLastWriteTime
                    },
                    cancellationToken).ConfigureAwait(false);
                await firstClient.SetEndOfFileAsync(firstFileHandle, TruncatedLength, cancellationToken).ConfigureAwait(false);
                FileNetworkOpenInformation mutatedNetworkInfo = FileNetworkOpenInformation.ReadFrom(
                    await firstClient.QueryInfoAsync(firstFileHandle, FileInformationClass.NetworkOpenInformation, cancellationToken: cancellationToken).ConfigureAwait(false));
                FileStandardInformation truncatedStandardInfo = FileStandardInformation.ReadFrom(
                    await firstClient.QueryInfoAsync(firstFileHandle, FileInformationClass.StandardInformation, cancellationToken: cancellationToken).ConfigureAwait(false));
                byte[] truncatedBytes = await firstClient.ReadAsync(firstFileHandle, (uint)TruncatedLength, 0, cancellationToken: cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(firstFileHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                firstFileHandle = null;
                await secondClient.CloseAsync(secondFileHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                secondFileHandle = null;

                largeFileHandle = await firstClient.OpenAsync(
                    firstTree,
                    largeRelativeFilePath,
                    GenericReadAccess | GenericWriteAccess,
                    SmbFileAttributes.Normal,
                    ShareAccess,
                    Smb2CreateDisposition.OverwriteIf,
                    Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken).ConfigureAwait(false);
                await firstClient.RequestMaximumCreditsAsync(cancellationToken).ConfigureAwait(false);
                uint largeWrittenCount = await WriteAllBytesAsync(firstClient, largeFileHandle, largePayloadBytes, cancellationToken).ConfigureAwait(false);
                byte[] largeRoundTripBytes = await ReadAllBytesAsync(firstClient, largeFileHandle, (uint)largePayloadBytes.Length, cancellationToken).ConfigureAwait(false);
                FileStandardInformation largeStandardInfo = FileStandardInformation.ReadFrom(
                    await firstClient.QueryInfoAsync(largeFileHandle, FileInformationClass.StandardInformation, cancellationToken: cancellationToken).ConfigureAwait(false));

                if (largeWrittenCount != largePayloadBytes.Length)
                {
                    throw new InvalidOperationException("Expected Samba to acknowledge the full bounded large write length.");
                }

                if (!largeRoundTripBytes.AsSpan().SequenceEqual(largePayloadBytes))
                {
                    throw new InvalidOperationException("Expected Samba to round-trip the bounded large payload bytes.");
                }

                if (largeStandardInfo.EndOfFile != (ulong)largePayloadBytes.Length)
                {
                    throw new InvalidOperationException("Expected Samba to report the bounded large payload length through FILE_STANDARD_INFORMATION.");
                }

                await firstClient.CloseAsync(largeFileHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                largeFileHandle = null;

                deleteLargeFileHandle = await firstClient.OpenExistingPathAsync(firstTree, largeRelativeFilePath, DeleteAccess, cancellationToken).ConfigureAwait(false);
                await firstClient.SetDeletePendingAsync(deleteLargeFileHandle, true, cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(deleteLargeFileHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                deleteLargeFileHandle = null;

                renameHandle = await firstClient.OpenExistingPathAsync(firstTree, relativeFilePath, GenericReadAccess | DeleteAccess, cancellationToken).ConfigureAwait(false);
                await firstClient.SetRenameAsync(renameHandle, renamedFilePath, cancellationToken: cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(renameHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                renameHandle = null;

                queryHandle = await firstClient.OpenAsync(
                    firstTree,
                    DirectoryName,
                    GenericReadAccess,
                    SmbFileAttributes.Directory,
                    ShareAccess,
                    Smb2CreateDisposition.Open,
                    Smb2CreateOptions.DirectoryFile,
                    cancellationToken).ConfigureAwait(false);
                byte[] queryDirectoryBytes = await firstClient.QueryDirectoryAsync(
                    queryHandle,
                    FileInformationClass.FullDirectoryInformation,
                    fileNamePattern: "*",
                    flags: Smb2QueryDirectoryFlags.RestartScans,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                FileFullDirectoryInformationEntry[] directoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(queryDirectoryBytes);
                await firstClient.CloseAsync(queryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                queryHandle = null;

                bool nonEmptyDirectoryDeleteRejected = false;
                deleteDirectoryHandle = await firstClient.OpenExistingPathAsync(firstTree, DirectoryName, DeleteAccess, cancellationToken).ConfigureAwait(false);

                try
                {
                    await firstClient.SetDeletePendingAsync(deleteDirectoryHandle, true, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.DirectoryNotEmpty)
                {
                    nonEmptyDirectoryDeleteRejected = true;
                }

                if (!nonEmptyDirectoryDeleteRejected)
                {
                    throw new InvalidOperationException("Expected Samba to reject delete-pending on the non-empty directory.");
                }

                await firstClient.CloseAsync(deleteDirectoryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                deleteDirectoryHandle = null;

                renameDirectoryHandle = await firstClient.OpenExistingPathAsync(firstTree, DirectoryName, GenericReadAccess | DeleteAccess, cancellationToken).ConfigureAwait(false);
                await firstClient.SetRenameAsync(renameDirectoryHandle, renamedDirectoryPath, cancellationToken: cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(renameDirectoryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                renameDirectoryHandle = null;

                bool originalDirectoryMissingRejected = false;

                try
                {
                    await firstClient.OpenExistingPathAsync(firstTree, DirectoryName, GenericReadAccess, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (
                    exception.Status == NtStatus.ObjectNameNotFound ||
                    exception.Status == NtStatus.ObjectPathNotFound)
                {
                    originalDirectoryMissingRejected = true;
                }

                if (!originalDirectoryMissingRejected)
                {
                    throw new InvalidOperationException("Expected the original directory path to stop resolving after directory rename.");
                }

                queryHandle = await firstClient.OpenExistingPathAsync(firstTree, renamedDirectoryPath, GenericReadAccess, cancellationToken).ConfigureAwait(false);
                byte[] renamedQueryDirectoryBytes = await firstClient.QueryDirectoryAsync(
                    queryHandle,
                    FileInformationClass.FullDirectoryInformation,
                    fileNamePattern: "*",
                    flags: Smb2QueryDirectoryFlags.RestartScans,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                FileFullDirectoryInformationEntry[] renamedDirectoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(renamedQueryDirectoryBytes);
                await firstClient.CloseAsync(queryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                queryHandle = null;

                deleteFileHandle = await firstClient.OpenExistingPathAsync(firstTree, renamedFileInRenamedDirectoryPath, DeleteAccess, cancellationToken).ConfigureAwait(false);
                await firstClient.SetDeletePendingAsync(deleteFileHandle, true, cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(deleteFileHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                deleteFileHandle = null;

                bool deletedFileReopenRejected = false;

                try
                {
                    await firstClient.OpenExistingPathAsync(firstTree, renamedFileInRenamedDirectoryPath, GenericReadAccess, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (
                    exception.Status == NtStatus.ObjectNameNotFound ||
                    exception.Status == NtStatus.ObjectPathNotFound)
                {
                    deletedFileReopenRejected = true;
                }

                if (!deletedFileReopenRejected)
                {
                    throw new InvalidOperationException("Expected the renamed file to stop resolving after delete.");
                }

                deleteNestedDirectoryHandle = await firstClient.OpenExistingPathAsync(firstTree, renamedNestedDirectoryPath, DeleteAccess, cancellationToken).ConfigureAwait(false);
                await firstClient.SetDeletePendingAsync(deleteNestedDirectoryHandle, true, cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(deleteNestedDirectoryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                deleteNestedDirectoryHandle = null;

                deleteDirectoryHandle = await firstClient.OpenExistingPathAsync(firstTree, renamedDirectoryPath, DeleteAccess, cancellationToken).ConfigureAwait(false);
                await firstClient.SetDeletePendingAsync(deleteDirectoryHandle, true, cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(deleteDirectoryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                deleteDirectoryHandle = null;

                bool deletedDirectoryReopenRejected = false;

                try
                {
                    await firstClient.OpenExistingPathAsync(firstTree, renamedDirectoryPath, GenericReadAccess, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (
                    exception.Status == NtStatus.ObjectNameNotFound ||
                    exception.Status == NtStatus.ObjectPathNotFound)
                {
                    deletedDirectoryReopenRejected = true;
                }

                if (!deletedDirectoryReopenRejected)
                {
                    throw new InvalidOperationException("Expected the renamed directory to stop resolving after cleanup.");
                }

                SambaInteropAdvancedSmb3Result advancedSmb3 = await RunAdvancedSmb3Async(options, credential, cancellationToken).ConfigureAwait(false);

                return new SambaInteropSmokeResult
                {
                    AdvancedSmb3 = advancedSmb3,
                    Server = options.Server,
                    Port = options.Port,
                    Share = options.Share,
                    Dialect = dialectLabel,
                    UserName = options.UserName,
                    BrowsedShareNames = ProjectRemoteShareNames(browsedShares),
                    BrowsedShareLocalPath = browsedShareInfo.LocalPath,
                    BrowsedShareCurrentUses = browsedShareInfo.CurrentUses ?? 0,
                    Directory = DirectoryName,
                    NestedDirectory = nestedDirectoryPath,
                    RenamedDirectory = renamedDirectoryPath,
                    RenamedNestedDirectory = renamedNestedDirectoryPath,
                    LargeFilePath = largeRelativeFilePath,
                    LargePayloadLength = largePayloadBytes.Length,
                    LargeWroteBytes = largeWrittenCount,
                    LargeEndOfFile = largeStandardInfo.EndOfFile,
                    WroteBytes = writtenCount,
                    RoundTripText = Encoding.UTF8.GetString(roundTripBytes),
                    TruncatedRoundTripText = Encoding.UTF8.GetString(truncatedBytes),
                    InitialEndOfFile = initialNetworkInfo.EndOfFile,
                    StandardInfoEndOfFile = standardInfo.EndOfFile,
                    MutatedLastWriteTime = mutatedNetworkInfo.LastWriteTime,
                    TruncatedEndOfFile = TruncatedLength,
                    FinalEndOfFile = truncatedStandardInfo.EndOfFile,
                    RenamedFilePath = renamedFileInRenamedDirectoryPath,
                    LockConflictRejected = lockConflictRejected,
                    NonEmptyDirectoryDeleteRejected = nonEmptyDirectoryDeleteRejected,
                    OriginalDirectoryMissingRejected = originalDirectoryMissingRejected,
                    DeletedFileReopenRejected = deletedFileReopenRejected,
                    DeletedDirectoryReopenRejected = deletedDirectoryReopenRejected,
                    DirectoryEntryNames = ProjectDirectoryEntryNames(directoryEntries),
                    RenamedDirectoryEntryNames = ProjectDirectoryEntryNames(renamedDirectoryEntries)
                };
            }
            finally
            {
                await CloseIfNeededAsync(firstClient, directoryHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, nestedDirectoryHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, firstFileHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, largeFileHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(secondClient, secondFileHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, renameHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, queryHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, deleteFileHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, deleteLargeFileHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, deleteDirectoryHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, renameDirectoryHandle).ConfigureAwait(false);
                await CloseIfNeededAsync(firstClient, deleteNestedDirectoryHandle).ConfigureAwait(false);
                await TreeDisconnectIfNeededAsync(firstClient, firstTree).ConfigureAwait(false);
                await TreeDisconnectIfNeededAsync(secondClient, secondTree).ConfigureAwait(false);
            }
        }

        private static string[] ProjectDirectoryEntryNames(FileFullDirectoryInformationEntry[] directoryEntries)
        {
            List<string> names = new List<string>(directoryEntries.Length);

            for (int index = 0; index < directoryEntries.Length; index++)
            {
                names.Add(directoryEntries[index].FileName);
            }

            return names.ToArray();
        }

        private static string[] ProjectRemoteShareNames(OpenCifsRemoteShareInfo[] shares)
        {
            List<string> names = new List<string>(shares.Length);

            for (int index = 0; index < shares.Length; index++)
            {
                names.Add(shares[index].Name);
            }

            return names.ToArray();
        }

        private static bool ContainsRemoteShare(OpenCifsRemoteShareInfo[] shares, string shareName)
        {
            for (int index = 0; index < shares.Length; index++)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(shares[index].Name, shareName))
                {
                    return true;
                }
            }

            return false;
        }

        private static byte[] CreateLargePayloadBytes(int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");
            }

            byte[] bytes = new byte[length];

            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = unchecked((byte)('A' + (index % 23)));
            }

            return bytes;
        }

        private static async Task<uint> WriteAllBytesAsync(
            OpenCifsClientConnection client,
            OpenCifsClientOpenHandle openHandle,
            byte[] data,
            CancellationToken cancellationToken)
        {
            uint chunkLength = GetReadWriteChunkLength(client, client.Session.NegotiatedMaxWriteSize);
            uint totalWritten = 0;

            for (int offset = 0; offset < data.Length; offset += checked((int)chunkLength))
            {
                int chunkSize = Math.Min(data.Length - offset, checked((int)chunkLength));
                byte[] chunk = new byte[chunkSize];
                Buffer.BlockCopy(data, offset, chunk, 0, chunkSize);
                totalWritten += await client.WriteAsync(openHandle, chunk, checked((ulong)offset), cancellationToken).ConfigureAwait(false);
            }

            return totalWritten;
        }

        private static async Task<OpenCifsClientOpenHandle> OpenDirectoryCreateCompatAsync(
            OpenCifsClientConnection client,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            CancellationToken cancellationToken)
        {
            try
            {
                return await client.OpenAsync(
                    treeHandle,
                    path,
                    GenericReadAccess,
                    SmbFileAttributes.Normal,
                    ShareAccess,
                    Smb2CreateDisposition.OpenIf,
                    Smb2CreateOptions.DirectoryFile,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.ObjectNameNotFound)
            {
                try
                {
                    return await client.OpenAsync(
                        treeHandle,
                        path,
                        GenericReadAccess,
                        SmbFileAttributes.Directory,
                        ShareAccess,
                        Smb2CreateDisposition.OpenIf,
                        Smb2CreateOptions.DirectoryFile,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException secondException) when (secondException.Status == NtStatus.ObjectNameNotFound)
                {
                    return await client.OpenAsync(
                        treeHandle,
                        path,
                        GenericReadAccess,
                        SmbFileAttributes.Directory,
                        ShareAccess,
                        Smb2CreateDisposition.OpenIf,
                        Smb2CreateOptions.None,
                        cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private static async Task<byte[]> ReadAllBytesAsync(
            OpenCifsClientConnection client,
            OpenCifsClientOpenHandle openHandle,
            uint length,
            CancellationToken cancellationToken)
        {
            uint chunkLength = GetReadWriteChunkLength(client, client.Session.NegotiatedMaxReadSize);
            byte[] result = new byte[length];
            int copied = 0;

            for (uint offset = 0; offset < length; offset += chunkLength)
            {
                uint currentLength = Math.Min(chunkLength, length - offset);
                byte[] chunk = await client.ReadAsync(openHandle, currentLength, offset, cancellationToken: cancellationToken).ConfigureAwait(false);
                Buffer.BlockCopy(chunk, 0, result, copied, chunk.Length);
                copied += chunk.Length;
            }

            return result;
        }

        private static uint GetReadWriteChunkLength(OpenCifsClientConnection client, uint negotiatedMaximum)
        {
            if (negotiatedMaximum == 0)
            {
                return Smb2CreditChargeHelper.BytesPerCredit;
            }

            uint creditBoundLength = checked((uint)Math.Max(1, client.Session.AvailableCredits)) * Smb2CreditChargeHelper.BytesPerCredit;
            return Math.Min(negotiatedMaximum, creditBoundLength);
        }

        private static async Task<SambaInteropAdvancedSmb3Result> RunAdvancedSmb3Async(
            SambaInteropOptions options,
            OpenCifsClientCredential credential,
            CancellationToken cancellationToken)
        {
            bool dialectIsSmb3 = options.Dialect >= SmbDialect.Smb30;

            if (!dialectIsSmb3)
            {
                return new SambaInteropAdvancedSmb3Result
                {
                    DialectIsSmb3 = false,
                    EncryptionExpected = false,
                    SecureNegotiateValidationExpected = false,
                    DurableHandleV2 = CreateSkippedDurableHandleResult("Durable-handle v2 verification only applies to SMB 3.x dialect lanes."),
                    Oplock = CreateSkippedOplockResult("Advanced SMB 3.x oplock reporting only applies to SMB 3.x dialect lanes."),
                    Lease = CreateSkippedLeaseResult("Advanced SMB 3.x lease reporting only applies to SMB 3.x dialect lanes.")
                };
            }

            return new SambaInteropAdvancedSmb3Result
            {
                DialectIsSmb3 = true,
                EncryptionExpected = true,
                SecureNegotiateValidationExpected = true,
                DurableHandleV2 = await RunDurableHandleV2ProbeAsync(options, credential, cancellationToken).ConfigureAwait(false),
                Oplock = await RunOplockProbeAsync(options, credential, cancellationToken).ConfigureAwait(false),
                Lease = await RunLeaseProbeAsync(options, credential, cancellationToken).ConfigureAwait(false)
            };
        }

        private static async Task<SambaInteropDurableHandleV2Result> RunDurableHandleV2ProbeAsync(
            SambaInteropOptions options,
            OpenCifsClientCredential credential,
            CancellationToken cancellationToken)
        {
            SambaInteropDurableHandleV2Result result = new SambaInteropDurableHandleV2Result
            {
                Attempted = true
            };
            string filePath = "advanced-smb3-durable-" + Guid.NewGuid().ToString("N").Substring(0, 12) + ".bin";
            byte[] payload = Encoding.UTF8.GetBytes("advanced smb3 durable payload");
            OpenCifsClientConnection? durableClient = null;
            OpenCifsClientConnection? competingClient = null;
            OpenCifsClientConnection? reconnectClient = null;
            OpenCifsClientOpenHandle? durableOpen = null;
            OpenCifsClientOpenHandle? competingOpen = null;
            OpenCifsClientOpenHandle? reconnectedOpen = null;
            bool competingDetachedLockSucceeded = false;

            try
            {
                durableClient = new OpenCifsClientConnection(CreateClientOptions(options));
                await durableClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                OpenCifsClientTreeHandle durableTree = await durableClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);
                durableOpen = await durableClient.OpenAsync(
                    durableTree,
                    filePath,
                    desiredAccess: GenericReadAccess | GenericWriteAccess | DeleteAccess,
                    fileAttributes: SmbFileAttributes.Normal,
                    shareAccess: ShareAccess,
                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                    createOptions: Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken: cancellationToken,
                    requestDurableHandle: true).ConfigureAwait(false);
                result.Granted = durableOpen.IsDurable;
                result.UsesDurableHandleV2 = durableOpen.UsesDurableHandleV2;
                result.CanReconnectDurably = durableOpen.CanReconnectDurably;
                result.IsPersistent = durableOpen.IsPersistent;
                result.DurableTimeoutMs = durableOpen.DurableTimeoutMs;
                result.GrantedOplockLevel = durableOpen.OplockLevel.ToString();

                if (!durableOpen.IsDurable || !durableOpen.UsesDurableHandleV2 || !durableOpen.CanReconnectDurably)
                {
                    result.Outcome = "skipped";
                    result.SkipReason = "The Samba peer did not grant a reconnectable SMB 3.x durable-handle v2 open on this lane.";
                    return result;
                }

                uint writtenCount = await durableClient.WriteAsync(durableOpen, payload, 0, cancellationToken).ConfigureAwait(false);
                if (writtenCount != payload.Length)
                {
                    throw new InvalidOperationException("The durable-handle probe did not receive a full initial write acknowledgment.");
                }

                await durableClient.FlushAsync(durableOpen, cancellationToken).ConfigureAwait(false);
                await durableClient.LockAsync(durableOpen, new[]
                {
                    new Smb2LockElement
                    {
                        Offset = 0,
                        Length = checked((ulong)payload.Length),
                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                    }
                }, cancellationToken).ConfigureAwait(false);

                await SimulateAbruptDisconnectAsync(durableClient).ConfigureAwait(false);

                competingClient = new OpenCifsClientConnection(CreateClientOptions(options));
                await competingClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                OpenCifsClientTreeHandle competingTree = await competingClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);
                try
                {
                    competingOpen = await competingClient.OpenExistingPathAsync(competingTree, filePath, GenericReadAccess, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.ObjectNameNotFound)
                {
                    result.Outcome = "unsupported";
                    result.Failure = exception.Message;
                    result.UnsupportedReason = "The Samba peer granted durable-handle v2 reconnect state but did not keep the detached file reopenable from a competing client before reconnect.";
                    return result;
                }
                catch (OpenCifsStatusException exception)
                {
                    throw new InvalidOperationException("The durable-handle v2 probe could not open the detached file from a competing client: " + exception.Message, exception);
                }

                StringBuilder unsupportedReasonBuilder = new StringBuilder();
                (bool detachedReadConflictPreserved, bool detachedReadUnexpectedSuccess, NtStatus? detachedReadActualStatus) = await ObserveExpectedStatusAsync(
                    async () => { _ = await competingClient.ReadAsync(competingOpen, checked((uint)payload.Length), 0, cancellationToken: cancellationToken).ConfigureAwait(false); },
                    NtStatus.FileLockConflict).ConfigureAwait(false);
                result.PreservedReadLockConflict = detachedReadConflictPreserved;

                if (!detachedReadConflictPreserved)
                {
                    unsupportedReasonBuilder.Append("The Samba peer granted durable-handle v2 reconnect state but did not preserve detached exclusive byte-range read conflicts before reconnect");
                    unsupportedReasonBuilder.Append(detachedReadUnexpectedSuccess
                        ? "."
                        : " (returned " + detachedReadActualStatus!.Value.ToString() + ").");
                }

                (bool detachedLockConflictPreserved, bool detachedLockUnexpectedSuccess, NtStatus? detachedLockActualStatus) = await ObserveExpectedStatusAsync(
                    () => competingClient.LockAsync(competingOpen, new[]
                    {
                        new Smb2LockElement
                        {
                            Offset = 0,
                            Length = checked((ulong)payload.Length),
                            Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                        }
                    }, cancellationToken),
                    NtStatus.LockNotGranted).ConfigureAwait(false);
                result.PreservedLockConflict = detachedLockConflictPreserved;

                if (!detachedLockConflictPreserved)
                {
                    if (unsupportedReasonBuilder.Length != 0)
                    {
                        unsupportedReasonBuilder.Append(' ');
                    }

                    unsupportedReasonBuilder.Append("The peer also did not preserve detached exclusive byte-range lock conflicts before reconnect");
                    unsupportedReasonBuilder.Append(detachedLockUnexpectedSuccess
                        ? "."
                        : " (returned " + detachedLockActualStatus!.Value.ToString() + ").");
                    competingDetachedLockSucceeded = detachedLockUnexpectedSuccess;
                }

                if (competingDetachedLockSucceeded)
                {
                    await competingClient.LockAsync(competingOpen, new[]
                    {
                        new Smb2LockElement
                        {
                            Offset = 0,
                            Length = checked((ulong)payload.Length),
                            Flags = Smb2LockFlags.Unlock
                        }
                    }, cancellationToken).ConfigureAwait(false);
                    competingDetachedLockSucceeded = false;
                }

                reconnectClient = new OpenCifsClientConnection(CreateClientOptions(options));
                await reconnectClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                OpenCifsClientTreeHandle reconnectTree = await reconnectClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);
                try
                {
                    reconnectedOpen = await reconnectClient.ReconnectDurableOpenAsync(reconnectTree, durableOpen, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsStatusException exception) when (exception.Status == NtStatus.ObjectNameNotFound)
                {
                    if (unsupportedReasonBuilder.Length != 0)
                    {
                        unsupportedReasonBuilder.Append(' ');
                    }

                    unsupportedReasonBuilder.Append("The peer also rejected the durable reconnect create after the detached competing-open phase with STATUS_OBJECT_NAME_NOT_FOUND.");
                    result.Outcome = "unsupported";
                    result.Failure = exception.Message;
                    result.UnsupportedReason = unsupportedReasonBuilder.ToString();
                    return result;
                }
                catch (OpenCifsStatusException exception)
                {
                    throw new InvalidOperationException("The durable-handle v2 probe could not reconnect the durable open after disconnect: " + exception.Message, exception);
                }
                result.Reconnected = true;

                byte[] reconnectedBytes = await reconnectClient.ReadAsync(reconnectedOpen, checked((uint)payload.Length), 0, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (!reconnectedBytes.AsSpan().SequenceEqual(payload))
                {
                    throw new InvalidOperationException("The durable-handle v2 probe read back an unexpected payload after reconnect.");
                }

                await reconnectClient.LockAsync(reconnectedOpen, new[]
                {
                    new Smb2LockElement
                    {
                        Offset = 0,
                        Length = checked((ulong)payload.Length),
                        Flags = Smb2LockFlags.Unlock
                    }
                }, cancellationToken).ConfigureAwait(false);

                byte[] competingBytes = await competingClient.ReadAsync(competingOpen, checked((uint)payload.Length), 0, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (!competingBytes.AsSpan().SequenceEqual(payload))
                {
                    throw new InvalidOperationException("The durable-handle v2 probe did not preserve readable payload bytes for the competing client after reconnect.");
                }

                await competingClient.LockAsync(competingOpen, new[]
                {
                    new Smb2LockElement
                    {
                        Offset = 0,
                        Length = checked((ulong)payload.Length),
                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                    }
                }, cancellationToken).ConfigureAwait(false);
                await competingClient.LockAsync(competingOpen, new[]
                {
                    new Smb2LockElement
                    {
                        Offset = 0,
                        Length = checked((ulong)payload.Length),
                        Flags = Smb2LockFlags.Unlock
                    }
                }, cancellationToken).ConfigureAwait(false);
                result.PostReconnectCompetingLockSucceeded = true;
                if (unsupportedReasonBuilder.Length != 0)
                {
                    result.Outcome = "unsupported";
                    result.UnsupportedReason = unsupportedReasonBuilder.ToString();
                    return result;
                }

                result.Outcome = "passed";
                return result;
            }
            catch (OpenCifsStatusException exception) when (IsCapabilitySkipStatus(exception.Status))
            {
                result.Outcome = "skipped";
                result.SkipReason = "The Samba peer rejected the durable-handle v2 probe as unsupported for this lane.";
                result.Failure = exception.Status.ToString();
                return result;
            }
            catch (Exception exception)
            {
                result.Outcome = "failed";
                result.Failure = exception.Message;
                return result;
            }
            finally
            {
                await TryCloseOpenAsync(reconnectClient, reconnectedOpen).ConfigureAwait(false);
                await TryCloseOpenAsync(competingClient, competingOpen).ConfigureAwait(false);
                await DisposeIfNeededAsync(reconnectClient).ConfigureAwait(false);
                await DisposeIfNeededAsync(competingClient).ConfigureAwait(false);
                await DisposeIfNeededAsync(durableClient).ConfigureAwait(false);
                await CleanupFileIfNeededAsync(options, credential, filePath, cancellationToken).ConfigureAwait(false);
            }
        }

        private static async Task<SambaInteropOplockBreakResult> RunOplockProbeAsync(
            SambaInteropOptions options,
            OpenCifsClientCredential credential,
            CancellationToken cancellationToken)
        {
            SambaInteropOplockBreakResult result = new SambaInteropOplockBreakResult
            {
                Attempted = true,
                RequestedLevel = Smb2OplockLevel.Exclusive.ToString()
            };
            string filePath = "advanced-smb3-oplock-" + Guid.NewGuid().ToString("N").Substring(0, 12) + ".bin";
            byte[] payload = Encoding.UTF8.GetBytes("advanced smb3 oplock payload");
            OpenCifsClientConnection? watcherClient = null;
            OpenCifsClientConnection? actorClient = null;
            OpenCifsClientOpenHandle? watcherOpen = null;
            OpenCifsClientOpenHandle? actorOpen = null;

            try
            {
                watcherClient = new OpenCifsClientConnection(CreateClientOptions(options));
                actorClient = new OpenCifsClientConnection(CreateClientOptions(options));
                await watcherClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                await actorClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);

                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);
                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);

                watcherOpen = await watcherClient.OpenAsync(
                    watcherTree,
                    filePath,
                    desiredAccess: GenericReadAccess | GenericWriteAccess | DeleteAccess,
                    fileAttributes: SmbFileAttributes.Normal,
                    shareAccess: ShareAccess,
                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                    createOptions: Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken: cancellationToken,
                    requestedOplockLevel: Smb2OplockLevel.Exclusive).ConfigureAwait(false);
                result.GrantedLevel = watcherOpen.OplockLevel.ToString();

                if (watcherOpen.OplockLevel != Smb2OplockLevel.Exclusive)
                {
                    result.Outcome = "skipped";
                    result.SkipReason = "The Samba peer did not grant an exclusive oplock on the SMB 3.x lane.";
                    return result;
                }

                uint writtenCount = await watcherClient.WriteAsync(watcherOpen, payload, 0, cancellationToken).ConfigureAwait(false);
                if (writtenCount != payload.Length)
                {
                    throw new InvalidOperationException("The oplock probe did not receive a full seed write acknowledgment.");
                }

                await watcherClient.FlushAsync(watcherOpen, cancellationToken).ConfigureAwait(false);

                using CancellationTokenSource breakTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                breakTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                Task<OpenCifsClientOplockBreakNotification> breakTask = watcherClient.WaitForOplockBreakAsync(breakTokenSource.Token);

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                actorOpen = await actorClient.OpenAsync(
                    actorTree,
                    filePath,
                    desiredAccess: GenericReadAccess,
                    fileAttributes: SmbFileAttributes.Normal,
                    shareAccess: ShareAccess,
                    createDisposition: Smb2CreateDisposition.Open,
                    createOptions: Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                OpenCifsClientOplockBreakNotification breakNotification = await breakTask.ConfigureAwait(false);
                result.BreakObserved = true;
                result.PreviousLevel = breakNotification.PreviousOplockLevel.ToString();
                result.NewLevel = breakNotification.NewOplockLevel.ToString();
                result.Acknowledged = breakNotification.WasAcknowledged;
                result.Outcome = "passed";
                return result;
            }
            catch (OpenCifsStatusException exception) when (IsCapabilitySkipStatus(exception.Status))
            {
                result.Outcome = "skipped";
                result.SkipReason = "The Samba peer rejected the oplock probe as unsupported for this SMB 3.x lane.";
                result.Failure = exception.Status.ToString();
                return result;
            }
            catch (OperationCanceledException exception)
            {
                result.Outcome = "failed";
                result.Failure = exception.Message;
                return result;
            }
            catch (Exception exception)
            {
                result.Outcome = "failed";
                result.Failure = exception.Message;
                return result;
            }
            finally
            {
                await TryCloseOpenAsync(actorClient, actorOpen).ConfigureAwait(false);
                await TryCloseOpenAsync(watcherClient, watcherOpen).ConfigureAwait(false);
                await DisposeIfNeededAsync(actorClient).ConfigureAwait(false);
                await DisposeIfNeededAsync(watcherClient).ConfigureAwait(false);
                await CleanupFileIfNeededAsync(options, credential, filePath, cancellationToken).ConfigureAwait(false);
            }
        }

        private static async Task<SambaInteropLeaseBreakResult> RunLeaseProbeAsync(
            SambaInteropOptions options,
            OpenCifsClientCredential credential,
            CancellationToken cancellationToken)
        {
            Smb2LeaseState requestedLeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
            SambaInteropLeaseBreakResult result = new SambaInteropLeaseBreakResult
            {
                Attempted = true,
                RequestedState = requestedLeaseState.ToString()
            };
            string filePath = "advanced-smb3-lease-" + Guid.NewGuid().ToString("N").Substring(0, 12) + ".bin";
            byte[] payload = Encoding.UTF8.GetBytes("advanced smb3 lease payload");
            OpenCifsClientConnection? watcherClient = null;
            OpenCifsClientConnection? actorClient = null;
            OpenCifsClientOpenHandle? watcherOpen = null;
            OpenCifsClientOpenHandle? actorOpen = null;

            try
            {
                watcherClient = new OpenCifsClientConnection(CreateClientOptions(options));
                actorClient = new OpenCifsClientConnection(CreateClientOptions(options));
                await watcherClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                await actorClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);

                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);
                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);

                watcherOpen = await watcherClient.OpenAsync(
                    watcherTree,
                    filePath,
                    desiredAccess: GenericReadAccess | GenericWriteAccess | DeleteAccess,
                    fileAttributes: SmbFileAttributes.Normal,
                    shareAccess: ShareAccess,
                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                    createOptions: Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken: cancellationToken,
                    requestedOplockLevel: Smb2OplockLevel.Lease,
                    requestedLeaseState: requestedLeaseState).ConfigureAwait(false);
                result.GrantedState = watcherOpen.LeaseState.ToString();

                if (watcherOpen.OplockLevel != Smb2OplockLevel.Lease || !HasRequiredLeaseState(watcherOpen.LeaseState, requestedLeaseState))
                {
                    result.Outcome = "skipped";
                    result.SkipReason = "The Samba peer did not grant the requested lease state on the SMB 3.x lane.";
                    return result;
                }

                uint writtenCount = await watcherClient.WriteAsync(watcherOpen, payload, 0, cancellationToken).ConfigureAwait(false);
                if (writtenCount != payload.Length)
                {
                    throw new InvalidOperationException("The lease probe did not receive a full seed write acknowledgment.");
                }

                await watcherClient.FlushAsync(watcherOpen, cancellationToken).ConfigureAwait(false);

                using CancellationTokenSource breakTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                breakTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                Task<OpenCifsClientLeaseBreakNotification> breakTask = watcherClient.WaitForLeaseBreakAsync(breakTokenSource.Token);

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                actorOpen = await actorClient.OpenAsync(
                    actorTree,
                    filePath,
                    desiredAccess: GenericReadAccess,
                    fileAttributes: SmbFileAttributes.Normal,
                    shareAccess: ShareAccess,
                    createDisposition: Smb2CreateDisposition.Open,
                    createOptions: Smb2CreateOptions.NonDirectoryFile,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                OpenCifsClientLeaseBreakNotification breakNotification = await breakTask.ConfigureAwait(false);
                result.BreakObserved = true;
                result.PreviousState = breakNotification.PreviousLeaseState.ToString();
                result.NewState = breakNotification.NewLeaseState.ToString();
                result.Acknowledged = breakNotification.WasAcknowledged;
                result.Outcome = "passed";
                return result;
            }
            catch (OpenCifsStatusException exception) when (IsCapabilitySkipStatus(exception.Status))
            {
                result.Outcome = "skipped";
                result.SkipReason = "The Samba peer rejected the lease probe as unsupported for this SMB 3.x lane.";
                result.Failure = exception.Status.ToString();
                return result;
            }
            catch (OperationCanceledException exception)
            {
                result.Outcome = "failed";
                result.Failure = exception.Message;
                return result;
            }
            catch (Exception exception)
            {
                result.Outcome = "failed";
                result.Failure = exception.Message;
                return result;
            }
            finally
            {
                await TryCloseOpenAsync(actorClient, actorOpen).ConfigureAwait(false);
                await TryCloseOpenAsync(watcherClient, watcherOpen).ConfigureAwait(false);
                await DisposeIfNeededAsync(actorClient).ConfigureAwait(false);
                await DisposeIfNeededAsync(watcherClient).ConfigureAwait(false);
                await CleanupFileIfNeededAsync(options, credential, filePath, cancellationToken).ConfigureAwait(false);
            }
        }

        private static async Task CleanupFileIfNeededAsync(
            SambaInteropOptions options,
            OpenCifsClientCredential credential,
            string path,
            CancellationToken cancellationToken)
        {
            OpenCifsClientConnection? cleanupClient = null;
            OpenCifsClientOpenHandle? cleanupOpen = null;

            try
            {
                cleanupClient = new OpenCifsClientConnection(CreateClientOptions(options));
                await cleanupClient.ConnectAndAuthenticateAsync(credential, cancellationToken).ConfigureAwait(false);
                OpenCifsClientTreeHandle cleanupTree = await cleanupClient.TreeConnectAsync(options.Share, cancellationToken).ConfigureAwait(false);
                cleanupOpen = await cleanupClient.OpenExistingPathAsync(cleanupTree, path, DeleteAccess, cancellationToken).ConfigureAwait(false);
                await cleanupClient.SetDeletePendingAsync(cleanupOpen, true, cancellationToken).ConfigureAwait(false);
            }
            catch (OpenCifsStatusException exception) when (
                exception.Status == NtStatus.NoSuchFile ||
                exception.Status == NtStatus.ObjectNameNotFound ||
                exception.Status == NtStatus.ObjectPathNotFound)
            {
            }
            catch
            {
            }
            finally
            {
                await TryCloseOpenAsync(cleanupClient, cleanupOpen).ConfigureAwait(false);
                await DisposeIfNeededAsync(cleanupClient).ConfigureAwait(false);
            }
        }

        private static async Task DisposeIfNeededAsync(OpenCifsClientConnection? connection)
        {
            if (connection == null)
            {
                return;
            }

            try
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private static async Task<(bool Matched, bool Succeeded, NtStatus? ActualStatus)> ObserveExpectedStatusAsync(Func<Task> operation, NtStatus expectedStatus)
        {
            try
            {
                await operation().ConfigureAwait(false);
                return (false, true, null);
            }
            catch (OpenCifsStatusException exception) when (exception.Status == expectedStatus)
            {
                return (true, false, exception.Status);
            }
            catch (OpenCifsStatusException exception)
            {
                return (false, false, exception.Status);
            }
        }

        private static async Task SimulateAbruptDisconnectAsync(OpenCifsClientConnection connection)
        {
            MethodInfo? method = typeof(OpenCifsClientConnection).GetMethod(
                "SimulateTransportDisconnectAsync",
                BindingFlags.Instance | BindingFlags.NonPublic);

            if (method == null)
            {
                throw new InvalidOperationException("The Samba interop runner could not locate the abrupt-disconnect helper.");
            }

            object? invocationResult = method.Invoke(connection, Array.Empty<object>());
            if (invocationResult is not Task disconnectTask)
            {
                throw new InvalidOperationException("The Samba interop runner abrupt-disconnect helper did not return a task.");
            }

            await disconnectTask.ConfigureAwait(false);
        }

        private static OpenCifsClientOptions CreateClientOptions(SambaInteropOptions options)
        {
            return new OpenCifsClientOptions
            {
                ServerName = options.Server,
                ServerPort = options.Port,
                RequireSigning = true,
                PreferEncryption = options.Dialect >= SmbDialect.Smb30,
                MinimumDialect = options.Dialect,
                MaximumDialect = options.Dialect,
                EnableSmb311Preview = options.Dialect == SmbDialect.Smb311
            };
        }

        private static bool HasRequiredLeaseState(Smb2LeaseState actual, Smb2LeaseState expected)
        {
            return (actual & expected) == expected;
        }

        private static bool IsCapabilitySkipStatus(NtStatus status)
        {
            return status == NtStatus.NotSupported ||
                status == NtStatus.InvalidParameter ||
                status == NtStatus.InvalidDeviceRequest;
        }

        private static SambaInteropDurableHandleV2Result CreateSkippedDurableHandleResult(string reason)
        {
            return new SambaInteropDurableHandleV2Result
            {
                Attempted = false,
                Outcome = "skipped",
                SkipReason = reason
            };
        }

        private static SambaInteropOplockBreakResult CreateSkippedOplockResult(string reason)
        {
            return new SambaInteropOplockBreakResult
            {
                Attempted = false,
                Outcome = "skipped",
                SkipReason = reason,
                RequestedLevel = Smb2OplockLevel.Exclusive.ToString()
            };
        }

        private static SambaInteropLeaseBreakResult CreateSkippedLeaseResult(string reason)
        {
            return new SambaInteropLeaseBreakResult
            {
                Attempted = false,
                Outcome = "skipped",
                SkipReason = reason,
                RequestedState = (Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching).ToString()
            };
        }

        private static async Task TryCloseOpenAsync(OpenCifsClientConnection? connection, OpenCifsClientOpenHandle? openHandle)
        {
            if (connection == null || openHandle == null || openHandle.IsClosed)
            {
                return;
            }

            try
            {
                await connection.CloseAsync(openHandle).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private static async Task CloseIfNeededAsync(OpenCifsClientConnection client, OpenCifsClientOpenHandle? openHandle)
        {
            if (openHandle == null || openHandle.IsClosed)
            {
                return;
            }

            try
            {
                await client.CloseAsync(openHandle).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private static async Task TreeDisconnectIfNeededAsync(OpenCifsClientConnection client, OpenCifsClientTreeHandle? treeHandle)
        {
            if (treeHandle == null || treeHandle.IsDisconnected)
            {
                return;
            }

            try
            {
                await client.TreeDisconnectAsync(treeHandle).ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }
}

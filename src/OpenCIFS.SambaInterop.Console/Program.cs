namespace OpenCIFS.SambaInterop.Console
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Protocol;
    using SmbFileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal static class Program
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

        public static async Task<int> Main(string[] args)
        {
            try
            {
                Options options = ParseArguments(args);
                SmokeResult result = await RunAsync(options).ConfigureAwait(false);
                JsonSerializerOptions serializerOptions = new JsonSerializerOptions
                {
                    WriteIndented = true
                };
                string json = JsonSerializer.Serialize(result, serializerOptions);

                if (!string.IsNullOrWhiteSpace(options.OutputPath))
                {
                    string? outputDirectory = Path.GetDirectoryName(options.OutputPath);

                    if (!string.IsNullOrWhiteSpace(outputDirectory))
                    {
                        Directory.CreateDirectory(outputDirectory);
                    }

                    await File.WriteAllTextAsync(options.OutputPath, json, Encoding.UTF8).ConfigureAwait(false);
                }

                System.Console.WriteLine(json);
                return 0;
            }
            catch (Exception exception)
            {
                System.Console.Error.WriteLine(exception);
                return 1;
            }
        }

        private static async Task<SmokeResult> RunAsync(Options options)
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
            string truncatedText = Encoding.UTF8.GetString(payloadBytes, 0, checked((int)TruncatedLength));
            string dialectLabel = GetDialectLabel(options.Dialect);

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

                directoryHandle = await firstClient.OpenAsync(
                    firstTree,
                    DirectoryName,
                    GenericReadAccess,
                    SmbFileAttributes.Directory,
                    ShareAccess,
                    Smb2CreateDisposition.OpenIf,
                    Smb2CreateOptions.DirectoryFile,
                    cancellationToken).ConfigureAwait(false);
                await firstClient.CloseAsync(directoryHandle, cancellationToken: cancellationToken).ConfigureAwait(false);
                directoryHandle = null;

                nestedDirectoryHandle = await firstClient.OpenAsync(
                    firstTree,
                    nestedDirectoryPath,
                    GenericReadAccess,
                    SmbFileAttributes.Directory,
                    ShareAccess,
                    Smb2CreateDisposition.OpenIf,
                    Smb2CreateOptions.DirectoryFile,
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

                return new SmokeResult
                {
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

        private static SmbDialect ParseDialect(string value)
        {
            return value switch
            {
                "Smb2002" => SmbDialect.Smb2002,
                "Smb21" => SmbDialect.Smb21,
                "Smb30" => SmbDialect.Smb30,
                "Smb302" => SmbDialect.Smb302,
                "Smb311" => SmbDialect.Smb311,
                _ => throw new ArgumentException("Unsupported dialect '" + value + "'.")
            };
        }

        private static string GetDialectLabel(SmbDialect dialect)
        {
            return dialect switch
            {
                SmbDialect.Smb2002 => "SMB 2.0.2",
                SmbDialect.Smb21 => "SMB 2.1",
                SmbDialect.Smb30 => "SMB 3.0",
                SmbDialect.Smb302 => "SMB 3.0.2",
                SmbDialect.Smb311 => "SMB 3.1.1",
                _ => dialect.ToString()
            };
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

        private static Options ParseArguments(string[] args)
        {
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            for (int index = 0; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException("Arguments must be provided as --name value pairs.");
                }

                values[args[index][2..]] = args[index + 1];
            }

            return new Options
            {
                Server = GetRequired(values, "server"),
                Port = Int32.Parse(GetRequired(values, "port"), System.Globalization.CultureInfo.InvariantCulture),
                Share = GetRequired(values, "share"),
                UserName = GetRequired(values, "username"),
                Password = GetRequired(values, "password"),
                Domain = GetRequired(values, "domain"),
                Dialect = values.TryGetValue("dialect", out string? dialectValue) ? ParseDialect(dialectValue) : SmbDialect.Smb21,
                LargePayloadLength = values.TryGetValue("large-payload-length", out string? largePayloadLengthValue)
                    ? Int32.Parse(largePayloadLengthValue, System.Globalization.CultureInfo.InvariantCulture)
                    : 200000,
                OutputPath = values.TryGetValue("output", out string? outputPath) ? outputPath : String.Empty
            };
        }

        private static string GetRequired(IReadOnlyDictionary<string, string> values, string name)
        {
            if (!values.TryGetValue(name, out string? value) || String.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("Missing required argument --" + name + ".");
            }

            return value;
        }

        private sealed class Options
        {
            public SmbDialect Dialect { get; init; }

            public string Domain { get; init; } = String.Empty;

            public int LargePayloadLength { get; init; } = 200000;

            public string OutputPath { get; init; } = String.Empty;

            public string Password { get; init; } = String.Empty;

            public int Port { get; init; }

            public string Server { get; init; } = String.Empty;

            public string Share { get; init; } = String.Empty;

            public string UserName { get; init; } = String.Empty;
        }

        private sealed class SmokeResult
        {
            public string[] BrowsedShareNames { get; init; } = Array.Empty<string>();

            public string BrowsedShareLocalPath { get; init; } = String.Empty;

            public uint BrowsedShareCurrentUses { get; init; }

            public string Dialect { get; init; } = String.Empty;

            public string[] DirectoryEntryNames { get; init; } = Array.Empty<string>();

            public bool DeletedDirectoryReopenRejected { get; init; }

            public bool DeletedFileReopenRejected { get; init; }

            public string Directory { get; init; } = String.Empty;

            public ulong FinalEndOfFile { get; init; }

            public ulong InitialEndOfFile { get; init; }

            public ulong LargeEndOfFile { get; init; }

            public string LargeFilePath { get; init; } = String.Empty;

            public int LargePayloadLength { get; init; }

            public uint LargeWroteBytes { get; init; }

            public bool LockConflictRejected { get; init; }

            public ulong MutatedLastWriteTime { get; init; }

            public string NestedDirectory { get; init; } = String.Empty;

            public bool NonEmptyDirectoryDeleteRejected { get; init; }

            public bool OriginalDirectoryMissingRejected { get; init; }

            public string RenamedDirectory { get; init; } = String.Empty;

            public string RenamedFilePath { get; init; } = String.Empty;

            public string[] RenamedDirectoryEntryNames { get; init; } = Array.Empty<string>();

            public string RenamedNestedDirectory { get; init; } = String.Empty;

            public string RoundTripText { get; init; } = String.Empty;

            public string Server { get; init; } = String.Empty;

            public string Share { get; init; } = String.Empty;

            public ulong StandardInfoEndOfFile { get; init; }

            public ulong TruncatedEndOfFile { get; init; }

            public string TruncatedRoundTripText { get; init; } = String.Empty;

            public string UserName { get; init; } = String.Empty;

            public int Port { get; init; }

            public uint WroteBytes { get; init; }
        }
    }
}

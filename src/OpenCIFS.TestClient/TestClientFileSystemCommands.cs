namespace OpenCIFS.TestClient
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;

    internal sealed class TestClientFileSystemCommands
    {
        public TestClientFileSystemCommands(TestClientState state)
        {
            _State = state ?? throw new ArgumentNullException(nameof(state), "State cannot be null.");
        }

        public async Task ChangeDirectoryAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            if (parts.Length == 1)
            {
                Console.WriteLine(GetDisplayRemotePath(_State.CurrentRemotePath));
                return;
            }

            string targetPath = NormalizeRemotePath(parts[1]);
            OpenCifsClientResult<OpenCifsClientFileMetadata> result = await _State.ShareSession!.Metadata.TryGetAttributesAsync(targetPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            if (!result.Value!.IsDirectory)
            {
                Console.WriteLine("[ERROR] The target path is not a directory.");
                return;
            }

            _State.CurrentRemotePath = targetPath;
            Console.WriteLine("[OK] Current directory = " + GetDisplayRemotePath(_State.CurrentRemotePath));
        }

        public async Task ListDirectoryAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string path = _State.CurrentRemotePath;
            string? pattern = null;

            if (parts.Length >= 2)
            {
                if (parts.Length == 2 && ContainsWildcard(parts[1]))
                {
                    pattern = parts[1];
                }
                else
                {
                    path = NormalizeRemotePath(parts[1]);
                    if (parts.Length >= 3)
                    {
                        pattern = parts[2];
                    }
                }
            }

            OpenCifsClientResult<OpenCifsClientDirectoryEntry[]> result = await _State.ShareSession!.Directories.TryEnumerateAsync(path, pattern, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            OpenCifsClientDirectoryEntry[] entries = result.Value!;
            Console.WriteLine("[OK] Directory listing for " + GetDisplayRemotePath(path) + ":");

            if (entries.Length == 0)
            {
                Console.WriteLine("  (empty)");
                return;
            }

            foreach (OpenCifsClientDirectoryEntry entry in entries.OrderBy(entry => entry.FileName, StringComparer.OrdinalIgnoreCase))
            {
                bool isDirectory = (entry.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0;
                string itemType = isDirectory ? "<DIR>" : "FILE ";
                Console.WriteLine(
                    "  " +
                    itemType.PadRight(5) +
                    " " +
                    entry.EndOfFile.ToString().PadLeft(10) +
                    "  " +
                    entry.FileName +
                    "  [" +
                    entry.FileAttributes +
                    "]");
            }
        }

        public async Task PrintTreeAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string path = parts.Length >= 2 ? NormalizeRemotePath(parts[1]) : _State.CurrentRemotePath;
            Console.WriteLine("[OK] Tree for " + GetDisplayRemotePath(path) + ":");
            await PrintTreeNodeAsync(path, depth: 0, cancellationToken).ConfigureAwait(false);
        }

        public async Task PrintMetadataAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string path = parts.Length >= 2 ? NormalizeRemotePath(parts[1]) : _State.CurrentRemotePath;
            OpenCifsClientResult<OpenCifsClientFileMetadata> result = await _State.ShareSession!.Metadata.TryGetAttributesAsync(path, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            OpenCifsClientFileMetadata metadata = result.Value!;
            Console.WriteLine("[OK] Metadata for " + GetDisplayRemotePath(path) + ":");
            Console.WriteLine("  Path           : " + metadata.Path);
            Console.WriteLine("  Is Directory   : " + metadata.IsDirectory);
            Console.WriteLine("  Delete Pending : " + metadata.IsDeletePending);
            Console.WriteLine("  EOF            : " + metadata.EndOfFile);
            Console.WriteLine("  Allocation     : " + metadata.AllocationSize);
            Console.WriteLine("  Attributes     : " + metadata.FileAttributes);
            Console.WriteLine("  Created (UTC)  : " + TestClientConsoleHelpers.FormatNullableDateTime(metadata.CreationTimeUtc));
            Console.WriteLine("  Accessed (UTC) : " + TestClientConsoleHelpers.FormatNullableDateTime(metadata.LastAccessTimeUtc));
            Console.WriteLine("  Written (UTC)  : " + TestClientConsoleHelpers.FormatNullableDateTime(metadata.LastWriteTimeUtc));
            Console.WriteLine("  Changed (UTC)  : " + TestClientConsoleHelpers.FormatNullableDateTime(metadata.ChangeTimeUtc));
        }

        public async Task CreateDirectoryAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult result = await _State.ShareSession!.Directories.TryCreateAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Created directory " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        public async Task DeleteDirectoryAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult result = await _State.ShareSession!.Directories.TryDeleteAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Deleted directory " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        public async Task ReadTextFileAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult<byte[]> result = await _State.ShareSession!.Files.TryReadAllBytesAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            string text = Encoding.UTF8.GetString(result.Value!);
            Console.WriteLine("[OK] File contents for " + GetDisplayRemotePath(normalizedPath) + ":");
            Console.WriteLine(text);
        }

        public async Task WriteTextFileAsync(string path, string text, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            byte[] data = Encoding.UTF8.GetBytes(text);
            OpenCifsClientResult result = await _State.ShareSession!.Files.TryWriteAllBytesAsync(normalizedPath, data, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Wrote " + data.Length + " bytes to " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        public async Task UploadFileAsync(string localPath, string remotePath, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string fullLocalPath = Path.GetFullPath(localPath);
            if (!File.Exists(fullLocalPath))
            {
                Console.WriteLine("[ERROR] Local file was not found: " + fullLocalPath);
                return;
            }

            byte[] data = await File.ReadAllBytesAsync(fullLocalPath, cancellationToken).ConfigureAwait(false);
            string normalizedRemotePath = NormalizeRemotePath(remotePath);
            OpenCifsClientResult result = await _State.ShareSession!.Files.TryWriteAllBytesAsync(normalizedRemotePath, data, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Uploaded " + data.Length + " bytes to " + GetDisplayRemotePath(normalizedRemotePath) + ".");
        }

        public async Task DownloadFileAsync(string remotePath, string localPath, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedRemotePath = NormalizeRemotePath(remotePath);
            OpenCifsClientResult<byte[]> result = await _State.ShareSession!.Files.TryReadAllBytesAsync(normalizedRemotePath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            string fullLocalPath = Path.GetFullPath(localPath);
            string? localDirectory = Path.GetDirectoryName(fullLocalPath);
            if (!string.IsNullOrWhiteSpace(localDirectory))
            {
                Directory.CreateDirectory(localDirectory);
            }

            await File.WriteAllBytesAsync(fullLocalPath, result.Value!, cancellationToken).ConfigureAwait(false);
            Console.WriteLine("[OK] Downloaded " + result.Value!.Length + " bytes to " + fullLocalPath + ".");
        }

        public async Task DeleteFileAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult result = await _State.ShareSession!.Files.TryDeleteAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Deleted file " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        public async Task RenamePathAsync(string sourcePath, string destinationPath, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedSourcePath = NormalizeRemotePath(sourcePath);
            string normalizedDestinationPath = NormalizeRemotePath(destinationPath);
            OpenCifsClientResult<OpenCifsClientFileMetadata> metadataResult = await _State.ShareSession!.Metadata.TryGetAttributesAsync(normalizedSourcePath, cancellationToken).ConfigureAwait(false);

            if (!metadataResult.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(metadataResult.Exception!));
                return;
            }

            OpenCifsClientResult renameResult = metadataResult.Value!.IsDirectory
                ? await _State.ShareSession.Directories.TryRenameAsync(normalizedSourcePath, normalizedDestinationPath, cancellationToken: cancellationToken).ConfigureAwait(false)
                : await _State.ShareSession.Files.TryRenameAsync(normalizedSourcePath, normalizedDestinationPath, cancellationToken: cancellationToken).ConfigureAwait(false);

            if (!renameResult.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(renameResult.Exception!));
                return;
            }

            Console.WriteLine(
                "[OK] Renamed " +
                GetDisplayRemotePath(normalizedSourcePath) +
                " -> " +
                GetDisplayRemotePath(normalizedDestinationPath) +
                ".");
        }

        private bool EnsureShareIsOpen()
        {
            if (_State.ShareSession != null)
            {
                return true;
            }

            Console.WriteLine("[ERROR] Open a share first.");
            return false;
        }

        private string NormalizeRemotePath(string path)
        {
            return TestClientPathUtilities.NormalizeRemotePath(_State.CurrentRemotePath, path);
        }

        private static string CombineRemotePath(string basePath, string childName)
        {
            return TestClientPathUtilities.CombineRemotePath(basePath, childName);
        }

        private static string GetDisplayRemotePath(string path)
        {
            return TestClientPathUtilities.GetDisplayRemotePath(path);
        }

        private static bool ContainsWildcard(string value)
        {
            return TestClientPathUtilities.ContainsWildcard(value);
        }

        private static string FormatClientFailure(OpenCifsClientException exception)
        {
            return TestClientConsoleHelpers.FormatClientFailure(exception);
        }

        private async Task PrintTreeNodeAsync(string path, int depth, CancellationToken cancellationToken)
        {
            OpenCifsClientResult<OpenCifsClientDirectoryEntry[]> result = await _State.ShareSession!.Directories.TryEnumerateAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(new string(' ', depth * 2) + FormatClientFailure(result.Exception!));
                return;
            }

            OpenCifsClientDirectoryEntry[] entries = result.Value!;
            foreach (OpenCifsClientDirectoryEntry entry in entries.OrderBy(entry => entry.FileName, StringComparer.OrdinalIgnoreCase))
            {
                if (entry.FileName == "." || entry.FileName == "..")
                {
                    continue;
                }

                bool isDirectory = (entry.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0;
                Console.WriteLine(new string(' ', depth * 2) + (isDirectory ? "[D] " : "[F] ") + entry.FileName);

                if (isDirectory)
                {
                    string childPath = CombineRemotePath(path, entry.FileName);
                    await PrintTreeNodeAsync(childPath, depth + 1, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private readonly TestClientState _State;
    }
}

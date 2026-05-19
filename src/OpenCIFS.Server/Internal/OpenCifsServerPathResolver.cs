namespace OpenCIFS.Server
{
    using System;
    using System.IO;
    using OpenCIFS.Protocol;

    internal static class OpenCifsServerPathResolver
    {
        public static string ResolveShareRootPath(string rootPath)
        {
            try
            {
                return Path.GetFullPath(rootPath);
            }
            catch (Exception exception)
            {
                throw new ArgumentException("RootPath could not be resolved to a filesystem location.", nameof(rootPath), exception);
            }
        }

        public static string NormalizeRenamePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ProtocolEncodingException("The FILE_RENAME_INFORMATION_TYPE_2 path cannot be null or whitespace.");
            }

            string normalizedPath = path.Trim().Replace('/', '\\').Trim('\\');

            if (normalizedPath.Length == 0)
            {
                throw new ProtocolEncodingException("The FILE_RENAME_INFORMATION_TYPE_2 path must resolve to a non-empty relative path.");
            }

            return normalizedPath;
        }

        public static bool TryResolveShareFilePath(string shareRootPath, string relativePath, out string? fullPath, out NtStatus status, bool allowShareRoot = false)
        {
            fullPath = null;

            if (string.IsNullOrWhiteSpace(shareRootPath))
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            string shareRoot;

            try
            {
                shareRoot = Path.GetFullPath(shareRootPath);
            }
            catch (Exception)
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            string normalizedRelativePath = relativePath.Trim().Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar).Trim(Path.DirectorySeparatorChar);

            if (normalizedRelativePath.Length == 0)
            {
                if (!allowShareRoot)
                {
                    status = NtStatus.InvalidParameter;
                    return false;
                }

                fullPath = shareRoot;
                status = NtStatus.Success;
                return true;
            }

            string candidatePath;

            try
            {
                candidatePath = Path.GetFullPath(Path.Combine(shareRoot, normalizedRelativePath));
            }
            catch (Exception)
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            string rootedPrefix = shareRoot.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? shareRoot
                : shareRoot + Path.DirectorySeparatorChar;

            if (!candidatePath.StartsWith(rootedPrefix, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(candidatePath, shareRoot, StringComparison.OrdinalIgnoreCase))
            {
                status = NtStatus.ObjectPathNotFound;
                return false;
            }

            fullPath = candidatePath;
            status = NtStatus.Success;
            return true;
        }

        public static bool IsShareRootOpenRequest(Smb2CreateRequest request)
        {
            return request.Name.Length == 0 &&
                (request.CreateOptions & Smb2CreateOptions.NonDirectoryFile) == 0 &&
                (request.CreateDisposition == Smb2CreateDisposition.Open || request.CreateDisposition == Smb2CreateDisposition.OpenIf);
        }

        public static bool IsPathDescendantOf(string fullPath, string directoryPath)
        {
            if (string.IsNullOrEmpty(fullPath) || string.IsNullOrEmpty(directoryPath))
            {
                return false;
            }

            string directoryPrefix = directoryPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? directoryPath
                : directoryPath + Path.DirectorySeparatorChar;
            return fullPath.StartsWith(directoryPrefix, StringComparison.OrdinalIgnoreCase);
        }

        public static bool TryCreateBackingDirectory(OpenCifsServerShareBackend backend, string fullPath, out NtStatus status)
        {
            try
            {
                backend.CreateDirectory(fullPath);
                status = NtStatus.Success;
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                status = NtStatus.AccessDenied;
                return false;
            }
            catch (IOException)
            {
                status = NtStatus.AccessDenied;
                return false;
            }
        }
    }
}

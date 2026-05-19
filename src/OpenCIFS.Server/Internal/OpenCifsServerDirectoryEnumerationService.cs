namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Enumeration;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerDirectoryEnumerationService
    {
        private readonly Func<OpenCifsServerShareBackend, string, FileMetadata> _BuildFileMetadata;

        public OpenCifsServerDirectoryEnumerationService(Func<OpenCifsServerShareBackend, string, FileMetadata> buildFileMetadata)
        {
            _BuildFileMetadata = buildFileMetadata ?? throw new ArgumentNullException(nameof(buildFileMetadata), "BuildFileMetadata cannot be null.");
        }

        public List<FileSystemInfo> EnumerateMatchingEntries(OpenCifsServerShareBackend backend, string fullPath, string pattern)
        {
            List<FileSystemInfo> matches = new List<FileSystemInfo>();
            string normalizedPattern = NormalizeSearchPattern(pattern);

            IReadOnlyList<FileSystemInfo> children = backend.EnumerateFileSystemInfos(fullPath);

            for (int index = 0; index < children.Count; index++)
            {
                FileSystemInfo child = children[index];

                if (FileSystemName.MatchesSimpleExpression(normalizedPattern, child.Name, ignoreCase: true))
                {
                    matches.Add(child);
                }
            }

            matches.Sort((left, right) => StringComparer.OrdinalIgnoreCase.Compare(left.Name, right.Name));
            return matches;
        }

        public NtStatus TryBuildEnumerationBuffer(
            OpenCifsServerShareBackend backend,
            FileInformationClass informationClass,
            IReadOnlyList<FileSystemInfo> matchingEntries,
            int startIndex,
            uint outputBufferLength,
            bool returnSingleEntry,
            out byte[] outputBuffer,
            out int returnedEntryCount)
        {
            outputBuffer = Array.Empty<byte>();
            returnedEntryCount = 0;

            switch (informationClass)
            {
                case FileInformationClass.DirectoryInformation:
                {
                    List<FileDirectoryInformationEntry> entries = new List<FileDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.FullDirectoryInformation:
                {
                    List<FileFullDirectoryInformationEntry> entries = new List<FileFullDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateFullDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileFullDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.BothDirectoryInformation:
                {
                    List<FileBothDirectoryInformationEntry> entries = new List<FileBothDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateBothDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileBothDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.IdBothDirectoryInformation:
                {
                    List<FileIdBothDirectoryInformationEntry> entries = new List<FileIdBothDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateIdBothDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileIdBothDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                case FileInformationClass.IdFullDirectoryInformation:
                {
                    List<FileIdFullDirectoryInformationEntry> entries = new List<FileIdFullDirectoryInformationEntry>();

                    for (int index = startIndex; index < matchingEntries.Count; index++)
                    {
                        entries.Add(CreateIdFullDirectoryInformationEntry(backend, matchingEntries[index]));
                        byte[] candidateBuffer = FileIdFullDirectoryInformationEntry.EncodeEntries(entries);

                        if (candidateBuffer.Length > outputBufferLength)
                        {
                            if (entries.Count == 1)
                            {
                                return NtStatus.InfoLengthMismatch;
                            }

                            entries.RemoveAt(entries.Count - 1);
                            break;
                        }

                        outputBuffer = candidateBuffer;
                        returnedEntryCount = entries.Count;

                        if (returnSingleEntry)
                        {
                            break;
                        }
                    }

                    return returnedEntryCount == 0 ? NtStatus.InfoLengthMismatch : NtStatus.Success;
                }
                default:
                    return NtStatus.InvalidInfoClass;
            }
        }

        private static string NormalizeSearchPattern(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return "*";
            }

            if (pattern.IndexOfAny(new char[] { '\\', '/' }) >= 0)
            {
                throw new ProtocolValidationException("The query-directory search pattern must not contain path separators.", nameof(pattern));
            }

            return pattern;
        }

        private FileDirectoryInformationEntry CreateDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = _BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                FileName = fileSystemInfo.Name
            };
        }

        private FileFullDirectoryInformationEntry CreateFullDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = _BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileFullDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                FileName = fileSystemInfo.Name
            };
        }

        private FileBothDirectoryInformationEntry CreateBothDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = _BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileBothDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                ShortName = string.Empty,
                FileName = fileSystemInfo.Name
            };
        }

        private FileIdBothDirectoryInformationEntry CreateIdBothDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = _BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileIdBothDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                ShortName = string.Empty,
                FileId = 0,
                FileName = fileSystemInfo.Name
            };
        }

        private FileIdFullDirectoryInformationEntry CreateIdFullDirectoryInformationEntry(OpenCifsServerShareBackend backend, FileSystemInfo fileSystemInfo)
        {
            FileMetadata metadata = _BuildFileMetadata(backend, fileSystemInfo.FullName);
            return new FileIdFullDirectoryInformationEntry
            {
                FileIndex = 0,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                EndOfFile = metadata.EndOfFile,
                AllocationSize = metadata.AllocationSize,
                FileAttributes = metadata.FileAttributes,
                EaSize = 0,
                Reserved = 0,
                FileId = 0,
                FileName = fileSystemInfo.Name
            };
        }
    }
}

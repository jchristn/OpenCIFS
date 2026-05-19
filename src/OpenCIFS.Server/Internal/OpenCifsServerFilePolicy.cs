namespace OpenCIFS.Server
{
    using System;
    using System.IO;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using SystemFileAttributes = System.IO.FileAttributes;

    internal static class OpenCifsServerFilePolicy
    {
        private const uint GenericRead = 0x80000000U;
        private const uint GenericWrite = 0x40000000U;
        private const uint DeleteAccess = 0x00010000U;
        private const uint FileReadData = 0x00000001U;
        private const uint FileWriteData = 0x00000002U;
        private const uint FileAppendData = 0x00000004U;
        private const uint FileReadAttributes = 0x00000080U;
        private const uint FileWriteAttributes = 0x00000100U;
        private const ulong StickyDisableFileTimeDirective = UInt64.MaxValue;
        private const ulong StickyEnableFileTimeDirective = UInt64.MaxValue - 1;

        public static SystemFileAttributes NormalizeCreateFileAttributes(ProtocolFileAttributes attributes)
        {
            const ProtocolFileAttributes directlySettableAttributes =
                ProtocolFileAttributes.ReadOnly |
                ProtocolFileAttributes.Hidden |
                ProtocolFileAttributes.System |
                ProtocolFileAttributes.Archive |
                ProtocolFileAttributes.Temporary |
                ProtocolFileAttributes.Offline |
                ProtocolFileAttributes.NotContentIndexed;

            ProtocolFileAttributes normalizedAttributes = attributes & directlySettableAttributes;
            normalizedAttributes |= ProtocolFileAttributes.Archive;
            return MapFileAttributes(normalizedAttributes);
        }

        public static ProtocolFileAttributes MapFileAttributes(SystemFileAttributes attributes)
        {
            ProtocolFileAttributes mappedAttributes = ProtocolFileAttributes.None;

            if ((attributes & SystemFileAttributes.ReadOnly) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.ReadOnly;
            }

            if ((attributes & SystemFileAttributes.Hidden) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Hidden;
            }

            if ((attributes & SystemFileAttributes.System) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.System;
            }

            if ((attributes & SystemFileAttributes.Directory) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Directory;
            }

            if ((attributes & SystemFileAttributes.Archive) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Archive;
            }

            if ((attributes & SystemFileAttributes.Temporary) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Temporary;
            }

            if ((attributes & SystemFileAttributes.SparseFile) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.SparseFile;
            }

            if ((attributes & SystemFileAttributes.ReparsePoint) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.ReparsePoint;
            }

            if ((attributes & SystemFileAttributes.Compressed) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Compressed;
            }

            if ((attributes & SystemFileAttributes.Offline) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Offline;
            }

            if ((attributes & SystemFileAttributes.NotContentIndexed) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.NotContentIndexed;
            }

            if ((attributes & SystemFileAttributes.Encrypted) != 0)
            {
                mappedAttributes |= ProtocolFileAttributes.Encrypted;
            }

            return mappedAttributes == ProtocolFileAttributes.None ? ProtocolFileAttributes.Normal : mappedAttributes;
        }

        public static SystemFileAttributes MapFileAttributes(ProtocolFileAttributes attributes)
        {
            if (attributes == ProtocolFileAttributes.None || attributes == ProtocolFileAttributes.Normal)
            {
                return SystemFileAttributes.Normal;
            }

            SystemFileAttributes mappedAttributes = 0;

            if ((attributes & ProtocolFileAttributes.ReadOnly) != 0)
            {
                mappedAttributes |= SystemFileAttributes.ReadOnly;
            }

            if ((attributes & ProtocolFileAttributes.Hidden) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Hidden;
            }

            if ((attributes & ProtocolFileAttributes.System) != 0)
            {
                mappedAttributes |= SystemFileAttributes.System;
            }

            if ((attributes & ProtocolFileAttributes.Archive) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Archive;
            }

            if ((attributes & ProtocolFileAttributes.Temporary) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Temporary;
            }

            if ((attributes & ProtocolFileAttributes.SparseFile) != 0)
            {
                mappedAttributes |= SystemFileAttributes.SparseFile;
            }

            if ((attributes & ProtocolFileAttributes.ReparsePoint) != 0)
            {
                mappedAttributes |= SystemFileAttributes.ReparsePoint;
            }

            if ((attributes & ProtocolFileAttributes.Compressed) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Compressed;
            }

            if ((attributes & ProtocolFileAttributes.Offline) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Offline;
            }

            if ((attributes & ProtocolFileAttributes.NotContentIndexed) != 0)
            {
                mappedAttributes |= SystemFileAttributes.NotContentIndexed;
            }

            if ((attributes & ProtocolFileAttributes.Encrypted) != 0)
            {
                mappedAttributes |= SystemFileAttributes.Encrypted;
            }

            return mappedAttributes == 0 ? SystemFileAttributes.Normal : mappedAttributes;
        }

        public static FileAccess DetermineFileAccess(uint desiredAccess)
        {
            bool canRead = CanReadData(desiredAccess);
            bool canWrite = CanWriteData(desiredAccess);

            if (canRead && canWrite)
            {
                return FileAccess.ReadWrite;
            }

            if (canWrite)
            {
                return FileAccess.Write;
            }

            return FileAccess.Read;
        }

        public static bool CanReadData(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadData)) != 0;
        }

        public static bool CanRead(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadData | FileReadAttributes)) != 0;
        }

        public static bool CanReadAttributes(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadAttributes)) != 0;
        }

        public static bool CanListDirectory(uint desiredAccess)
        {
            return (desiredAccess & (GenericRead | FileReadData)) != 0;
        }

        public static bool CanWrite(uint desiredAccess)
        {
            return (desiredAccess & (GenericWrite | FileWriteData | FileAppendData | FileWriteAttributes)) != 0;
        }

        public static bool CanWriteAttributes(uint desiredAccess)
        {
            return (desiredAccess & (GenericWrite | FileWriteAttributes)) != 0;
        }

        public static bool CanWriteData(uint desiredAccess)
        {
            return (desiredAccess & (GenericWrite | FileWriteData | FileAppendData)) != 0;
        }

        public static bool CanDelete(uint desiredAccess)
        {
            return (desiredAccess & DeleteAccess) != 0;
        }

        public static bool ShouldApplyExplicitFileTime(ulong value)
        {
            return value != 0 && !IsStickyFileTimeDirective(value);
        }

        public static bool IsEnableStickyFileTimeDirective(ulong value)
        {
            return value == StickyEnableFileTimeDirective;
        }

        public static bool TryConvertFileTimeToUtcDateTime(ulong value, out DateTime utcValue)
        {
            try
            {
                long signedValue = checked((long)value);
                utcValue = DateTime.FromFileTimeUtc(signedValue);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                utcValue = default;
                return false;
            }
            catch (OverflowException)
            {
                utcValue = default;
                return false;
            }
        }

        public static void SetCreationTimeUtc(OpenCifsServerShareBackend backend, string fullPath, DateTime utcValue)
        {
            backend.SetCreationTimeUtc(fullPath, utcValue, backend.DirectoryExists(fullPath));
        }

        public static void SetLastAccessTimeUtc(OpenCifsServerShareBackend backend, string fullPath, DateTime utcValue)
        {
            backend.SetLastAccessTimeUtc(fullPath, utcValue, backend.DirectoryExists(fullPath));
        }

        public static void SetLastWriteTimeUtc(OpenCifsServerShareBackend backend, string fullPath, DateTime utcValue)
        {
            backend.SetLastWriteTimeUtc(fullPath, utcValue, backend.DirectoryExists(fullPath));
        }

        private static bool IsStickyFileTimeDirective(ulong value)
        {
            return value == StickyDisableFileTimeDirective || value == StickyEnableFileTimeDirective;
        }
    }
}

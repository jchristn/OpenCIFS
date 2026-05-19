namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerFileIoOperationService
    {
        private readonly Func<OpenCifsServerHost, IEnumerable<ServerOpenRecord>> _EnumerateOpenRecords;
        private readonly OpenCifsServerFileStateTracker _FileStateTracker;
        private readonly Action<string, FileNotifyChangeFilter> _PublishModifiedNotification;
        private readonly OpenCifsServerSharedState _SharedState;

        public OpenCifsServerFileIoOperationService(
            OpenCifsServerSharedState sharedState,
            OpenCifsServerFileStateTracker fileStateTracker,
            Action<string, FileNotifyChangeFilter> publishModifiedNotification,
            Func<OpenCifsServerHost, IEnumerable<ServerOpenRecord>> enumerateOpenRecords)
        {
            _SharedState = sharedState ?? throw new ArgumentNullException(nameof(sharedState), "SharedState cannot be null.");
            _FileStateTracker = fileStateTracker ?? throw new ArgumentNullException(nameof(fileStateTracker), "FileStateTracker cannot be null.");
            _PublishModifiedNotification = publishModifiedNotification ?? throw new ArgumentNullException(nameof(publishModifiedNotification), "PublishModifiedNotification cannot be null.");
            _EnumerateOpenRecords = enumerateOpenRecords ?? throw new ArgumentNullException(nameof(enumerateOpenRecords), "EnumerateOpenRecords cannot be null.");
        }

        public OpenCifsServerOperationResult<Smb2ReadResponse> ExecuteRead(ServerOpenRecord openRecord, Smb2ReadRequest request, uint implementedReadWriteSize)
        {
            if (openRecord == null)
            {
                throw new ArgumentNullException(nameof(openRecord), "OpenRecord cannot be null.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (openRecord.IsNamedPipeEndpoint)
            {
                return CreateReadResult(NtStatus.NotSupported, new Smb2ReadResponse());
            }

            if (!openRecord.CanReadData)
            {
                return CreateReadResult(NtStatus.AccessDenied, new Smb2ReadResponse());
            }

            if (openRecord.IsDirectory || openRecord.Stream == null)
            {
                return CreateReadResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }

            if (request.Length > Int32.MaxValue)
            {
                return CreateReadResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }

            if (request.Length > implementedReadWriteSize)
            {
                return CreateReadResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }

            if (HasConflictingReadLock(openRecord, request.Offset, request.Length))
            {
                return CreateReadResult(NtStatus.FileLockConflict, new Smb2ReadResponse());
            }

            byte[] buffer = new byte[(int)request.Length];
            int bytesRead;

            try
            {
                openRecord.Stream.Position = checked((long)request.Offset);
                bytesRead = openRecord.Stream.Read(buffer, 0, buffer.Length);
            }
            catch (ArgumentOutOfRangeException)
            {
                return CreateReadResult(NtStatus.InvalidParameter, new Smb2ReadResponse());
            }
            catch (IOException)
            {
                return CreateReadResult(NtStatus.AccessDenied, new Smb2ReadResponse());
            }

            if (bytesRead == 0)
            {
                return CreateReadResult(NtStatus.EndOfFile, new Smb2ReadResponse());
            }

            if (bytesRead != buffer.Length)
            {
                Array.Resize(ref buffer, bytesRead);
            }

            _PublishModifiedNotification(openRecord.FullPath, _FileStateTracker.NoteTimestampMutation(openRecord, updateLastAccess: true));
            Smb2ReadResponse response = new Smb2ReadResponse
            {
                DataBuffer = buffer,
                DataRemaining = 0,
                Flags = 0
            };

            Smb2ReadResponseValidator.Validate(response);
            return CreateReadResult(NtStatus.Success, response);
        }

        public OpenCifsServerOperationResult<Smb2WriteResponse> ExecuteWrite(ServerOpenRecord openRecord, Smb2WriteRequest request, uint implementedReadWriteSize)
        {
            if (openRecord == null)
            {
                throw new ArgumentNullException(nameof(openRecord), "OpenRecord cannot be null.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (openRecord.IsNamedPipeEndpoint)
            {
                return CreateWriteResult(NtStatus.NotSupported, new Smb2WriteResponse());
            }

            if (!openRecord.CanWriteData)
            {
                return CreateWriteResult(NtStatus.AccessDenied, new Smb2WriteResponse());
            }

            if (openRecord.IsDirectory || openRecord.Stream == null)
            {
                return CreateWriteResult(NtStatus.InvalidParameter, new Smb2WriteResponse());
            }

            if (request.DataBuffer.Length > implementedReadWriteSize)
            {
                return CreateWriteResult(NtStatus.InvalidParameter, new Smb2WriteResponse());
            }

            if (HasConflictingWriteLock(openRecord, request.Offset, (ulong)request.DataBuffer.Length))
            {
                return CreateWriteResult(NtStatus.FileLockConflict, new Smb2WriteResponse());
            }

            try
            {
                openRecord.Stream.Position = checked((long)request.Offset);
                openRecord.Stream.Write(request.DataBuffer, 0, request.DataBuffer.Length);
                _FileStateTracker.EnsureDeclaredAllocationSize(openRecord.FullPath, unchecked((ulong)Math.Max(0L, openRecord.Stream.Length)));
            }
            catch (ArgumentOutOfRangeException)
            {
                return CreateWriteResult(NtStatus.InvalidParameter, new Smb2WriteResponse());
            }
            catch (IOException)
            {
                return CreateWriteResult(NtStatus.AccessDenied, new Smb2WriteResponse());
            }

            _PublishModifiedNotification(openRecord.FullPath, FileNotifyChangeFilter.Size | _FileStateTracker.NoteTimestampMutation(openRecord, updateLastWrite: true, updateChange: true));
            Smb2WriteResponse response = new Smb2WriteResponse
            {
                Count = (uint)request.DataBuffer.Length
            };

            Smb2WriteResponseValidator.Validate(response);
            return CreateWriteResult(NtStatus.Success, response);
        }

        public OpenCifsServerOperationResult<Smb2FlushResponse> ExecuteFlush(ServerOpenRecord openRecord, Smb2FlushRequest request)
        {
            if (openRecord == null)
            {
                throw new ArgumentNullException(nameof(openRecord), "OpenRecord cannot be null.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (openRecord.IsNamedPipeEndpoint)
            {
                return CreateFlushResult(NtStatus.NotSupported, new Smb2FlushResponse());
            }

            if (openRecord.IsDirectory || openRecord.Stream == null)
            {
                return CreateFlushResult(NtStatus.InvalidParameter, new Smb2FlushResponse());
            }

            try
            {
                openRecord.Stream.Flush();
            }
            catch (IOException)
            {
                return CreateFlushResult(NtStatus.AccessDenied, new Smb2FlushResponse());
            }

            Smb2FlushResponse response = new Smb2FlushResponse();
            Smb2FlushResponseValidator.Validate(response);
            return CreateFlushResult(NtStatus.Success, response);
        }

        public OpenCifsServerOperationResult<Smb2LockResponse> ExecuteLock(ServerOpenRecord openRecord, Smb2LockRequest request)
        {
            if (openRecord == null)
            {
                throw new ArgumentNullException(nameof(openRecord), "OpenRecord cannot be null.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (openRecord.IsNamedPipeEndpoint)
            {
                return CreateLockResult(NtStatus.NotSupported, new Smb2LockResponse());
            }

            if (openRecord.IsDirectory)
            {
                return CreateLockResult(NtStatus.InvalidParameter, new Smb2LockResponse());
            }

            NtStatus lockStatus = ApplyByteRangeLocks(openRecord, request.Locks);

            if (lockStatus != NtStatus.Success)
            {
                return CreateLockResult(lockStatus, new Smb2LockResponse());
            }

            Smb2LockResponse response = new Smb2LockResponse();
            Smb2LockResponseValidator.Validate(response);
            return CreateLockResult(NtStatus.Success, response);
        }

        private NtStatus ApplyByteRangeLocks(ServerOpenRecord openRecord, IReadOnlyList<Smb2LockElement> lockElements)
        {
            List<ServerByteRangeLock> pendingAdds = new List<ServerByteRangeLock>();
            List<ServerByteRangeLock> pendingRemovals = new List<ServerByteRangeLock>();

            for (int index = 0; index < lockElements.Count; index++)
            {
                Smb2LockElement element = lockElements[index];
                bool isUnlock = (element.Flags & Smb2LockFlags.Unlock) != 0;

                if (isUnlock)
                {
                    ServerByteRangeLock? existingLock = FindOwnedLock(openRecord, element.Offset, element.Length, pendingAdds, pendingRemovals);

                    if (existingLock == null)
                    {
                        return NtStatus.RangeNotLocked;
                    }

                    pendingRemovals.Add(existingLock);
                    continue;
                }

                bool requestedShared = (element.Flags & Smb2LockFlags.SharedLock) != 0;

                if (HasConflictingLock(openRecord, element.Offset, element.Length, requestedShared, pendingAdds, pendingRemovals))
                {
                    return NtStatus.LockNotGranted;
                }

                pendingAdds.Add(new ServerByteRangeLock
                {
                    OwnerVolatileFileId = openRecord.State.VolatileFileId,
                    Offset = element.Offset,
                    Length = element.Length,
                    IsShared = requestedShared
                });
            }

            for (int index = 0; index < pendingRemovals.Count; index++)
            {
                openRecord.Locks.Remove(pendingRemovals[index]);
            }

            for (int index = 0; index < pendingAdds.Count; index++)
            {
                openRecord.Locks.Add(pendingAdds[index]);
            }

            return NtStatus.Success;
        }

        private bool HasConflictingReadLock(ServerOpenRecord openRecord, ulong offset, ulong length)
        {
            if (!TryGetRangeEnd(offset, length, out ulong endOffset))
            {
                return true;
            }

            foreach (ServerByteRangeLock byteRangeLock in EnumerateLocksForPath(openRecord.FullPath))
            {
                if (!RangesOverlap(offset, endOffset, byteRangeLock.Offset, byteRangeLock.EndOffset))
                {
                    continue;
                }

                if (!byteRangeLock.IsShared && byteRangeLock.OwnerVolatileFileId != openRecord.State.VolatileFileId)
                {
                    return true;
                }
            }

            foreach (OpenCifsServerDetachedByteRangeLock detachedLock in EnumerateDetachedLocksForPath(openRecord.FullPath))
            {
                if (!TryGetRangeEnd(detachedLock.Offset, detachedLock.Length, out ulong detachedEndOffset))
                {
                    return true;
                }

                if (RangesOverlap(offset, endOffset, detachedLock.Offset, detachedEndOffset) &&
                    !detachedLock.IsShared)
                {
                    return true;
                }
            }

            return false;
        }

        private bool HasConflictingWriteLock(ServerOpenRecord openRecord, ulong offset, ulong length)
        {
            if (!TryGetRangeEnd(offset, length, out ulong endOffset))
            {
                return true;
            }

            foreach (ServerByteRangeLock byteRangeLock in EnumerateLocksForPath(openRecord.FullPath))
            {
                if (!RangesOverlap(offset, endOffset, byteRangeLock.Offset, byteRangeLock.EndOffset))
                {
                    continue;
                }

                if (byteRangeLock.OwnerVolatileFileId != openRecord.State.VolatileFileId || byteRangeLock.IsShared)
                {
                    return true;
                }
            }

            foreach (OpenCifsServerDetachedByteRangeLock detachedLock in EnumerateDetachedLocksForPath(openRecord.FullPath))
            {
                if (!TryGetRangeEnd(detachedLock.Offset, detachedLock.Length, out ulong detachedEndOffset))
                {
                    return true;
                }

                if (RangesOverlap(offset, endOffset, detachedLock.Offset, detachedEndOffset))
                {
                    return true;
                }
            }

            return false;
        }

        private ServerByteRangeLock? FindOwnedLock(
            ServerOpenRecord openRecord,
            ulong offset,
            ulong length,
            IReadOnlyList<ServerByteRangeLock> pendingAdds,
            IReadOnlyList<ServerByteRangeLock> pendingRemovals)
        {
            for (int index = pendingAdds.Count - 1; index >= 0; index--)
            {
                ServerByteRangeLock pendingLock = pendingAdds[index];

                if (pendingLock.OwnerVolatileFileId == openRecord.State.VolatileFileId &&
                    pendingLock.Offset == offset &&
                    pendingLock.Length == length)
                {
                    return pendingLock;
                }
            }

            for (int index = 0; index < openRecord.Locks.Count; index++)
            {
                ServerByteRangeLock existingLock = openRecord.Locks[index];

                if (ContainsLockReference(pendingRemovals, existingLock))
                {
                    continue;
                }

                if (existingLock.OwnerVolatileFileId == openRecord.State.VolatileFileId &&
                    existingLock.Offset == offset &&
                    existingLock.Length == length)
                {
                    return existingLock;
                }
            }

            return null;
        }

        private bool HasConflictingLock(
            ServerOpenRecord openRecord,
            ulong offset,
            ulong length,
            bool requestedShared,
            IReadOnlyList<ServerByteRangeLock> pendingAdds,
            IReadOnlyList<ServerByteRangeLock> pendingRemovals)
        {
            if (!TryGetRangeEnd(offset, length, out ulong endOffset))
            {
                return true;
            }

            foreach (ServerByteRangeLock byteRangeLock in EnumerateLocksForPath(openRecord.FullPath))
            {
                if (ContainsLockReference(pendingRemovals, byteRangeLock))
                {
                    continue;
                }

                if (!RangesOverlap(offset, endOffset, byteRangeLock.Offset, byteRangeLock.EndOffset))
                {
                    continue;
                }

                if (!requestedShared || !byteRangeLock.IsShared || byteRangeLock.OwnerVolatileFileId == openRecord.State.VolatileFileId)
                {
                    return true;
                }
            }

            foreach (OpenCifsServerDetachedByteRangeLock detachedLock in EnumerateDetachedLocksForPath(openRecord.FullPath))
            {
                if (!TryGetRangeEnd(detachedLock.Offset, detachedLock.Length, out ulong detachedEndOffset))
                {
                    return true;
                }

                if (!RangesOverlap(offset, endOffset, detachedLock.Offset, detachedEndOffset))
                {
                    continue;
                }

                if (!requestedShared || !detachedLock.IsShared)
                {
                    return true;
                }
            }

            for (int index = 0; index < pendingAdds.Count; index++)
            {
                ServerByteRangeLock pendingLock = pendingAdds[index];

                if (!RangesOverlap(offset, endOffset, pendingLock.Offset, pendingLock.EndOffset))
                {
                    continue;
                }

                if (!requestedShared || !pendingLock.IsShared || pendingLock.OwnerVolatileFileId == openRecord.State.VolatileFileId)
                {
                    return true;
                }
            }

            return false;
        }

        private IEnumerable<ServerByteRangeLock> EnumerateLocksForPath(string fullPath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerOpenRecord openRecord in _EnumerateOpenRecords(host))
                {
                    if (!string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    for (int index = 0; index < openRecord.Locks.Count; index++)
                    {
                        yield return openRecord.Locks[index];
                    }
                }
            }
        }

        private IEnumerable<OpenCifsServerDetachedByteRangeLock> EnumerateDetachedLocksForPath(string fullPath)
        {
            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (!string.Equals(durableOpenRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                for (int lockIndex = 0; lockIndex < durableOpenRecord.Locks.Count; lockIndex++)
                {
                    yield return durableOpenRecord.Locks[lockIndex];
                }
            }
        }

        private static bool ContainsLockReference(IReadOnlyList<ServerByteRangeLock> locks, ServerByteRangeLock candidate)
        {
            for (int index = 0; index < locks.Count; index++)
            {
                if (ReferenceEquals(locks[index], candidate))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool TryGetRangeEnd(ulong offset, ulong length, out ulong endOffset)
        {
            try
            {
                checked
                {
                    endOffset = offset + length;
                }

                return true;
            }
            catch (OverflowException)
            {
                endOffset = 0;
                return false;
            }
        }

        private static bool RangesOverlap(ulong leftStart, ulong leftEnd, ulong rightStart, ulong rightEnd)
        {
            return leftStart < rightEnd && rightStart < leftEnd;
        }

        private static OpenCifsServerOperationResult<Smb2ReadResponse> CreateReadResult(NtStatus status, Smb2ReadResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2ReadResponse>
            {
                Status = status,
                Response = response
            };
        }

        private static OpenCifsServerOperationResult<Smb2WriteResponse> CreateWriteResult(NtStatus status, Smb2WriteResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2WriteResponse>
            {
                Status = status,
                Response = response
            };
        }

        private static OpenCifsServerOperationResult<Smb2FlushResponse> CreateFlushResult(NtStatus status, Smb2FlushResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2FlushResponse>
            {
                Status = status,
                Response = response
            };
        }

        private static OpenCifsServerOperationResult<Smb2LockResponse> CreateLockResult(NtStatus status, Smb2LockResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2LockResponse>
            {
                Status = status,
                Response = response
            };
        }
    }
}

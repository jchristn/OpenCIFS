namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 lock requests.
    /// </summary>
    public static class Smb2LockRequestValidator
    {
        private const Smb2LockFlags SupportedFlags =
            Smb2LockFlags.SharedLock |
            Smb2LockFlags.ExclusiveLock |
            Smb2LockFlags.Unlock |
            Smb2LockFlags.FailImmediately;

        /// <summary>
        /// Validate a lock request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2LockRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 lock request cannot be null.", nameof(request));
            }

            if (request.LockSequence != 0)
            {
                throw new ProtocolValidationException("The SMB2 lock request lock-sequence field must remain zero for SMB 2.0.2.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 lock request must identify an open file handle.", nameof(request));
            }

            if (request.Locks.Length == 0)
            {
                throw new ProtocolValidationException("The SMB2 lock request must contain at least one lock element.", nameof(request));
            }

            for (int index = 0; index < request.Locks.Length; index++)
            {
                Smb2LockElement element = request.Locks[index] ?? throw new ProtocolValidationException("The SMB2 lock request cannot contain null lock elements.", nameof(request));

                if ((element.Flags & ~SupportedFlags) != 0)
                {
                    throw new ProtocolValidationException("The SMB2 lock request contains lock flags that are not supported.", nameof(request));
                }

                bool isShared = (element.Flags & Smb2LockFlags.SharedLock) != 0;
                bool isExclusive = (element.Flags & Smb2LockFlags.ExclusiveLock) != 0;
                bool isUnlock = (element.Flags & Smb2LockFlags.Unlock) != 0;
                bool failImmediately = (element.Flags & Smb2LockFlags.FailImmediately) != 0;

                if (isShared == isExclusive && !isUnlock)
                {
                    throw new ProtocolValidationException("Each SMB2 lock element must request exactly one lock mode.", nameof(request));
                }

                if (isUnlock && (isShared || isExclusive || failImmediately))
                {
                    throw new ProtocolValidationException("Unlock lock elements must not combine unlock with lock-acquisition flags.", nameof(request));
                }

                if (!isUnlock && !isShared && !isExclusive)
                {
                    throw new ProtocolValidationException("Each SMB2 lock element must either lock or unlock a range.", nameof(request));
                }

                if (element.Length == 0)
                {
                    throw new ProtocolValidationException("SMB2 lock elements must use non-zero range lengths.", nameof(request));
                }

                try
                {
                    checked
                    {
                        _ = element.Offset + element.Length;
                    }
                }
                catch (OverflowException)
                {
                    throw new ProtocolValidationException("The SMB2 lock element range exceeds the supported unsigned 64-bit offset space.", nameof(request));
                }
            }
        }
    }
}

namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Tracks SMB request lifecycle state.
    /// </summary>
    public sealed class RequestState : DisposableStateBase
    {
        /// <summary>
        /// Message identifier.
        /// </summary>
        public ulong MessageId { get; private set; } = 0;

        /// <summary>
        /// Request command identifier.
        /// </summary>
        public Smb2Command Command { get; private set; } = Smb2Command.Negotiate;

        /// <summary>
        /// Whether the request completed.
        /// </summary>
        public bool IsCompleted { get; private set; } = false;

        /// <summary>
        /// Whether the request was cancelled before completion.
        /// </summary>
        public bool IsCancelled { get; private set; } = false;

        /// <summary>
        /// Bound request header when the request lifecycle is tracked through the SMB2 header path.
        /// </summary>
        public Smb2Header? Header { get; private set; }

        /// <summary>
        /// Asynchronous identifier assigned by the server.
        /// </summary>
        public ulong AsyncId { get; private set; } = 0;

        /// <summary>
        /// Whether the request is being processed asynchronously.
        /// </summary>
        public bool IsAsync
        {
            get
            {
                return AsyncId != 0;
            }
        }

        /// <summary>
        /// Bind the request to a message identifier and command.
        /// </summary>
        /// <param name="messageId">Message identifier.</param>
        /// <param name="command">SMB2 command identifier.</param>
        public void Bind(ulong messageId, Smb2Command command)
        {
            EnsureNotDisposed();
            MessageId = messageId;
            Command = command;
            Header = null;
            AsyncId = 0;
            IsCompleted = false;
            IsCancelled = false;
        }

        /// <summary>
        /// Bind the request to an SMB2 header snapshot.
        /// </summary>
        /// <param name="header">Request header.</param>
        public void Bind(Smb2Header header)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header), "Header cannot be null.");
            }

            EnsureNotDisposed();
            MessageId = header.MessageId;
            Command = header.Command;
            Header = CloneHeader(header);
            AsyncId = 0;
            IsCompleted = false;
            IsCancelled = false;
        }

        /// <summary>
        /// Mark the request as being processed asynchronously.
        /// </summary>
        /// <param name="asyncId">Assigned asynchronous identifier.</param>
        public void MarkAsync(ulong asyncId)
        {
            EnsureNotDisposed();

            if (asyncId == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(asyncId), "Async identifiers must be non-zero.");
            }

            AsyncId = asyncId;
        }

        /// <summary>
        /// Mark the request as cancelled.
        /// </summary>
        public void Cancel()
        {
            EnsureNotDisposed();
            IsCancelled = true;
        }

        /// <summary>
        /// Mark the request as completed.
        /// </summary>
        public void Complete()
        {
            EnsureNotDisposed();
            IsCompleted = true;
        }

        private static Smb2Header CloneHeader(Smb2Header header)
        {
            return new Smb2Header
            {
                CreditCharge = header.CreditCharge,
                Status = header.Status,
                Command = header.Command,
                CreditRequest = header.CreditRequest,
                Flags = header.Flags,
                NextCommand = header.NextCommand,
                MessageId = header.MessageId,
                ProcessId = header.ProcessId,
                TreeId = header.TreeId,
                AsyncId = header.AsyncId,
                SessionId = header.SessionId,
                Signature = (byte[])header.Signature.Clone()
            };
        }
    }
}

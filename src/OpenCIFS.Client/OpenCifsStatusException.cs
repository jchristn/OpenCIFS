namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Exception raised when an SMB2 server returns a non-success NTSTATUS for a client operation.
    /// </summary>
    public sealed class OpenCifsStatusException : InvalidOperationException
    {
        /// <summary>
        /// Initialize an exception for a server-returned SMB2 status without extended error data.
        /// </summary>
        /// <param name="command">SMB2 command that failed.</param>
        /// <param name="status">Returned NTSTATUS value.</param>
        public OpenCifsStatusException(Smb2Command command, NtStatus status)
            : this(command, status, ReadOnlyMemory<byte>.Empty)
        {
        }

        /// <summary>
        /// Initialize an exception for a server-returned SMB2 status with decoded extended error data.
        /// </summary>
        /// <param name="command">SMB2 command that failed.</param>
        /// <param name="status">Returned NTSTATUS value.</param>
        /// <param name="errorData">Decoded SMB2 error-data bytes when available.</param>
        public OpenCifsStatusException(Smb2Command command, NtStatus status, ReadOnlyMemory<byte> errorData)
            : base(CreateMessage(command, status, errorData.Length))
        {
            Command = command;
            Status = status;
            _ErrorData = errorData.ToArray();
        }

        /// <summary>
        /// SMB2 command that returned the failure status.
        /// </summary>
        public Smb2Command Command { get; }

        /// <summary>
        /// Returned NTSTATUS value.
        /// </summary>
        public NtStatus Status { get; }

        /// <summary>
        /// Decoded SMB2 error-data bytes when the server returned an error response payload.
        /// </summary>
        public ReadOnlyMemory<byte> ErrorData
        {
            get
            {
                return _ErrorData;
            }
        }

        internal static OpenCifsStatusException CreateFromResponsePayload(Smb2Command command, NtStatus status, byte[]? responsePayload)
        {
            return new OpenCifsStatusException(command, status, DecodeErrorData(responsePayload));
        }

        private static string CreateMessage(Smb2Command command, NtStatus status, int errorDataLength)
        {
            string message = "SMB2 command " +
                command +
                " failed with NTSTATUS " +
                status +
                " (0x" +
                ((uint)status).ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                ").";

            if (errorDataLength > 0)
            {
                message += " ErrorDataLength=" + errorDataLength + ".";
            }

            return message;
        }

        private static ReadOnlyMemory<byte> DecodeErrorData(byte[]? responsePayload)
        {
            if (responsePayload == null || responsePayload.Length == 0)
            {
                return ReadOnlyMemory<byte>.Empty;
            }

            try
            {
                return Smb2ErrorResponse.ReadFrom(responsePayload).ErrorData;
            }
            catch (ProtocolEncodingException)
            {
                return responsePayload;
            }
        }

        private readonly byte[] _ErrorData;
    }
}

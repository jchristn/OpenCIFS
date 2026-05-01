namespace OpenCIFS.Client
{
    using System;
    using System.Globalization;

    /// <summary>
    /// Exception raised when a bounded RPC service hosted over <c>IPC$</c> returns a service-level failure code.
    /// </summary>
    public sealed class OpenCifsClientRpcException : OpenCifsClientException
    {
        /// <summary>
        /// Initialize an RPC exception.
        /// </summary>
        /// <param name="serviceName">Logical RPC service name.</param>
        /// <param name="operationName">Logical RPC operation name.</param>
        /// <param name="returnCode">Returned RPC service code.</param>
        public OpenCifsClientRpcException(string serviceName, string operationName, uint returnCode)
            : base(CreateMessage(serviceName, operationName, returnCode), ClassifyCategory(returnCode))
        {
            ServiceName = serviceName ?? string.Empty;
            OperationName = operationName ?? string.Empty;
            ReturnCode = returnCode;
        }

        /// <summary>
        /// Logical RPC service name.
        /// </summary>
        public string ServiceName { get; }

        /// <summary>
        /// Logical RPC operation name.
        /// </summary>
        public string OperationName { get; }

        /// <summary>
        /// Raw RPC service return code.
        /// </summary>
        public uint ReturnCode { get; }

        private static OpenCifsErrorCategory ClassifyCategory(uint returnCode)
        {
            switch (returnCode)
            {
                case 0x00000906:
                    return OpenCifsErrorCategory.NotFound;
                case 0x00000005:
                    return OpenCifsErrorCategory.AccessDenied;
                case 0x00000032:
                case 0x0000007C:
                    return OpenCifsErrorCategory.Unsupported;
                case 0x00000057:
                    return OpenCifsErrorCategory.ProtocolError;
                default:
                    return OpenCifsErrorCategory.Unknown;
            }
        }

        private static string CreateMessage(string serviceName, string operationName, uint returnCode)
        {
            string normalizedServiceName = string.IsNullOrWhiteSpace(serviceName) ? "RPC" : serviceName.Trim();
            string normalizedOperationName = string.IsNullOrWhiteSpace(operationName) ? "operation" : operationName.Trim();
            return normalizedServiceName +
                ' ' +
                normalizedOperationName +
                " failed with return code 0x" +
                returnCode.ToString("X8", CultureInfo.InvariantCulture) +
                '.';
        }
    }
}

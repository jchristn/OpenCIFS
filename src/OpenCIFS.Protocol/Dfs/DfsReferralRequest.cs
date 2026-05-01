namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// REQ_GET_DFS_REFERRAL payload used with <c>FSCTL_DFS_GET_REFERRALS</c>.
    /// </summary>
    public sealed class DfsReferralRequest
    {
        /// <summary>
        /// Highest referral-entry version understood by the client.
        /// </summary>
        public ushort MaxReferralLevel { get; set; } = 2;

        /// <summary>
        /// DFS path to resolve. The bounded managed slice uses a single-leading-backslash path such as <c>\server\share\link</c>.
        /// </summary>
        public string RequestPath { get; set; } = string.Empty;

        /// <summary>
        /// Serialize the request payload.
        /// </summary>
        /// <returns>Serialized bytes.</returns>
        public byte[] ToByteArray()
        {
            if (string.IsNullOrWhiteSpace(RequestPath))
            {
                throw new ArgumentNullException(nameof(RequestPath), "RequestPath cannot be null or whitespace.");
            }

            byte[] pathBytes = Encoding.Unicode.GetBytes(RequestPath + '\0');
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(MaxReferralLevel);
            writer.WriteBytes(pathBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request payload.
        /// </summary>
        /// <param name="buffer">Serialized payload bytes.</param>
        /// <returns>Decoded request.</returns>
        public static DfsReferralRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 4 || (buffer.Length & 1) != 0)
            {
                throw new ProtocolEncodingException("The DFS referral request payload is malformed.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort maxReferralLevel = reader.ReadUInt16();
            byte[] pathBytes = reader.ReadBytes(reader.RemainingBytes);

            if (pathBytes.Length < 2 || pathBytes[pathBytes.Length - 1] != 0 || pathBytes[pathBytes.Length - 2] != 0)
            {
                throw new ProtocolEncodingException("The DFS referral request path must be a null-terminated Unicode string.");
            }

            string requestPath = Encoding.Unicode.GetString(pathBytes, 0, pathBytes.Length - 2);

            if (string.IsNullOrWhiteSpace(requestPath))
            {
                throw new ProtocolEncodingException("The DFS referral request path cannot be empty.");
            }

            return new DfsReferralRequest
            {
                MaxReferralLevel = maxReferralLevel,
                RequestPath = requestPath
            };
        }
    }
}

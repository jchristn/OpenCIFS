namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 tree-connect response payload.
    /// </summary>
    public sealed class Smb2TreeConnectResponse
    {
        /// <summary>
        /// Share type.
        /// </summary>
        public Smb2ShareType ShareType { get; set; } = Smb2ShareType.Disk;

        /// <summary>
        /// Share flags.
        /// </summary>
        public uint ShareFlags { get; set; }

        /// <summary>
        /// Share capabilities.
        /// </summary>
        public uint Capabilities { get; set; }

        /// <summary>
        /// Maximal access mask.
        /// </summary>
        public uint MaximalAccess { get; set; }

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(16);
            writer.WriteByte((byte)ShareType);
            writer.WriteByte(0);
            writer.WriteUInt32(ShareFlags);
            writer.WriteUInt32(Capabilities);
            writer.WriteUInt32(MaximalAccess);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2TreeConnectResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != 16)
            {
                throw new ProtocolEncodingException("The SMB2 tree-connect response must be exactly 16 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != 16)
            {
                throw new ProtocolEncodingException("The SMB2 tree-connect response structure size must be 16 bytes.");
            }

            Smb2TreeConnectResponse response = new Smb2TreeConnectResponse
            {
                ShareType = (Smb2ShareType)reader.ReadByte()
            };

            reader.Skip(1);
            response.ShareFlags = reader.ReadUInt32();
            response.Capabilities = reader.ReadUInt32();
            response.MaximalAccess = reader.ReadUInt32();
            return response;
        }
    }
}

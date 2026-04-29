namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// SMB2 tree-connect request payload.
    /// </summary>
    public sealed class Smb2TreeConnectRequest
    {
        private const ushort StructureSize = 9;
        private const ushort FixedBodyLength = 8;

        /// <summary>
        /// Tree-connect flags.
        /// </summary>
        public ushort Flags { get; set; }

        /// <summary>
        /// Share path, typically a UNC path.
        /// </summary>
        public string Path
        {
            get
            {
                return _Path;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(Path), "Path cannot be null or whitespace.");
                }

                _Path = value;
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] pathBytes = Encoding.Unicode.GetBytes(Path);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(Flags);
            writer.WriteUInt16((ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength));
            writer.WriteUInt16((ushort)pathBytes.Length);
            writer.WriteBytes(pathBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2TreeConnectRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 tree-connect request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 tree-connect request structure size must be 9 bytes.");
            }

            Smb2TreeConnectRequest request = new Smb2TreeConnectRequest
            {
                Flags = reader.ReadUInt16()
            };

            ushort pathOffset = reader.ReadUInt16();
            ushort pathLength = reader.ReadUInt16();
            int relativePathOffset = pathOffset - ProtocolConstants.Smb2HeaderLength;

            if (relativePathOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 tree-connect request path offset is invalid.");
            }

            if (relativePathOffset + pathLength > buffer.Length || (pathLength % 2) != 0)
            {
                throw new ProtocolEncodingException("The SMB2 tree-connect request path bytes are invalid.");
            }

            request.Path = Encoding.Unicode.GetString(buffer.Slice(relativePathOffset, pathLength).ToArray());
            return request;
        }

        private string _Path = string.Empty;
    }
}

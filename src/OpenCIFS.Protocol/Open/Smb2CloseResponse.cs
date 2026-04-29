namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 close response payload.
    /// </summary>
    public sealed class Smb2CloseResponse
    {
        private const ushort StructureSize = 60;

        /// <summary>
        /// Close flags.
        /// </summary>
        public Smb2CloseFlags Flags { get; set; } = Smb2CloseFlags.None;

        /// <summary>
        /// Creation time in FILETIME form.
        /// </summary>
        public ulong CreationTime { get; set; }

        /// <summary>
        /// Last-access time in FILETIME form.
        /// </summary>
        public ulong LastAccessTime { get; set; }

        /// <summary>
        /// Last-write time in FILETIME form.
        /// </summary>
        public ulong LastWriteTime { get; set; }

        /// <summary>
        /// Change time in FILETIME form.
        /// </summary>
        public ulong ChangeTime { get; set; }

        /// <summary>
        /// Allocation size.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// End-of-file size.
        /// </summary>
        public ulong EndOfFile { get; set; }

        /// <summary>
        /// File attributes.
        /// </summary>
        public FileAttributes FileAttributes { get; set; } = FileAttributes.None;

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16((ushort)Flags);
            writer.WriteUInt32(0);
            writer.WriteUInt64(CreationTime);
            writer.WriteUInt64(LastAccessTime);
            writer.WriteUInt64(LastWriteTime);
            writer.WriteUInt64(ChangeTime);
            writer.WriteUInt64(AllocationSize);
            writer.WriteUInt64(EndOfFile);
            writer.WriteUInt32((uint)FileAttributes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2CloseResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 close response must be exactly 60 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 close response structure size must be 60 bytes.");
            }

            Smb2CloseResponse response = new Smb2CloseResponse
            {
                Flags = (Smb2CloseFlags)reader.ReadUInt16()
            };

            reader.Skip(4);
            response.CreationTime = reader.ReadUInt64();
            response.LastAccessTime = reader.ReadUInt64();
            response.LastWriteTime = reader.ReadUInt64();
            response.ChangeTime = reader.ReadUInt64();
            response.AllocationSize = reader.ReadUInt64();
            response.EndOfFile = reader.ReadUInt64();
            response.FileAttributes = (FileAttributes)reader.ReadUInt32();
            return response;
        }
    }
}

namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// SMB2 create request payload.
    /// </summary>
    public sealed class Smb2CreateRequest
    {
        private const ushort StructureSize = 57;
        private const ushort FixedBodyLength = 56;

        /// <summary>
        /// Requested oplock level.
        /// </summary>
        public Smb2OplockLevel RequestedOplockLevel { get; set; } = Smb2OplockLevel.None;

        /// <summary>
        /// Requested impersonation level.
        /// </summary>
        public Smb2ImpersonationLevel ImpersonationLevel { get; set; } = Smb2ImpersonationLevel.Impersonation;

        /// <summary>
        /// Desired access mask.
        /// </summary>
        public uint DesiredAccess { get; set; }

        /// <summary>
        /// Requested file attributes.
        /// </summary>
        public FileAttributes FileAttributes { get; set; } = FileAttributes.Normal;

        /// <summary>
        /// Share access mask.
        /// </summary>
        public uint ShareAccess { get; set; }

        /// <summary>
        /// Create disposition.
        /// </summary>
        public Smb2CreateDisposition CreateDisposition { get; set; } = Smb2CreateDisposition.OpenIf;

        /// <summary>
        /// Create options.
        /// </summary>
        public Smb2CreateOptions CreateOptions { get; set; } = Smb2CreateOptions.NonDirectoryFile;

        /// <summary>
        /// Relative path within the connected share.
        /// </summary>
        public string Name
        {
            get
            {
                return _Name;
            }
            set
            {
                _Name = value ?? throw new ArgumentNullException(nameof(Name), "Name cannot be null.");
            }
        }

        /// <summary>
        /// Raw create-context bytes.
        /// </summary>
        public byte[] CreateContexts
        {
            get
            {
                return _CreateContexts;
            }
            set
            {
                _CreateContexts = value ?? throw new ArgumentNullException(nameof(CreateContexts), "CreateContexts cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] nameBytes = Encoding.Unicode.GetBytes(Name);
            byte[] createContexts = CreateContexts;
            int createContextPadding = createContexts.Length == 0
                ? 0
                : GetEightBytePadding(ProtocolConstants.Smb2HeaderLength + FixedBodyLength + nameBytes.Length);
            ushort nameOffset = nameBytes.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);
            uint createContextsOffset = createContexts.Length == 0
                ? 0U
                : (uint)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength + nameBytes.Length + createContextPadding);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte(0);
            writer.WriteByte((byte)RequestedOplockLevel);
            writer.WriteUInt32((uint)ImpersonationLevel);
            writer.WriteUInt64(0);
            writer.WriteUInt64(0);
            writer.WriteUInt32(DesiredAccess);
            writer.WriteUInt32((uint)FileAttributes);
            writer.WriteUInt32(ShareAccess);
            writer.WriteUInt32((uint)CreateDisposition);
            writer.WriteUInt32((uint)CreateOptions);
            writer.WriteUInt16(nameOffset);
            writer.WriteUInt16((ushort)nameBytes.Length);
            writer.WriteUInt32(createContextsOffset);
            writer.WriteUInt32((uint)createContexts.Length);
            writer.WriteBytes(nameBytes);

            for (int index = 0; index < createContextPadding; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(createContexts);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2CreateRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 create request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 create request structure size must be 57 bytes.");
            }

            reader.Skip(1);
            Smb2CreateRequest request = new Smb2CreateRequest
            {
                RequestedOplockLevel = (Smb2OplockLevel)reader.ReadByte(),
                ImpersonationLevel = (Smb2ImpersonationLevel)reader.ReadUInt32()
            };

            reader.Skip(8);
            reader.Skip(8);
            request.DesiredAccess = reader.ReadUInt32();
            request.FileAttributes = (FileAttributes)reader.ReadUInt32();
            request.ShareAccess = reader.ReadUInt32();
            request.CreateDisposition = (Smb2CreateDisposition)reader.ReadUInt32();
            request.CreateOptions = (Smb2CreateOptions)reader.ReadUInt32();
            ushort nameOffset = reader.ReadUInt16();
            ushort nameLength = reader.ReadUInt16();
            uint createContextsOffset = reader.ReadUInt32();
            uint createContextsLength = reader.ReadUInt32();

            if (nameLength == 0)
            {
                request.Name = string.Empty;
            }
            else
            {
                int relativeNameOffset = nameOffset - ProtocolConstants.Smb2HeaderLength;

                if (relativeNameOffset < FixedBodyLength)
                {
                    throw new ProtocolEncodingException("The SMB2 create request name offset is invalid.");
                }

                if ((nameLength % 2) != 0 || relativeNameOffset + nameLength > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB2 create request name bytes are invalid.");
                }

                request.Name = Encoding.Unicode.GetString(buffer.Slice(relativeNameOffset, nameLength).ToArray());
            }

            if (createContextsLength == 0)
            {
                if (reader.RemainingBytes != Math.Max(0, buffer.Length - FixedBodyLength))
                {
                    throw new ProtocolEncodingException("The SMB2 create request contains unsupported trailing bytes.");
                }

                request.CreateContexts = Array.Empty<byte>();
                return request;
            }

            if (createContextsLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 create request create-context length exceeds the supported maximum.");
            }

            int relativeCreateContextsOffset = checked((int)createContextsOffset) - ProtocolConstants.Smb2HeaderLength;
            int createContextsLengthValue = checked((int)createContextsLength);

            if (relativeCreateContextsOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 create request create-context offset is invalid.");
            }

            if (relativeCreateContextsOffset + createContextsLengthValue > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 create request create-context buffer exceeds the available payload.");
            }

            request.CreateContexts = buffer.Slice(relativeCreateContextsOffset, createContextsLengthValue).ToArray();
            return request;
        }

        private static int GetEightBytePadding(int absoluteOffset)
        {
            int remainder = absoluteOffset % 8;
            return remainder == 0 ? 0 : 8 - remainder;
        }

        private string _Name = string.Empty;
        private byte[] _CreateContexts = Array.Empty<byte>();
    }
}

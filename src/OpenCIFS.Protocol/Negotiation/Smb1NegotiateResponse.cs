namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_NEGOTIATE</c> response used for the NT LM 0.12 / extended-security shape.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.5.2 defines a 17-word response body (<c>WordCount=0x11</c>) plus a variable
    /// <c>Buffer</c>. The extended-security shape sets <see cref="Smb1Capabilities.ExtendedSecurity" />,
    /// places the 16-byte server GUID at the start of <c>Buffer</c>, and follows it with the optional
    /// SPNEGO security blob.
    /// </remarks>
    public sealed class Smb1NegotiateResponse
    {
        private const byte WordCountValue = 0x11;
        private const int FixedBodyLength = 1 + (WordCountValue * sizeof(ushort)) + sizeof(ushort);
        private const int ServerGuidLength = 16;

        /// <summary>
        /// SMB1 response header.
        /// </summary>
        public Smb1Header Header
        {
            get
            {
                return _Header;
            }
            set
            {
                _Header = value ?? throw new ArgumentNullException(nameof(Header), "Header cannot be null.");
            }
        }

        /// <summary>
        /// Index of the dialect the server selected from the request's dialect array.
        /// </summary>
        public ushort DialectIndex { get; set; }

        /// <summary>
        /// Negotiated security-mode flags.
        /// </summary>
        public Smb1SecurityMode SecurityMode { get; set; } = Smb1SecurityMode.UserSecurity | Smb1SecurityMode.EncryptPasswords | Smb1SecurityMode.SigningEnabled;

        /// <summary>
        /// Maximum number of pending multiplexed requests on a single connection.
        /// </summary>
        public ushort MaxMpxCount { get; set; } = 50;

        /// <summary>
        /// Maximum number of virtual circuits per session.
        /// </summary>
        public ushort MaxNumberVcs { get; set; } = 1;

        /// <summary>
        /// Maximum buffer size accepted by the server.
        /// </summary>
        public uint MaxBufferSize { get; set; } = 65535;

        /// <summary>
        /// Maximum raw-mode buffer size.
        /// </summary>
        public uint MaxRawSize { get; set; } = 65536;

        /// <summary>
        /// Server-generated session key seed.
        /// </summary>
        public uint SessionKey { get; set; }

        /// <summary>
        /// Negotiated server capability flags.
        /// </summary>
        public Smb1Capabilities Capabilities { get; set; } = Smb1Capabilities.Unicode | Smb1Capabilities.LargeFiles | Smb1Capabilities.NtSmbs | Smb1Capabilities.Status32 | Smb1Capabilities.NtFind | Smb1Capabilities.ExtendedSecurity;

        /// <summary>
        /// System time as an SMB1 FILETIME value.
        /// </summary>
        public ulong SystemTime { get; set; }

        /// <summary>
        /// Server time-zone offset from UTC, in minutes.
        /// </summary>
        public short ServerTimeZoneMinutes { get; set; }

        /// <summary>
        /// Server GUID returned in the buffer when extended security is advertised.
        /// </summary>
        public Guid ServerGuid { get; set; }

        /// <summary>
        /// Optional SPNEGO security blob carried after the server GUID when extended security is advertised.
        /// </summary>
        public byte[] SecurityBlob
        {
            get
            {
                return _SecurityBlob;
            }
            set
            {
                _SecurityBlob = value ?? throw new ArgumentNullException(nameof(SecurityBlob), "SecurityBlob cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.Negotiate)
            {
                throw new ProtocolValidationException("The SMB1 negotiate response header command must be SMB_COM_NEGOTIATE.", nameof(Header));
            }

            if ((Capabilities & Smb1Capabilities.ExtendedSecurity) == 0)
            {
                throw new ProtocolValidationException("The bounded SMB1 negotiate response codec only supports the extended-security shape.", nameof(Capabilities));
            }

            byte[] securityBlobBytes = SecurityBlob;
            int byteCount = ServerGuidLength + securityBlobBytes.Length;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(SecurityBlob), "Server GUID plus SPNEGO security blob exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteUInt16(DialectIndex);
            writer.WriteByte((byte)SecurityMode);
            writer.WriteUInt16(MaxMpxCount);
            writer.WriteUInt16(MaxNumberVcs);
            writer.WriteUInt32(MaxBufferSize);
            writer.WriteUInt32(MaxRawSize);
            writer.WriteUInt32(SessionKey);
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteUInt64(SystemTime);
            writer.WriteUInt16(unchecked((ushort)ServerTimeZoneMinutes));
            writer.WriteByte(0);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteBytes(ServerGuid.ToByteArray());
            writer.WriteBytes(securityBlobBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 NEGOTIATE response from its wire bytes for the NT LM 0.12 extended-security shape.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1NegotiateResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 negotiate response.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.Negotiate)
            {
                throw new ProtocolEncodingException("The SMB1 response does not carry an SMB_COM_NEGOTIATE command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 negotiate response codec requires WordCount=17 (NT LM 0.12 / extended-security shape).");
            }

            ushort dialectIndex = reader.ReadUInt16();
            byte securityMode = reader.ReadByte();
            ushort maxMpxCount = reader.ReadUInt16();
            ushort maxNumberVcs = reader.ReadUInt16();
            uint maxBufferSize = reader.ReadUInt32();
            uint maxRawSize = reader.ReadUInt32();
            uint sessionKey = reader.ReadUInt32();
            uint capabilities = reader.ReadUInt32();
            ulong systemTime = reader.ReadUInt64();
            short serverTimeZoneMinutes = unchecked((short)reader.ReadUInt16());
            byte challengeLength = reader.ReadByte();
            ushort byteCount = reader.ReadUInt16();

            Smb1Capabilities capabilityFlags = (Smb1Capabilities)capabilities;

            if ((capabilityFlags & Smb1Capabilities.ExtendedSecurity) == 0)
            {
                throw new ProtocolEncodingException("The bounded SMB1 negotiate response codec only supports the extended-security shape.");
            }

            if (challengeLength != 0)
            {
                throw new ProtocolEncodingException("The SMB1 negotiate response ChallengeLength must be zero on the extended-security shape.");
            }

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 negotiate response ByteCount does not match the remaining payload length.");
            }

            if (byteCount < ServerGuidLength)
            {
                throw new ProtocolEncodingException("The SMB1 negotiate response buffer must include the 16-byte server GUID on the extended-security shape.");
            }

            byte[] serverGuidBytes = reader.ReadBytes(ServerGuidLength);
            byte[] securityBlobBytes = reader.ReadBytes(byteCount - ServerGuidLength);

            return new Smb1NegotiateResponse
            {
                Header = header,
                DialectIndex = dialectIndex,
                SecurityMode = (Smb1SecurityMode)securityMode,
                MaxMpxCount = maxMpxCount,
                MaxNumberVcs = maxNumberVcs,
                MaxBufferSize = maxBufferSize,
                MaxRawSize = maxRawSize,
                SessionKey = sessionKey,
                Capabilities = capabilityFlags,
                SystemTime = systemTime,
                ServerTimeZoneMinutes = serverTimeZoneMinutes,
                ServerGuid = new Guid(serverGuidBytes),
                SecurityBlob = securityBlobBytes
            };
        }

        private byte[] _SecurityBlob = Array.Empty<byte>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.Negotiate,
            Flags = (Smb1HeaderFlags)0x88,
            Flags2 = Smb1HeaderFlags2.None
        };
    }
}

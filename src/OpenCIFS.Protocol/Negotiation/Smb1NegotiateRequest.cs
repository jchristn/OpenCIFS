namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// SMB1 <c>SMB_COM_NEGOTIATE</c> request used for multi-protocol SMB2 bootstrap.
    /// </summary>
    public sealed class Smb1NegotiateRequest
    {
        /// <summary>
        /// SMB1 dialect string that indicates SMB 2.0.2 support during multi-protocol negotiate.
        /// </summary>
        public const string Smb2002DialectString = "SMB 2.002";

        /// <summary>
        /// SMB1 dialect string that indicates SMB 2.1 or newer support during multi-protocol negotiate.
        /// </summary>
        public const string Smb2WildcardDialectString = "SMB 2.???";

        private const byte DialectBufferFormat = 0x02;

        /// <summary>
        /// SMB1 request header.
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
        /// Dialect strings in wire order.
        /// </summary>
        public string[] Dialects
        {
            get
            {
                return _Dialects;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Dialects), "Dialects cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(Dialects), "At least one dialect string must be supplied.");
                }

                string[] clonedDialects = new string[value.Length];

                for (int index = 0; index < value.Length; index++)
                {
                    string dialect = value[index] ?? throw new ArgumentNullException(nameof(Dialects), "Dialect strings cannot be null.");

                    if (dialect.Length == 0)
                    {
                        throw new ArgumentOutOfRangeException(nameof(Dialects), "Dialect strings cannot be empty.");
                    }

                    if (dialect.IndexOf('\0') >= 0)
                    {
                        throw new ArgumentOutOfRangeException(nameof(Dialects), "Dialect strings cannot contain embedded null characters.");
                    }

                    clonedDialects[index] = dialect;
                }

                _Dialects = clonedDialects;
            }
        }

        /// <summary>
        /// Serialize the request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.Negotiate)
            {
                throw new ProtocolValidationException("The SMB1 negotiate request header command must be SMB_COM_NEGOTIATE.", nameof(Header));
            }

            byte[] dialectBytes = EncodeDialects(Dialects);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(0);
            writer.WriteUInt16(checked((ushort)dialectBytes.Length));
            writer.WriteBytes(dialectBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Determine whether the request contains a specific dialect string.
        /// </summary>
        /// <param name="dialect">Dialect string to find.</param>
        /// <returns><c>true</c> when the dialect is present.</returns>
        public bool ContainsDialect(string dialect)
        {
            if (dialect == null)
            {
                throw new ArgumentNullException(nameof(dialect), "Dialect cannot be null.");
            }

            for (int index = 0; index < Dialects.Length; index++)
            {
                if (StringComparer.Ordinal.Equals(Dialects[index], dialect))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Parse the request from SMB1 wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1NegotiateRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < ProtocolConstants.Smb1HeaderLength + 3)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 negotiate request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.Negotiate)
            {
                throw new ProtocolEncodingException("The SMB1 request does not carry an SMB_COM_NEGOTIATE command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != 0)
            {
                throw new ProtocolEncodingException("SMB1 negotiate requests must use WordCount=0.");
            }

            ushort byteCount = reader.ReadUInt16();

            if (byteCount == 0)
            {
                throw new ProtocolEncodingException("SMB1 negotiate requests must advertise at least one dialect string.");
            }

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 negotiate request ByteCount does not match the remaining payload length.");
            }

            List<string> dialects = new List<string>();

            while (reader.RemainingBytes > 0)
            {
                byte bufferFormat = reader.ReadByte();

                if (bufferFormat != DialectBufferFormat)
                {
                    throw new ProtocolEncodingException("SMB1 negotiate dialect strings must use buffer format 0x02.");
                }

                List<byte> dialectBytes = new List<byte>();
                bool foundTerminator = false;

                while (reader.RemainingBytes > 0)
                {
                    byte value = reader.ReadByte();

                    if (value == 0)
                    {
                        foundTerminator = true;
                        break;
                    }

                    dialectBytes.Add(value);
                }

                if (!foundTerminator)
                {
                    throw new ProtocolEncodingException("SMB1 negotiate dialect strings must be null terminated.");
                }

                if (dialectBytes.Count == 0)
                {
                    throw new ProtocolEncodingException("SMB1 negotiate dialect strings cannot be empty.");
                }

                dialects.Add(Encoding.ASCII.GetString(dialectBytes.ToArray()));
            }

            return new Smb1NegotiateRequest
            {
                Header = header,
                Dialects = dialects.ToArray()
            };
        }

        private static byte[] EncodeDialects(string[] dialects)
        {
            LittleEndianWriter writer = new LittleEndianWriter();

            for (int index = 0; index < dialects.Length; index++)
            {
                writer.WriteByte(DialectBufferFormat);
                writer.WriteBytes(Encoding.ASCII.GetBytes(dialects[index]));
                writer.WriteByte(0);
            }

            return writer.ToArray();
        }

        private string[] _Dialects = new string[] { Smb2002DialectString };
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.Negotiate
        };
    }
}

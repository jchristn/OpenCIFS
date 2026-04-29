namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// Internal OpenCIFS NTLM negotiate token carried inside SPNEGO mechanism tokens.
    /// </summary>
    public sealed class OpenCifsNtlmNegotiateToken
    {
        /// <summary>
        /// User name presented by the client.
        /// </summary>
        public string UserName
        {
            get
            {
                return _UserName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(UserName), "UserName cannot be null or whitespace.");
                }

                _UserName = value;
            }
        }

        /// <summary>
        /// Optional user domain presented by the client.
        /// </summary>
        public string UserDomain
        {
            get
            {
                return _UserDomain;
            }
            set
            {
                _UserDomain = value ?? throw new ArgumentNullException(nameof(UserDomain), "UserDomain cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the token to bytes.
        /// </summary>
        /// <returns>Serialized token bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            WriteUtf8String(writer, UserName);
            WriteUtf8String(writer, UserDomain);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the token from bytes.
        /// </summary>
        /// <param name="buffer">Serialized token bytes.</param>
        /// <returns>Parsed token.</returns>
        public static OpenCifsNtlmNegotiateToken ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            LittleEndianReader reader = new LittleEndianReader(buffer);
            OpenCifsNtlmNegotiateToken token = new OpenCifsNtlmNegotiateToken
            {
                UserName = ReadUtf8String(reader),
                UserDomain = ReadUtf8String(reader)
            };

            if (reader.RemainingBytes != 0)
            {
                throw new ProtocolEncodingException("The OpenCIFS NTLM negotiate token contains unsupported trailing bytes.");
            }

            return token;
        }

        private static void WriteUtf8String(LittleEndianWriter writer, string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            writer.WriteUInt16((ushort)bytes.Length);
            writer.WriteBytes(bytes);
        }

        private static string ReadUtf8String(LittleEndianReader reader)
        {
            ushort length = reader.ReadUInt16();
            return Encoding.UTF8.GetString(reader.ReadBytes(length));
        }

        private string _UserName = string.Empty;
        private string _UserDomain = string.Empty;
    }
}

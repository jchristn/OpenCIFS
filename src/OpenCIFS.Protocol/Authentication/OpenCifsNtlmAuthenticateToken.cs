namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// Internal OpenCIFS NTLM authenticate token carried inside SPNEGO mechanism tokens.
    /// </summary>
    public sealed class OpenCifsNtlmAuthenticateToken
    {
        /// <summary>
        /// User name being authenticated.
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
        /// Optional user domain.
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
        /// Serialized NT challenge response bytes.
        /// </summary>
        public byte[] NtChallengeResponse
        {
            get
            {
                return _NtChallengeResponse;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(NtChallengeResponse), "NtChallengeResponse cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(NtChallengeResponse), "NtChallengeResponse must not be empty.");
                }

                _NtChallengeResponse = value;
            }
        }

        /// <summary>
        /// Serialized LM challenge response bytes.
        /// </summary>
        public byte[] LmChallengeResponse
        {
            get
            {
                return _LmChallengeResponse;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(LmChallengeResponse), "LmChallengeResponse cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(LmChallengeResponse), "LmChallengeResponse must not be empty.");
                }

                _LmChallengeResponse = value;
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
            writer.WriteUInt16((ushort)NtChallengeResponse.Length);
            writer.WriteBytes(NtChallengeResponse);
            writer.WriteUInt16((ushort)LmChallengeResponse.Length);
            writer.WriteBytes(LmChallengeResponse);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the token from bytes.
        /// </summary>
        /// <param name="buffer">Serialized token bytes.</param>
        /// <returns>Parsed token.</returns>
        public static OpenCifsNtlmAuthenticateToken ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            LittleEndianReader reader = new LittleEndianReader(buffer);
            OpenCifsNtlmAuthenticateToken token = new OpenCifsNtlmAuthenticateToken
            {
                UserName = ReadUtf8String(reader),
                UserDomain = ReadUtf8String(reader)
            };

            ushort ntResponseLength = reader.ReadUInt16();
            token.NtChallengeResponse = reader.ReadBytes(ntResponseLength);
            ushort lmResponseLength = reader.ReadUInt16();
            token.LmChallengeResponse = reader.ReadBytes(lmResponseLength);

            if (reader.RemainingBytes != 0)
            {
                throw new ProtocolEncodingException("The OpenCIFS NTLM authenticate token contains unsupported trailing bytes.");
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
        private byte[] _NtChallengeResponse = Array.Empty<byte>();
        private byte[] _LmChallengeResponse = Array.Empty<byte>();
    }
}

namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// Internal OpenCIFS NTLM challenge token carried inside SPNEGO mechanism tokens.
    /// </summary>
    public sealed class OpenCifsNtlmChallengeToken
    {
        /// <summary>
        /// Eight-byte server challenge.
        /// </summary>
        public byte[] ServerChallenge
        {
            get
            {
                return _ServerChallenge;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(ServerChallenge), "ServerChallenge cannot be null.");
                }

                if (value.Length != 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(ServerChallenge), "ServerChallenge must be exactly 8 bytes.");
                }

                _ServerChallenge = value;
            }
        }

        /// <summary>
        /// Server name used in target-info construction.
        /// </summary>
        public string ServerName
        {
            get
            {
                return _ServerName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(ServerName), "ServerName cannot be null or whitespace.");
                }

                _ServerName = value;
            }
        }

        /// <summary>
        /// Target domain used in target-info construction.
        /// </summary>
        public string TargetDomain
        {
            get
            {
                return _TargetDomain;
            }
            set
            {
                _TargetDomain = value ?? throw new ArgumentNullException(nameof(TargetDomain), "TargetDomain cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the token to bytes.
        /// </summary>
        /// <returns>Serialized token bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(ServerChallenge);
            WriteUtf8String(writer, ServerName);
            WriteUtf8String(writer, TargetDomain);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the token from bytes.
        /// </summary>
        /// <param name="buffer">Serialized token bytes.</param>
        /// <returns>Parsed token.</returns>
        public static OpenCifsNtlmChallengeToken ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            LittleEndianReader reader = new LittleEndianReader(buffer);
            OpenCifsNtlmChallengeToken token = new OpenCifsNtlmChallengeToken
            {
                ServerChallenge = reader.ReadBytes(8),
                ServerName = ReadUtf8String(reader),
                TargetDomain = ReadUtf8String(reader)
            };

            if (reader.RemainingBytes != 0)
            {
                throw new ProtocolEncodingException("The OpenCIFS NTLM challenge token contains unsupported trailing bytes.");
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

        private byte[] _ServerChallenge = new byte[8];
        private string _ServerName = string.Empty;
        private string _TargetDomain = string.Empty;
    }
}

namespace OpenCIFS.Security
{
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Represents the NTLMv2 client-challenge structure embedded in NT challenge responses.
    /// </summary>
    public sealed class NtlmV2ClientChallenge
    {
        /// <summary>
        /// Current NTLMv2 response-type identifier.
        /// </summary>
        public byte ResponseType { get; set; } = 0x01;

        /// <summary>
        /// Highest NTLMv2 response-type identifier understood by the client.
        /// </summary>
        public byte HighResponseType { get; set; } = 0x01;

        /// <summary>
        /// FILETIME timestamp value.
        /// </summary>
        public ulong Timestamp { get; set; }

        /// <summary>
        /// Eight-byte client challenge.
        /// </summary>
        public byte[] ClientChallenge
        {
            get
            {
                return _ClientChallenge;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(ClientChallenge), "ClientChallenge cannot be null.");
                }

                if (value.Length != 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(ClientChallenge), "ClientChallenge must be exactly 8 bytes.");
                }

                _ClientChallenge = value;
            }
        }

        /// <summary>
        /// Server target-info AV pairs without the trailing end-of-list marker.
        /// </summary>
        public NtlmAvPair[] AvPairs
        {
            get
            {
                return _AvPairs;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(AvPairs), "AvPairs cannot be null.");
                }

                for (int index = 0; index < value.Length; index++)
                {
                    if (value[index] == null)
                    {
                        throw new ArgumentException("AvPairs cannot contain null entries.", nameof(AvPairs));
                    }

                    if (value[index].AvId == NtlmAvPairId.EndOfList)
                    {
                        throw new ArgumentException("AvPairs must not include the trailing end-of-list marker.", nameof(AvPairs));
                    }
                }

                _AvPairs = value;
            }
        }

        /// <summary>
        /// Trailing bytes that follow the AV-pair end-of-list marker.
        /// Windows NTLMv2 examples carry a reserved zero DWORD here.
        /// </summary>
        public byte[] TrailingBytes
        {
            get
            {
                return _TrailingBytes;
            }
            set
            {
                _TrailingBytes = value ?? throw new ArgumentNullException(nameof(TrailingBytes), "TrailingBytes cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the client-challenge structure to its wire format.
        /// </summary>
        /// <returns>Serialized client-challenge bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteByte(ResponseType);
            writer.WriteByte(HighResponseType);
            writer.WriteUInt16(0);
            writer.WriteUInt32(0);
            writer.WriteUInt64(Timestamp);
            writer.WriteBytes(ClientChallenge);
            writer.WriteUInt32(0);

            for (int index = 0; index < AvPairs.Length; index++)
            {
                writer.WriteBytes(AvPairs[index].ToByteArray());
            }

            writer.WriteUInt16((ushort)NtlmAvPairId.EndOfList);
            writer.WriteUInt16(0);
            writer.WriteBytes(TrailingBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse a client-challenge structure from a binary buffer.
        /// </summary>
        /// <param name="buffer">Serialized client-challenge bytes.</param>
        /// <returns>Parsed client-challenge value.</returns>
        public static NtlmV2ClientChallenge ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 32)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete NTLMv2 client-challenge structure.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            NtlmV2ClientChallenge challenge = new NtlmV2ClientChallenge
            {
                ResponseType = reader.ReadByte(),
                HighResponseType = reader.ReadByte()
            };

            reader.Skip(2);
            reader.Skip(4);
            challenge.Timestamp = reader.ReadUInt64();
            challenge.ClientChallenge = reader.ReadBytes(8);
            reader.Skip(4);

            List<NtlmAvPair> avPairs = new List<NtlmAvPair>();
            bool foundEndOfList = false;

            while (reader.RemainingBytes >= 4)
            {
                NtlmAvPair avPair = NtlmAvPair.ReadFrom(reader);

                if (avPair.AvId == NtlmAvPairId.EndOfList)
                {
                    if (avPair.Value.Length != 0)
                    {
                        throw new ProtocolEncodingException("The end-of-list AV pair must not carry a value.");
                    }

                    foundEndOfList = true;
                    break;
                }

                avPairs.Add(avPair);
            }

            if (!foundEndOfList)
            {
                throw new ProtocolEncodingException("The NTLMv2 client-challenge structure is missing the end-of-list AV pair.");
            }

            challenge.AvPairs = avPairs.ToArray();
            challenge.TrailingBytes = reader.ReadBytes(reader.RemainingBytes);
            return challenge;
        }

        private byte[] _ClientChallenge = new byte[8];
        private NtlmAvPair[] _AvPairs = Array.Empty<NtlmAvPair>();
        private byte[] _TrailingBytes = new byte[4];
    }
}

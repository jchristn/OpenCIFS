namespace OpenCIFS.Security
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using OpenCIFS.Protocol;

    /// <summary>
    /// NTLMSSP challenge message.
    /// </summary>
    public sealed class NtlmChallengeMessage
    {
        /// <summary>
        /// Challenge capability flags.
        /// </summary>
        public NtlmNegotiateFlags Flags { get; set; }

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
        /// Optional challenge target name.
        /// </summary>
        public string TargetName { get; set; } = string.Empty;

        /// <summary>
        /// Optional target-info AV pair list without the end-of-list marker.
        /// </summary>
        public NtlmAvPair[] TargetInfo { get; set; } = Array.Empty<NtlmAvPair>();

        /// <summary>
        /// Optional NTLM version bytes.
        /// </summary>
        public byte[]? Version { get; set; }

        /// <summary>
        /// Serialize the message to bytes.
        /// </summary>
        /// <returns>Serialized NTLM challenge bytes.</returns>
        public byte[] ToByteArray()
        {
            ValidateVersion(Version);

            NtlmNegotiateFlags effectiveFlags = Flags;
            Encoding encoding = NtlmMessageUtilities.GetTextEncoding(effectiveFlags);
            byte[] targetNameBytes = string.IsNullOrEmpty(TargetName) ? Array.Empty<byte>() : encoding.GetBytes(TargetName);
            byte[] targetInfoBytes = SerializeTargetInfo(TargetInfo);
            byte[] versionBytes = Version ?? Array.Empty<byte>();

            if (targetNameBytes.Length > 0)
            {
                effectiveFlags |= NtlmNegotiateFlags.RequestTarget;
            }

            if (targetInfoBytes.Length > 0)
            {
                effectiveFlags |= NtlmNegotiateFlags.TargetInfo;
            }

            uint payloadOffset = versionBytes.Length == 0 ? 48U : 56U;
            uint currentOffset = payloadOffset;

            LittleEndianWriter payloadWriter = new LittleEndianWriter();
            NtlmFieldDescriptor targetNameDescriptor = AppendPayload(payloadWriter, targetNameBytes, ref currentOffset);
            NtlmFieldDescriptor targetInfoDescriptor = AppendPayload(payloadWriter, targetInfoBytes, ref currentOffset);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            writer.WriteUInt32((uint)NtlmMessageType.Challenge);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, targetNameDescriptor.Length, targetNameDescriptor.Offset);
            writer.WriteUInt32((uint)effectiveFlags);
            writer.WriteBytes(ServerChallenge);
            writer.WriteUInt64(0);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, targetInfoDescriptor.Length, targetInfoDescriptor.Offset);
            writer.WriteBytes(versionBytes);
            writer.WriteBytes(payloadWriter.ToArray());
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the message from bytes.
        /// </summary>
        /// <param name="buffer">Serialized NTLM challenge bytes.</param>
        /// <returns>Parsed message.</returns>
        public static NtlmChallengeMessage ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            NtlmMessageUtilities.ValidateMessage(buffer, NtlmMessageType.Challenge, minimumLength: 48);

            NtlmNegotiateFlags flags = (NtlmNegotiateFlags)new LittleEndianReader(buffer.Slice(20, 4)).ReadUInt32();
            Encoding encoding = NtlmMessageUtilities.GetTextEncoding(flags);
            NtlmFieldDescriptor targetNameDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 12);
            NtlmFieldDescriptor targetInfoDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 40);
            int payloadOffset = NtlmMessageUtilities.GetPayloadOffset(buffer.Span, 12, 40);

            return new NtlmChallengeMessage
            {
                Flags = flags,
                ServerChallenge = buffer.Slice(24, 8).ToArray(),
                TargetName = NtlmMessageUtilities.ReadTextPayload(buffer, targetNameDescriptor, encoding),
                TargetInfo = ReadTargetInfo(NtlmMessageUtilities.ReadPayload(buffer, targetInfoDescriptor)),
                Version = payloadOffset >= 56 && buffer.Length >= 56 ? buffer.Slice(48, 8).ToArray() : null
            };
        }

        private static void ValidateVersion(byte[]? version)
        {
            if (version != null && version.Length != 0 && version.Length != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(version), "The NTLM challenge version field must be 8 bytes when present.");
            }
        }

        private static byte[] SerializeTargetInfo(IReadOnlyList<NtlmAvPair> pairs)
        {
            if (pairs == null || pairs.Count == 0)
            {
                return Array.Empty<byte>();
            }

            LittleEndianWriter writer = new LittleEndianWriter();

            for (int index = 0; index < pairs.Count; index++)
            {
                if (pairs[index] == null)
                {
                    throw new ArgumentException("TargetInfo cannot contain null AV pairs.", nameof(pairs));
                }

                writer.WriteBytes(pairs[index].ToByteArray());
            }

            writer.WriteUInt16((ushort)NtlmAvPairId.EndOfList);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        private static NtlmAvPair[] ReadTargetInfo(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length == 0)
            {
                return Array.Empty<NtlmAvPair>();
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            List<NtlmAvPair> pairs = new List<NtlmAvPair>();
            bool foundTerminator = false;

            while (reader.RemainingBytes >= 4)
            {
                NtlmAvPairId avId = (NtlmAvPairId)reader.ReadUInt16();
                ushort length = reader.ReadUInt16();
                byte[] value = reader.ReadBytes(length);

                if (avId == NtlmAvPairId.EndOfList)
                {
                    if (value.Length != 0)
                    {
                        throw new ProtocolEncodingException("The NTLM target-info terminator must not carry a value.");
                    }

                    foundTerminator = true;
                    break;
                }

                pairs.Add(new NtlmAvPair
                {
                    AvId = avId,
                    Value = value
                });
            }

            if (!foundTerminator)
            {
                throw new ProtocolEncodingException("The NTLM challenge target-info list is missing the end-of-list AV pair.");
            }

            if (reader.RemainingBytes != 0)
            {
                throw new ProtocolEncodingException("The NTLM challenge target-info list contains unsupported trailing bytes.");
            }

            return pairs.ToArray();
        }

        private static NtlmFieldDescriptor AppendPayload(LittleEndianWriter writer, byte[] value, ref uint currentOffset)
        {
            NtlmFieldDescriptor descriptor = new NtlmFieldDescriptor(
                length: checked((ushort)value.Length),
                offset: currentOffset);
            writer.WriteBytes(value);
            currentOffset += checked((uint)value.Length);
            return descriptor;
        }

        private byte[] _ServerChallenge = new byte[8];
    }
}

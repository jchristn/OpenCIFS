namespace OpenCIFS.Security
{
    using System;
    using System.Text;
    using OpenCIFS.Protocol;

    /// <summary>
    /// NTLMSSP authenticate message.
    /// </summary>
    public sealed class NtlmAuthenticateMessage
    {
        /// <summary>
        /// Negotiated capability flags.
        /// </summary>
        public NtlmNegotiateFlags Flags { get; set; }

        /// <summary>
        /// LM challenge response bytes.
        /// </summary>
        public byte[] LmChallengeResponse { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// NT challenge response bytes.
        /// </summary>
        public byte[] NtChallengeResponse { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Optional account domain name.
        /// </summary>
        public string DomainName { get; set; } = string.Empty;

        /// <summary>
        /// Account user name.
        /// </summary>
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// Optional client workstation name.
        /// </summary>
        public string Workstation { get; set; } = string.Empty;

        /// <summary>
        /// Optional encrypted random session key.
        /// </summary>
        public byte[] EncryptedRandomSessionKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Optional NTLM version bytes.
        /// </summary>
        public byte[]? Version { get; set; }

        /// <summary>
        /// Optional message-integrity code bytes.
        /// </summary>
        public byte[]? MessageIntegrityCode { get; set; }

        /// <summary>
        /// Whether to include a MIC field when serializing.
        /// </summary>
        public bool IncludeMessageIntegrityCodeField { get; set; }

        /// <summary>
        /// Offset of the parsed MIC field in the source message when present.
        /// </summary>
        public int MessageIntegrityCodeOffset { get; private set; }

        /// <summary>
        /// Serialize the message to bytes.
        /// </summary>
        /// <param name="zeroMessageIntegrityCode">Whether to zero the serialized MIC field.</param>
        /// <returns>Serialized NTLM authenticate bytes.</returns>
        public byte[] ToByteArray(bool zeroMessageIntegrityCode = false)
        {
            ValidateVersion(Version);
            ValidateMessageIntegrityCode(MessageIntegrityCode);

            NtlmNegotiateFlags effectiveFlags = Flags;
            Encoding encoding = NtlmMessageUtilities.GetTextEncoding(effectiveFlags);
            byte[] domainBytes = string.IsNullOrEmpty(DomainName) ? Array.Empty<byte>() : encoding.GetBytes(DomainName);
            byte[] userBytes = string.IsNullOrEmpty(UserName) ? Array.Empty<byte>() : encoding.GetBytes(UserName);
            byte[] workstationBytes = string.IsNullOrEmpty(Workstation) ? Array.Empty<byte>() : encoding.GetBytes(Workstation);
            byte[] versionBytes = Version ?? Array.Empty<byte>();
            bool includeMic = IncludeMessageIntegrityCodeField || (MessageIntegrityCode != null && MessageIntegrityCode.Length != 0);

            uint preambleLength = checked((uint)(versionBytes.Length + (includeMic ? 16 : 0)));
            uint currentOffset = 64U + preambleLength;
            LittleEndianWriter payloadWriter = new LittleEndianWriter();

            NtlmFieldDescriptor lmDescriptor = AppendPayload(payloadWriter, LmChallengeResponse, ref currentOffset);
            NtlmFieldDescriptor ntDescriptor = AppendPayload(payloadWriter, NtChallengeResponse, ref currentOffset);
            NtlmFieldDescriptor domainDescriptor = AppendPayload(payloadWriter, domainBytes, ref currentOffset);
            NtlmFieldDescriptor userDescriptor = AppendPayload(payloadWriter, userBytes, ref currentOffset);
            NtlmFieldDescriptor workstationDescriptor = AppendPayload(payloadWriter, workstationBytes, ref currentOffset);

            if (EncryptedRandomSessionKey.Length > 0)
            {
                effectiveFlags |= NtlmNegotiateFlags.KeyExchange;
            }

            NtlmFieldDescriptor sessionKeyDescriptor = AppendPayload(payloadWriter, EncryptedRandomSessionKey, ref currentOffset);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            writer.WriteUInt32((uint)NtlmMessageType.Authenticate);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, lmDescriptor.Length, lmDescriptor.Offset);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, ntDescriptor.Length, ntDescriptor.Offset);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, domainDescriptor.Length, domainDescriptor.Offset);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, userDescriptor.Length, userDescriptor.Offset);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, workstationDescriptor.Length, workstationDescriptor.Offset);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, sessionKeyDescriptor.Length, sessionKeyDescriptor.Offset);
            writer.WriteUInt32((uint)effectiveFlags);
            writer.WriteBytes(versionBytes);

            if (includeMic)
            {
                if (zeroMessageIntegrityCode || MessageIntegrityCode == null || MessageIntegrityCode.Length == 0)
                {
                    writer.WriteBytes(new byte[16]);
                }
                else
                {
                    writer.WriteBytes(MessageIntegrityCode);
                }
            }

            writer.WriteBytes(payloadWriter.ToArray());
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the message from bytes.
        /// </summary>
        /// <param name="buffer">Serialized NTLM authenticate bytes.</param>
        /// <returns>Parsed message.</returns>
        public static NtlmAuthenticateMessage ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            NtlmMessageUtilities.ValidateMessage(buffer, NtlmMessageType.Authenticate, minimumLength: 64);

            NtlmNegotiateFlags flags = (NtlmNegotiateFlags)new LittleEndianReader(buffer.Slice(60, 4)).ReadUInt32();
            Encoding encoding = NtlmMessageUtilities.GetTextEncoding(flags);
            NtlmFieldDescriptor lmDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 12);
            NtlmFieldDescriptor ntDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 20);
            NtlmFieldDescriptor domainDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 28);
            NtlmFieldDescriptor userDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 36);
            NtlmFieldDescriptor workstationDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 44);
            NtlmFieldDescriptor sessionKeyDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 52);
            int payloadOffset = NtlmMessageUtilities.GetPayloadOffset(buffer.Span, 12, 20, 28, 36, 44, 52);

            NtlmAuthenticateMessage message = new NtlmAuthenticateMessage
            {
                Flags = flags,
                LmChallengeResponse = NtlmMessageUtilities.ReadPayload(buffer, lmDescriptor),
                NtChallengeResponse = NtlmMessageUtilities.ReadPayload(buffer, ntDescriptor),
                DomainName = NtlmMessageUtilities.ReadTextPayload(buffer, domainDescriptor, encoding),
                UserName = NtlmMessageUtilities.ReadTextPayload(buffer, userDescriptor, encoding),
                Workstation = NtlmMessageUtilities.ReadTextPayload(buffer, workstationDescriptor, encoding),
                EncryptedRandomSessionKey = NtlmMessageUtilities.ReadPayload(buffer, sessionKeyDescriptor)
            };

            if (payloadOffset >= 88)
            {
                message.Version = buffer.Slice(64, 8).ToArray();
                message.MessageIntegrityCode = buffer.Slice(72, 16).ToArray();
                message.MessageIntegrityCodeOffset = 72;
                message.IncludeMessageIntegrityCodeField = true;
            }
            else if (payloadOffset >= 80)
            {
                message.MessageIntegrityCode = buffer.Slice(64, 16).ToArray();
                message.MessageIntegrityCodeOffset = 64;
                message.IncludeMessageIntegrityCodeField = true;
            }
            else if (payloadOffset >= 72 && payloadOffset != 80)
            {
                message.Version = buffer.Slice(64, 8).ToArray();
            }

            return message;
        }

        private static void ValidateVersion(byte[]? version)
        {
            if (version != null && version.Length != 0 && version.Length != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(version), "The NTLM authenticate version field must be 8 bytes when present.");
            }
        }

        private static void ValidateMessageIntegrityCode(byte[]? messageIntegrityCode)
        {
            if (messageIntegrityCode != null && messageIntegrityCode.Length != 0 && messageIntegrityCode.Length != 16)
            {
                throw new ArgumentOutOfRangeException(nameof(messageIntegrityCode), "The NTLM MIC field must be 16 bytes when present.");
            }
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
    }
}

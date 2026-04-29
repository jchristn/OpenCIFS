namespace OpenCIFS.Security
{
    using System;
    using System.Text;
    using OpenCIFS.Protocol;

    /// <summary>
    /// NTLMSSP negotiate message.
    /// </summary>
    public sealed class NtlmNegotiateMessage
    {
        /// <summary>
        /// Negotiated capability flags.
        /// </summary>
        public NtlmNegotiateFlags Flags { get; set; }

        /// <summary>
        /// Optional client domain name.
        /// </summary>
        public string DomainName { get; set; } = string.Empty;

        /// <summary>
        /// Optional client workstation name.
        /// </summary>
        public string Workstation { get; set; } = string.Empty;

        /// <summary>
        /// Optional NTLM version bytes.
        /// </summary>
        public byte[]? Version { get; set; }

        /// <summary>
        /// Serialize the message to bytes.
        /// </summary>
        /// <returns>Serialized NTLM negotiate bytes.</returns>
        public byte[] ToByteArray()
        {
            ValidateVersion(Version);

            NtlmNegotiateFlags effectiveFlags = Flags;
            Encoding encoding = NtlmMessageUtilities.GetTextEncoding(effectiveFlags);
            byte[] versionBytes = Version ?? Array.Empty<byte>();
            byte[] domainBytes = string.IsNullOrEmpty(DomainName) ? Array.Empty<byte>() : encoding.GetBytes(DomainName);
            byte[] workstationBytes = string.IsNullOrEmpty(Workstation) ? Array.Empty<byte>() : encoding.GetBytes(Workstation);

            if (domainBytes.Length > 0)
            {
                effectiveFlags |= NtlmNegotiateFlags.OemDomainNameSupplied;
            }

            if (workstationBytes.Length > 0)
            {
                effectiveFlags |= NtlmNegotiateFlags.OemWorkstationSupplied;
            }

            uint payloadOffset = versionBytes.Length == 0 ? 32U : 40U;
            uint currentOffset = payloadOffset;

            LittleEndianWriter payloadWriter = new LittleEndianWriter();
            NtlmFieldDescriptor domainDescriptor = AppendPayload(payloadWriter, domainBytes, ref currentOffset);
            NtlmFieldDescriptor workstationDescriptor = AppendPayload(payloadWriter, workstationBytes, ref currentOffset);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            writer.WriteUInt32((uint)NtlmMessageType.Negotiate);
            writer.WriteUInt32((uint)effectiveFlags);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, domainDescriptor.Length, domainDescriptor.Offset);
            NtlmMessageUtilities.WriteFieldDescriptor(writer, workstationDescriptor.Length, workstationDescriptor.Offset);
            writer.WriteBytes(versionBytes);
            writer.WriteBytes(payloadWriter.ToArray());
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the message from bytes.
        /// </summary>
        /// <param name="buffer">Serialized NTLM negotiate bytes.</param>
        /// <returns>Parsed message.</returns>
        public static NtlmNegotiateMessage ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            NtlmMessageUtilities.ValidateMessage(buffer, NtlmMessageType.Negotiate, minimumLength: 32);

            NtlmNegotiateFlags flags = (NtlmNegotiateFlags)new LittleEndianReader(buffer.Slice(12, 4)).ReadUInt32();
            Encoding encoding = NtlmMessageUtilities.GetTextEncoding(flags);
            NtlmFieldDescriptor domainDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 16);
            NtlmFieldDescriptor workstationDescriptor = NtlmMessageUtilities.ReadFieldDescriptor(buffer.Span, 24);
            int payloadOffset = NtlmMessageUtilities.GetPayloadOffset(buffer.Span, 16, 24);

            return new NtlmNegotiateMessage
            {
                Flags = flags,
                DomainName = NtlmMessageUtilities.ReadTextPayload(buffer, domainDescriptor, encoding),
                Workstation = NtlmMessageUtilities.ReadTextPayload(buffer, workstationDescriptor, encoding),
                Version = payloadOffset >= 40 && buffer.Length >= 40 ? buffer.Slice(32, 8).ToArray() : null
            };
        }

        private static void ValidateVersion(byte[]? version)
        {
            if (version != null && version.Length != 0 && version.Length != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(version), "The NTLM negotiate version field must be 8 bytes when present.");
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

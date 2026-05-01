namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// RESP_GET_DFS_REFERRAL payload.
    /// </summary>
    public sealed class DfsReferralResponse
    {
        private const int HeaderLength = 8;

        /// <summary>
        /// Number of bytes consumed from the request path.
        /// </summary>
        public ushort PathConsumed { get; set; }

        /// <summary>
        /// Referral-header flags.
        /// </summary>
        public DfsReferralHeaderFlags HeaderFlags { get; set; } = DfsReferralHeaderFlags.None;

        /// <summary>
        /// Returned referral entries.
        /// </summary>
        public DfsReferralEntryV2[] Entries { get; set; } = Array.Empty<DfsReferralEntryV2>();

        /// <summary>
        /// Serialize the response payload.
        /// </summary>
        /// <returns>Serialized bytes.</returns>
        public byte[] ToByteArray()
        {
            DfsReferralEntryV2[] entries = Entries ?? Array.Empty<DfsReferralEntryV2>();
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(PathConsumed);
            writer.WriteUInt16(checked((ushort)entries.Length));
            writer.WriteUInt32((uint)HeaderFlags);

            for (int index = 0; index < entries.Length; index++)
            {
                writer.WriteBytes(entries[index].ToByteArray());
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response payload.
        /// </summary>
        /// <param name="buffer">Serialized payload bytes.</param>
        /// <returns>Decoded response.</returns>
        public static DfsReferralResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < HeaderLength)
            {
                throw new ProtocolEncodingException("The DFS referral response payload is truncated.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort pathConsumed = reader.ReadUInt16();
            ushort numberOfReferrals = reader.ReadUInt16();
            DfsReferralHeaderFlags headerFlags = (DfsReferralHeaderFlags)reader.ReadUInt32();
            DfsReferralEntryV2[] entries = new DfsReferralEntryV2[numberOfReferrals];
            int offset = HeaderLength;

            for (int index = 0; index < numberOfReferrals; index++)
            {
                entries[index] = DfsReferralEntryV2.ReadFrom(buffer, offset, out offset);
            }

            return new DfsReferralResponse
            {
                PathConsumed = pathConsumed,
                HeaderFlags = headerFlags,
                Entries = entries
            };
        }
    }
}

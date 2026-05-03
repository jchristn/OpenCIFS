namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// RESP_GET_DFS_REFERRAL payload supporting bounded V2 and V3/V4 entry shapes per
    /// MS-DFSC section 2.2.5.
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
        /// Bounded V2 referral entries.
        /// </summary>
        public IList<DfsReferralEntryV2> EntriesV2
        {
            get
            {
                return _EntriesV2;
            }
        }

        /// <summary>
        /// Bounded V3/V4 referral entries.
        /// </summary>
        public IList<DfsReferralEntryV3> EntriesV3
        {
            get
            {
                return _EntriesV3;
            }
        }

        /// <summary>
        /// Legacy V2 entries view used by callers that only handle the V2 shape. Reading the
        /// property returns the current <see cref="EntriesV2" /> contents as an array; assigning
        /// replaces the V2 list while leaving <see cref="EntriesV3" /> untouched.
        /// </summary>
        public DfsReferralEntryV2[] Entries
        {
            get
            {
                DfsReferralEntryV2[] copy = new DfsReferralEntryV2[_EntriesV2.Count];

                for (int index = 0; index < _EntriesV2.Count; index++)
                {
                    copy[index] = _EntriesV2[index];
                }

                return copy;
            }
            set
            {
                _EntriesV2.Clear();

                if (value == null)
                {
                    return;
                }

                for (int index = 0; index < value.Length; index++)
                {
                    _EntriesV2.Add(value[index]);
                }
            }
        }

        /// <summary>
        /// Serialize the response payload.
        /// </summary>
        /// <returns>Serialized bytes.</returns>
        public byte[] ToByteArray()
        {
            int totalEntries = _EntriesV2.Count + _EntriesV3.Count;
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(PathConsumed);
            writer.WriteUInt16(checked((ushort)totalEntries));
            writer.WriteUInt32((uint)HeaderFlags);

            for (int index = 0; index < _EntriesV2.Count; index++)
            {
                writer.WriteBytes(_EntriesV2[index].ToByteArray());
            }

            for (int index = 0; index < _EntriesV3.Count; index++)
            {
                writer.WriteBytes(_EntriesV3[index].ToByteArray());
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
            DfsReferralResponse response = new DfsReferralResponse
            {
                PathConsumed = pathConsumed,
                HeaderFlags = headerFlags
            };

            int offset = HeaderLength;

            for (int index = 0; index < numberOfReferrals; index++)
            {
                if (offset + 2 > buffer.Length)
                {
                    throw new ProtocolEncodingException("The DFS referral entry header is truncated.");
                }

                ushort versionNumber = (ushort)(buffer.Span[offset] | (buffer.Span[offset + 1] << 8));

                if (versionNumber == 2)
                {
                    response._EntriesV2.Add(DfsReferralEntryV2.ReadFrom(buffer, offset, out offset));
                }
                else if (versionNumber == 3 || versionNumber == 4)
                {
                    response._EntriesV3.Add(DfsReferralEntryV3.ReadFrom(buffer, offset, out offset));
                }
                else
                {
                    throw new ProtocolEncodingException("The DFS referral entry version is not supported by the bounded codec.");
                }
            }

            return response;
        }

        private readonly List<DfsReferralEntryV2> _EntriesV2 = new List<DfsReferralEntryV2>();
        private readonly List<DfsReferralEntryV3> _EntriesV3 = new List<DfsReferralEntryV3>();
    }
}

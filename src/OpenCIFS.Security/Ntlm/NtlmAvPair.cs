namespace OpenCIFS.Security
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Represents a single NTLM AV pair.
    /// </summary>
    public sealed class NtlmAvPair
    {
        /// <summary>
        /// AV pair identifier.
        /// </summary>
        public NtlmAvPairId AvId { get; set; } = NtlmAvPairId.EndOfList;

        /// <summary>
        /// AV pair value bytes.
        /// </summary>
        public byte[] Value
        {
            get
            {
                return _Value;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Value), "Value cannot be null.");
                }

                if (AvId == NtlmAvPairId.EndOfList && value.Length != 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(Value), "The end-of-list AV pair must not carry a value.");
                }

                _Value = value;
            }
        }

        /// <summary>
        /// Serialize the AV pair to its wire format.
        /// </summary>
        /// <returns>Serialized AV pair bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16((ushort)AvId);
            writer.WriteUInt16((ushort)Value.Length);
            writer.WriteBytes(Value);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an AV pair from a reader positioned at the AV pair header.
        /// </summary>
        /// <param name="reader">Binary reader.</param>
        /// <returns>Parsed AV pair.</returns>
        internal static NtlmAvPair ReadFrom(LittleEndianReader reader)
        {
            NtlmAvPairId avId = (NtlmAvPairId)reader.ReadUInt16();
            ushort length = reader.ReadUInt16();
            byte[] value = reader.ReadBytes(length);
            return new NtlmAvPair
            {
                AvId = avId,
                Value = value
            };
        }

        private byte[] _Value = Array.Empty<byte>();
    }
}

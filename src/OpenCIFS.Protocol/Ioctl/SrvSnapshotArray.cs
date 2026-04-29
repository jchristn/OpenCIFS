namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// SRV_SNAPSHOT_ARRAY payload returned by FSCTL_SRV_ENUMERATE_SNAPSHOTS.
    /// </summary>
    public sealed class SrvSnapshotArray
    {
        private const int FixedBodyLength = 12;

        /// <summary>
        /// Number of snapshots available on the share backing the open.
        /// </summary>
        public uint NumberOfSnapshots { get; set; }

        /// <summary>
        /// Snapshot tokens returned in the response.
        /// </summary>
        public string[] Snapshots
        {
            get
            {
                return _Snapshots;
            }
            set
            {
                _Snapshots = value ?? throw new ArgumentNullException(nameof(Snapshots), "Snapshots cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the snapshot array to wire format.
        /// </summary>
        /// <returns>Serialized bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] snapshotsBytes = EncodeMultiSz(Snapshots);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(NumberOfSnapshots);
            writer.WriteUInt32((uint)Snapshots.Length);
            writer.WriteUInt32((uint)snapshotsBytes.Length);
            writer.WriteBytes(snapshotsBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the snapshot array from wire format.
        /// </summary>
        /// <param name="buffer">Wire-format bytes.</param>
        /// <returns>Parsed snapshot array.</returns>
        public static SrvSnapshotArray ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SRV_SNAPSHOT_ARRAY structure.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            SrvSnapshotArray array = new SrvSnapshotArray
            {
                NumberOfSnapshots = reader.ReadUInt32()
            };
            uint numberOfSnapshotsReturned = reader.ReadUInt32();
            uint snapshotArraySize = reader.ReadUInt32();

            if (snapshotArraySize > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SRV_SNAPSHOT_ARRAY snapshot payload exceeds the supported maximum.");
            }

            int snapshotArrayLength = checked((int)snapshotArraySize);

            if (snapshotArrayLength < 4 || (snapshotArrayLength % 2) != 0)
            {
                throw new ProtocolEncodingException("The SRV_SNAPSHOT_ARRAY snapshot payload must be valid UTF-16 and include the terminating double null.");
            }

            if (FixedBodyLength + snapshotArrayLength != buffer.Length)
            {
                throw new ProtocolEncodingException("The SRV_SNAPSHOT_ARRAY snapshot payload length does not match the available buffer.");
            }

            byte[] snapshotBytes = reader.ReadBytes(snapshotArrayLength);
            array.Snapshots = DecodeMultiSz(snapshotBytes);

            if (numberOfSnapshotsReturned != array.Snapshots.Length)
            {
                throw new ProtocolEncodingException("The SRV_SNAPSHOT_ARRAY returned-count field does not match the parsed snapshot token count.");
            }

            if (array.NumberOfSnapshots < numberOfSnapshotsReturned)
            {
                throw new ProtocolEncodingException("The SRV_SNAPSHOT_ARRAY total snapshot count cannot be less than the returned snapshot count.");
            }

            return array;
        }

        private static byte[] EncodeMultiSz(IReadOnlyList<string> snapshots)
        {
            if (snapshots.Count == 0)
            {
                return new byte[4];
            }

            StringBuilder builder = new StringBuilder();

            for (int index = 0; index < snapshots.Count; index++)
            {
                string snapshot = snapshots[index] ?? throw new ProtocolValidationException("SRV_SNAPSHOT_ARRAY entries cannot be null.", nameof(snapshots));
                builder.Append(snapshot);
                builder.Append('\0');
            }

            builder.Append('\0');
            return Encoding.Unicode.GetBytes(builder.ToString());
        }

        private static string[] DecodeMultiSz(byte[] snapshotBytes)
        {
            string decoded = Encoding.Unicode.GetString(snapshotBytes);

            if (decoded.Length < 2 || decoded[decoded.Length - 1] != '\0' || decoded[decoded.Length - 2] != '\0')
            {
                throw new ProtocolEncodingException("The SRV_SNAPSHOT_ARRAY snapshot payload must end with a double null terminator.");
            }

            string[] tokens = decoded.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);

            for (int index = 0; index < tokens.Length; index++)
            {
                if (!tokens[index].StartsWith("@GMT-", StringComparison.Ordinal))
                {
                    throw new ProtocolEncodingException("The SRV_SNAPSHOT_ARRAY contains a snapshot token with an invalid format.");
                }
            }

            return tokens;
        }

        private string[] _Snapshots = Array.Empty<string>();
    }
}

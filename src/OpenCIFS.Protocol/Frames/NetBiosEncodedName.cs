namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// NetBIOS name in the wire-encoded first-level form per RFC 1001 section 4.2.1.2.
    /// </summary>
    /// <remarks>
    /// Each of the 16 raw NetBIOS-name bytes is split into two nibbles and each nibble is
    /// added to <c>'A'</c> (<c>0x41</c>) so the encoded form is 32 ASCII letters from
    /// <c>A</c> through <c>P</c>. The wire form prepends a single length byte of <c>0x20</c>
    /// and appends a single zero byte representing an empty NetBIOS scope, for a total
    /// length of 34 bytes per encoded name.
    /// </remarks>
    public sealed class NetBiosEncodedName
    {
        /// <summary>
        /// Total wire length in bytes (length byte + 32 encoded chars + scope terminator).
        /// </summary>
        public const int WireLength = 34;

        private const byte EncodedLengthMarker = 0x20;
        private const int RawNameLength = 16;
        private const int EncodedNameLength = 32;

        /// <summary>
        /// Pad byte appended to NetBIOS service names shorter than 15 bytes.
        /// </summary>
        public const byte ServiceNamePadByte = 0x20;

        /// <summary>
        /// Service-byte suffix for the file-server NetBIOS service (<c>0x20</c>).
        /// </summary>
        public const byte FileServerServiceSuffix = 0x20;

        /// <summary>
        /// Service-byte suffix for the workstation NetBIOS service (<c>0x00</c>).
        /// </summary>
        public const byte WorkstationServiceSuffix = 0x00;

        /// <summary>
        /// Raw 16-byte NetBIOS name.
        /// </summary>
        public byte[] RawName
        {
            get
            {
                return _RawName;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(RawName), "RawName cannot be null.");
                }

                if (value.Length != RawNameLength)
                {
                    throw new ArgumentException("RawName must be exactly 16 bytes.", nameof(RawName));
                }

                _RawName = value;
            }
        }

        /// <summary>
        /// Build an encoded name from a service name and a 1-byte service suffix.
        /// </summary>
        /// <param name="serviceName">ASCII service name. Up to 15 bytes; padded with <c>0x20</c>.</param>
        /// <param name="serviceSuffix">Service byte appended after the padded name.</param>
        /// <returns>Encoded NetBIOS name.</returns>
        public static NetBiosEncodedName FromServiceName(string serviceName, byte serviceSuffix)
        {
            if (serviceName == null)
            {
                throw new ArgumentNullException(nameof(serviceName), "serviceName cannot be null.");
            }

            byte[] serviceBytes = Encoding.ASCII.GetBytes(serviceName);

            if (serviceBytes.Length > RawNameLength - 1)
            {
                throw new ArgumentOutOfRangeException(nameof(serviceName), "NetBIOS service names cannot exceed 15 ASCII bytes.");
            }

            byte[] rawName = new byte[RawNameLength];

            for (int index = 0; index < rawName.Length - 1; index++)
            {
                rawName[index] = index < serviceBytes.Length ? serviceBytes[index] : ServiceNamePadByte;
            }

            rawName[RawNameLength - 1] = serviceSuffix;

            return new NetBiosEncodedName
            {
                RawName = rawName
            };
        }

        /// <summary>
        /// Serialize the encoded name to its 34-byte wire form.
        /// </summary>
        /// <returns>Wire bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] result = new byte[WireLength];
            result[0] = EncodedLengthMarker;

            for (int index = 0; index < RawNameLength; index++)
            {
                byte value = _RawName[index];
                result[1 + (index * 2)] = (byte)('A' + ((value >> 4) & 0x0F));
                result[1 + (index * 2) + 1] = (byte)('A' + (value & 0x0F));
            }

            result[WireLength - 1] = 0;
            return result;
        }

        /// <summary>
        /// Parse an encoded NetBIOS name from its 34-byte wire form.
        /// </summary>
        /// <param name="buffer">Wire bytes.</param>
        /// <returns>Decoded name.</returns>
        public static NetBiosEncodedName ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < WireLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete encoded NetBIOS name.");
            }

            ReadOnlySpan<byte> span = buffer.Span;

            if (span[0] != EncodedLengthMarker)
            {
                throw new ProtocolEncodingException("The encoded NetBIOS name length marker must be 0x20.");
            }

            if (span[WireLength - 1] != 0)
            {
                throw new ProtocolEncodingException("The encoded NetBIOS name scope terminator must be a single zero byte.");
            }

            byte[] rawName = new byte[RawNameLength];

            for (int index = 0; index < RawNameLength; index++)
            {
                int high = span[1 + (index * 2)] - 'A';
                int low = span[1 + (index * 2) + 1] - 'A';

                if (high < 0 || high > 0x0F || low < 0 || low > 0x0F)
                {
                    throw new ProtocolEncodingException("The encoded NetBIOS name contains characters outside A-P.");
                }

                rawName[index] = (byte)((high << 4) | low);
            }

            return new NetBiosEncodedName
            {
                RawName = rawName
            };
        }

        private byte[] _RawName = new byte[RawNameLength];
    }
}

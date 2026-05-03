namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// Bounded DFS_GET_REFERRALS_EX request payload per MS-DFSC section 2.2.3.
    /// </summary>
    /// <remarks>
    /// Used by SMB 3.0+ DFS clients to convey extended request data (currently the requesting
    /// client's site name) along with the DFS namespace path. The request layout is:
    /// MaxReferralLevel (2) + RequestFlags (2) + RequestDataLength (4) + RequestData. The bounded
    /// codec carries the SiteName form when <see cref="IncludeSiteName" /> is set per the
    /// <c>REQ_GET_DFS_REFERRAL_EX_FLAG_SITE_NAME</c> flag.
    /// </remarks>
    public sealed class DfsReferralRequestEx
    {
        /// <summary>
        /// Maximum DFS referral version the requester can decode (typically 1 through 4).
        /// </summary>
        public ushort MaxReferralLevel { get; set; } = 4;

        /// <summary>
        /// When set, <see cref="SiteName" /> is included in the request data. Maps to the
        /// <c>REQ_GET_DFS_REFERRAL_EX_FLAG_SITE_NAME</c> bit (0x0001).
        /// </summary>
        public bool IncludeSiteName { get; set; }

        /// <summary>
        /// Number of bytes the client has already consumed from <see cref="RequestFileName" /> while
        /// resolving an earlier referral. Always 0 on the initial request.
        /// </summary>
        public ushort PathConsumed { get; set; }

        /// <summary>
        /// DFS namespace path being resolved.
        /// </summary>
        public string RequestFileName
        {
            get
            {
                return _RequestFileName;
            }
            set
            {
                _RequestFileName = value ?? throw new ArgumentNullException(nameof(RequestFileName), "RequestFileName cannot be null.");
            }
        }

        /// <summary>
        /// Site name carried when <see cref="IncludeSiteName" /> is set. Empty otherwise.
        /// </summary>
        public string SiteName
        {
            get
            {
                return _SiteName;
            }
            set
            {
                _SiteName = value ?? throw new ArgumentNullException(nameof(SiteName), "SiteName cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the EX request to its wire form.
        /// </summary>
        /// <returns>Wire bytes.</returns>
        public byte[] ToByteArray()
        {
            if (string.IsNullOrEmpty(RequestFileName))
            {
                throw new ArgumentNullException(nameof(RequestFileName), "RequestFileName cannot be empty.");
            }

            byte[] requestFileNameBytes = Encoding.Unicode.GetBytes(RequestFileName + '\0');
            byte[] siteNameBytes = IncludeSiteName ? Encoding.Unicode.GetBytes(SiteName + '\0') : Array.Empty<byte>();
            int requestDataLength = sizeof(ushort) + sizeof(ushort) + requestFileNameBytes.Length;

            if (IncludeSiteName)
            {
                requestDataLength += sizeof(ushort) + siteNameBytes.Length;
            }

            ushort requestFlags = (ushort)(IncludeSiteName ? 0x0001 : 0x0000);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(MaxReferralLevel);
            writer.WriteUInt16(requestFlags);
            writer.WriteUInt32((uint)requestDataLength);
            writer.WriteUInt16(PathConsumed);
            writer.WriteUInt16((ushort)requestFileNameBytes.Length);
            writer.WriteBytes(requestFileNameBytes);

            if (IncludeSiteName)
            {
                writer.WriteUInt16((ushort)siteNameBytes.Length);
                writer.WriteBytes(siteNameBytes);
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse an EX request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Wire bytes.</param>
        /// <returns>Parsed request.</returns>
        public static DfsReferralRequestEx ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = sizeof(ushort) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + sizeof(ushort);

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete DFS_GET_REFERRALS_EX request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort maxReferralLevel = reader.ReadUInt16();
            ushort requestFlags = reader.ReadUInt16();
            uint requestDataLength = reader.ReadUInt32();

            if (requestDataLength > (uint)reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The DFS_GET_REFERRALS_EX RequestDataLength exceeds the buffer.");
            }

            bool includeSiteName = (requestFlags & 0x0001) != 0;
            ushort pathConsumed = reader.ReadUInt16();
            ushort requestFileNameLength = reader.ReadUInt16();

            if (requestFileNameLength > reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The DFS_GET_REFERRALS_EX RequestFileNameLength exceeds the buffer.");
            }

            byte[] requestFileNameBytes = reader.ReadBytes(requestFileNameLength);
            string requestFileName = StripTrailingNullUnicode(requestFileNameBytes);
            string siteName = string.Empty;

            if (includeSiteName)
            {
                if (reader.RemainingBytes < sizeof(ushort))
                {
                    throw new ProtocolEncodingException("The DFS_GET_REFERRALS_EX request is missing the SiteName length.");
                }

                ushort siteNameLength = reader.ReadUInt16();

                if (siteNameLength > reader.RemainingBytes)
                {
                    throw new ProtocolEncodingException("The DFS_GET_REFERRALS_EX SiteNameLength exceeds the buffer.");
                }

                byte[] siteNameBytes = reader.ReadBytes(siteNameLength);
                siteName = StripTrailingNullUnicode(siteNameBytes);
            }

            return new DfsReferralRequestEx
            {
                MaxReferralLevel = maxReferralLevel,
                IncludeSiteName = includeSiteName,
                PathConsumed = pathConsumed,
                RequestFileName = requestFileName,
                SiteName = siteName
            };
        }

        private static string StripTrailingNullUnicode(byte[] bytes)
        {
            int length = bytes.Length;

            if (length >= 2 && bytes[length - 1] == 0 && bytes[length - 2] == 0)
            {
                length -= 2;
            }

            return length > 0 ? Encoding.Unicode.GetString(bytes, 0, length) : string.Empty;
        }

        private string _RequestFileName = string.Empty;
        private string _SiteName = string.Empty;
    }
}

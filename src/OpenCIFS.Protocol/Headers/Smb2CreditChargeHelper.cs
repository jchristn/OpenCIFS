namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Helpers for the bounded SMB2 credit-charge and large-I/O slices.
    /// </summary>
    public static class Smb2CreditChargeHelper
    {
        /// <summary>
        /// SMB2 bytes represented by a single credit.
        /// </summary>
        public const uint BytesPerCredit = 65536;

        /// <summary>
        /// Bounded large-I/O size currently implemented for SMB 2.1 read and write.
        /// </summary>
        public const uint ImplementedLargeReadWriteSize = 1048576;

        /// <summary>
        /// Get the implemented maximum read or write size for the supplied dialect.
        /// </summary>
        /// <param name="dialect">Negotiated or effective dialect.</param>
        /// <returns>Implemented maximum request size.</returns>
        public static uint GetImplementedReadWriteSize(SmbDialect dialect)
        {
            return dialect >= SmbDialect.Smb21
                ? ImplementedLargeReadWriteSize
                : BytesPerCredit;
        }

        /// <summary>
        /// Calculate the required SMB2 request-credit count for a read or write length.
        /// </summary>
        /// <param name="dialect">Negotiated or effective dialect.</param>
        /// <param name="length">Requested read or write length.</param>
        /// <returns>Credits required to carry the request.</returns>
        public static ushort GetRequiredReadWriteCredits(SmbDialect? dialect, uint length)
        {
            if (!dialect.HasValue || dialect.Value < SmbDialect.Smb21)
            {
                return 1;
            }

            if (length <= BytesPerCredit)
            {
                return 1;
            }

            uint credits = checked((length + BytesPerCredit - 1U) / BytesPerCredit);
            return checked((ushort)Math.Clamp((int)credits, 1, UInt16.MaxValue));
        }

        /// <summary>
        /// Calculate the SMB2 header credit charge for a read or write length.
        /// </summary>
        /// <param name="dialect">Negotiated or effective dialect.</param>
        /// <param name="length">Requested read or write length.</param>
        /// <returns>Header credit charge.</returns>
        public static ushort GetReadWriteCreditCharge(SmbDialect? dialect, uint length)
        {
            ushort credits = GetRequiredReadWriteCredits(dialect, length);
            return credits <= 1 ? (ushort)0 : credits;
        }
    }
}

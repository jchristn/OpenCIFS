namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Maps planned OpenCIFS dialect identifiers to SMB2/3 wire values.
    /// </summary>
    public static class SmbDialectCatalog
    {
        /// <summary>
        /// Convert an OpenCIFS dialect identifier to its SMB2/3 wire value.
        /// </summary>
        /// <param name="dialect">Dialect identifier.</param>
        /// <returns>SMB2/3 wire value.</returns>
        public static ushort ToSmb2WireDialect(SmbDialect dialect)
        {
            switch (dialect)
            {
                case SmbDialect.Smb2002:
                    return 0x0202;
                case SmbDialect.Smb21:
                    return 0x0210;
                case SmbDialect.Smb30:
                    return 0x0300;
                case SmbDialect.Smb302:
                    return 0x0302;
                case SmbDialect.Smb311:
                    return 0x0311;
                default:
                    throw new ArgumentOutOfRangeException(nameof(dialect), "The supplied dialect does not have an SMB2/3 wire value.");
            }
        }

        /// <summary>
        /// Try to map an SMB2/3 wire dialect value to an OpenCIFS dialect identifier.
        /// </summary>
        /// <param name="wireDialect">SMB2/3 wire dialect value.</param>
        /// <param name="dialect">Resolved dialect identifier.</param>
        /// <returns><c>true</c> when the wire value is recognized.</returns>
        public static bool TryFromSmb2WireDialect(ushort wireDialect, out SmbDialect dialect)
        {
            switch (wireDialect)
            {
                case 0x0202:
                    dialect = SmbDialect.Smb2002;
                    return true;
                case 0x0210:
                    dialect = SmbDialect.Smb21;
                    return true;
                case 0x0300:
                    dialect = SmbDialect.Smb30;
                    return true;
                case 0x0302:
                    dialect = SmbDialect.Smb302;
                    return true;
                case 0x0311:
                    dialect = SmbDialect.Smb311;
                    return true;
                default:
                    dialect = default;
                    return false;
            }
        }

        /// <summary>
        /// Get the SMB2/3 dialects that fall within an inclusive range.
        /// </summary>
        /// <param name="minimumDialect">Minimum inclusive dialect.</param>
        /// <param name="maximumDialect">Maximum inclusive dialect.</param>
        /// <returns>Ordered dialects in ascending wire-generation order.</returns>
        public static SmbDialect[] GetSmb2DialectsInRange(SmbDialect minimumDialect, SmbDialect maximumDialect)
        {
            if (maximumDialect < minimumDialect)
            {
                throw new ArgumentException("MaximumDialect must be greater than or equal to MinimumDialect.", nameof(maximumDialect));
            }

            List<SmbDialect> dialects = new List<SmbDialect>();

            for (SmbDialect dialect = SmbDialect.Smb2002; dialect <= SmbDialect.Smb311; dialect++)
            {
                if (dialect < minimumDialect || dialect > maximumDialect)
                {
                    continue;
                }

                dialects.Add(dialect);
            }

            return dialects.ToArray();
        }

        /// <summary>
        /// Select the highest common SMB2/3 dialect between a client offer and a server range.
        /// </summary>
        /// <param name="clientDialects">Client-offered dialects.</param>
        /// <param name="minimumServerDialect">Server minimum inclusive dialect.</param>
        /// <param name="maximumServerDialect">Server maximum inclusive dialect.</param>
        /// <param name="negotiatedDialect">Selected dialect when one is found.</param>
        /// <returns><c>true</c> when a common dialect exists.</returns>
        public static bool TrySelectHighestCommonSmb2Dialect(ReadOnlySpan<SmbDialect> clientDialects, SmbDialect minimumServerDialect, SmbDialect maximumServerDialect, out SmbDialect negotiatedDialect)
        {
            if (maximumServerDialect < minimumServerDialect)
            {
                throw new ArgumentException("MaximumServerDialect must be greater than or equal to MinimumServerDialect.", nameof(maximumServerDialect));
            }

            for (SmbDialect candidate = maximumServerDialect; candidate >= minimumServerDialect; candidate--)
            {
                if (candidate == SmbDialect.Cifs10)
                {
                    continue;
                }

                if (ContainsDialect(clientDialects, candidate))
                {
                    negotiatedDialect = candidate;
                    return true;
                }
            }

            negotiatedDialect = default;
            return false;
        }

        private static bool ContainsDialect(ReadOnlySpan<SmbDialect> dialects, SmbDialect dialect)
        {
            for (int index = 0; index < dialects.Length; index++)
            {
                if (dialects[index] == dialect)
                {
                    return true;
                }
            }

            return false;
        }
    }
}

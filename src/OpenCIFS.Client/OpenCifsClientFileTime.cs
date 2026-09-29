namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Shared FILETIME conversion helpers for the primary client surface.
    /// </summary>
    internal static class OpenCifsClientFileTime
    {
        /// <summary>
        /// Convert a wire FILETIME value into a UTC timestamp, treating zero and out-of-range values as unspecified.
        /// </summary>
        /// <param name="value">FILETIME value from the server.</param>
        /// <returns>UTC timestamp, or null when the server did not report a usable value.</returns>
        internal static DateTime? ToUtcDateTimeOrNull(ulong value)
        {
            if (value == 0 || value > Int64.MaxValue)
            {
                return null;
            }

            try
            {
                return DateTime.FromFileTimeUtc((long)value);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        /// <summary>
        /// Convert a timestamp into a wire FILETIME value, treating unspecified kinds as UTC.
        /// </summary>
        /// <param name="value">Timestamp.</param>
        /// <returns>FILETIME value.</returns>
        internal static ulong ToFileTimeUtc(DateTime value)
        {
            DateTime utcValue = value.Kind switch
            {
                DateTimeKind.Utc => value,
                DateTimeKind.Local => value.ToUniversalTime(),
                _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
            };

            return unchecked((ulong)utcValue.ToFileTimeUtc());
        }
    }
}

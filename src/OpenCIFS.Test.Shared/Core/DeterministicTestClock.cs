namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Globalization;
    using System.Text;

    /// <summary>
    /// Shared deterministic timestamp helpers for repeatable OpenCIFS test vectors.
    /// </summary>
    public static class DeterministicTestClock
    {
        private static readonly DateTimeOffset _BaseUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        /// <summary>
        /// Resolve a deterministic UTC timestamp for a stable test key.
        /// </summary>
        /// <param name="key">Stable key.</param>
        /// <param name="sequence">Optional deterministic sequence number.</param>
        /// <returns>Deterministic UTC timestamp.</returns>
        public static DateTimeOffset GetUtc(string key, int sequence = 0)
        {
            if (String.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException(nameof(key), "Clock key cannot be null or whitespace.");
            }

            if (sequence < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sequence), "Sequence must be non-negative.");
            }

            string compositeKey = key + "#" + sequence.ToString(CultureInfo.InvariantCulture);
            ulong hash = ComputeFnv1a64(compositeKey);
            long secondOffset = (long)(hash % (365UL * 24UL * 60UL * 60UL));
            return _BaseUtc.AddSeconds(secondOffset);
        }

        /// <summary>
        /// Resolve a deterministic file-time timestamp for a stable test key.
        /// </summary>
        /// <param name="key">Stable key.</param>
        /// <param name="sequence">Optional deterministic sequence number.</param>
        /// <returns>Deterministic UTC file time.</returns>
        public static ulong GetFileTimeUtc(string key, int sequence = 0)
        {
            return unchecked((ulong)GetUtc(key, sequence).UtcDateTime.ToFileTimeUtc());
        }

        private static ulong ComputeFnv1a64(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            ulong hash = 14695981039346656037UL;

            for (int index = 0; index < bytes.Length; index++)
            {
                hash ^= bytes[index];
                hash *= 1099511628211UL;
            }

            return hash;
        }
    }
}

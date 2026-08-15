namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Globalization;
    using System.Text;

    /// <summary>
    /// Stable cross-process hash helpers for deterministic OpenCIFS test inputs.
    /// </summary>
    public static class DeterministicTestHash
    {
        /// <summary>
        /// Compute a stable 32-bit hash for the supplied key.
        /// </summary>
        /// <param name="key">Stable key.</param>
        /// <returns>Stable 32-bit hash.</returns>
        public static int ComputeInt32(string key)
        {
            if (String.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentNullException(nameof(key), "Hash key cannot be null or whitespace.");
            }

            byte[] bytes = Encoding.UTF8.GetBytes(key);
            uint hash = 2166136261U;

            for (int index = 0; index < bytes.Length; index++)
            {
                hash ^= bytes[index];
                hash *= 16777619U;
            }

            return unchecked((int)hash);
        }

        /// <summary>
        /// Compute a stable 32-bit hash for the supplied key and sequence value.
        /// </summary>
        /// <param name="key">Stable key.</param>
        /// <param name="sequence">Sequence value.</param>
        /// <returns>Stable 32-bit hash.</returns>
        public static int ComputeInt32(string key, int sequence)
        {
            return ComputeInt32(key + "#" + sequence.ToString(CultureInfo.InvariantCulture));
        }
    }
}

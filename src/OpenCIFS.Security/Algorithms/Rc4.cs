namespace OpenCIFS.Security
{
    using System;

    /// <summary>
    /// RC4 stream cipher used by NTLM key exchange.
    /// </summary>
    public static class Rc4
    {
        /// <summary>
        /// Apply RC4 to the supplied payload.
        /// </summary>
        /// <param name="key">RC4 key bytes.</param>
        /// <param name="data">Payload bytes.</param>
        /// <returns>Transformed bytes.</returns>
        public static byte[] Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        {
            if (key.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(key), "RC4 requires a non-empty key.");
            }

            byte[] state = new byte[256];

            for (int index = 0; index < state.Length; index++)
            {
                state[index] = (byte)index;
            }

            int swapIndex = 0;

            for (int index = 0; index < state.Length; index++)
            {
                swapIndex = (swapIndex + state[index] + key[index % key.Length]) & 0xFF;
                (state[index], state[swapIndex]) = (state[swapIndex], state[index]);
            }

            byte[] output = new byte[data.Length];
            int i = 0;
            int j = 0;

            for (int index = 0; index < data.Length; index++)
            {
                i = (i + 1) & 0xFF;
                j = (j + state[i]) & 0xFF;
                (state[i], state[j]) = (state[j], state[i]);
                byte keyByte = state[(state[i] + state[j]) & 0xFF];
                output[index] = (byte)(data[index] ^ keyByte);
            }

            return output;
        }
    }
}

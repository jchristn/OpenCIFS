namespace OpenCIFS.Security
{
    using System.Buffers.Binary;

    /// <summary>
    /// Computes MD4 message digests for NTLM credential hashing.
    /// </summary>
    public static class Md4
    {
        /// <summary>
        /// Compute an MD4 digest for the supplied message bytes.
        /// </summary>
        /// <param name="message">Message bytes.</param>
        /// <returns>Sixteen-byte MD4 digest.</returns>
        public static byte[] HashData(ReadOnlySpan<byte> message)
        {
            uint a = 0x67452301U;
            uint b = 0xEFCDAB89U;
            uint c = 0x98BADCFEU;
            uint d = 0x10325476U;

            ulong messageBitLength = checked((ulong)message.Length * 8UL);
            int paddingLength = CalculatePaddingLength(message.Length);
            byte[] buffer = new byte[message.Length + 1 + paddingLength + 8];
            message.CopyTo(buffer);
            buffer[message.Length] = 0x80;
            BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(buffer.Length - 8), messageBitLength);
            Span<uint> block = stackalloc uint[16];

            for (int offset = 0; offset < buffer.Length; offset += 64)
            {
                for (int index = 0; index < block.Length; index++)
                {
                    block[index] = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset + (index * 4), 4));
                }

                uint aa = a;
                uint bb = b;
                uint cc = c;
                uint dd = d;

                Round1(ref a, b, c, d, block[0], 3);
                Round1(ref d, a, b, c, block[1], 7);
                Round1(ref c, d, a, b, block[2], 11);
                Round1(ref b, c, d, a, block[3], 19);
                Round1(ref a, b, c, d, block[4], 3);
                Round1(ref d, a, b, c, block[5], 7);
                Round1(ref c, d, a, b, block[6], 11);
                Round1(ref b, c, d, a, block[7], 19);
                Round1(ref a, b, c, d, block[8], 3);
                Round1(ref d, a, b, c, block[9], 7);
                Round1(ref c, d, a, b, block[10], 11);
                Round1(ref b, c, d, a, block[11], 19);
                Round1(ref a, b, c, d, block[12], 3);
                Round1(ref d, a, b, c, block[13], 7);
                Round1(ref c, d, a, b, block[14], 11);
                Round1(ref b, c, d, a, block[15], 19);

                Round2(ref a, b, c, d, block[0], 3);
                Round2(ref d, a, b, c, block[4], 5);
                Round2(ref c, d, a, b, block[8], 9);
                Round2(ref b, c, d, a, block[12], 13);
                Round2(ref a, b, c, d, block[1], 3);
                Round2(ref d, a, b, c, block[5], 5);
                Round2(ref c, d, a, b, block[9], 9);
                Round2(ref b, c, d, a, block[13], 13);
                Round2(ref a, b, c, d, block[2], 3);
                Round2(ref d, a, b, c, block[6], 5);
                Round2(ref c, d, a, b, block[10], 9);
                Round2(ref b, c, d, a, block[14], 13);
                Round2(ref a, b, c, d, block[3], 3);
                Round2(ref d, a, b, c, block[7], 5);
                Round2(ref c, d, a, b, block[11], 9);
                Round2(ref b, c, d, a, block[15], 13);

                Round3(ref a, b, c, d, block[0], 3);
                Round3(ref d, a, b, c, block[8], 9);
                Round3(ref c, d, a, b, block[4], 11);
                Round3(ref b, c, d, a, block[12], 15);
                Round3(ref a, b, c, d, block[2], 3);
                Round3(ref d, a, b, c, block[10], 9);
                Round3(ref c, d, a, b, block[6], 11);
                Round3(ref b, c, d, a, block[14], 15);
                Round3(ref a, b, c, d, block[1], 3);
                Round3(ref d, a, b, c, block[9], 9);
                Round3(ref c, d, a, b, block[5], 11);
                Round3(ref b, c, d, a, block[13], 15);
                Round3(ref a, b, c, d, block[3], 3);
                Round3(ref d, a, b, c, block[11], 9);
                Round3(ref c, d, a, b, block[7], 11);
                Round3(ref b, c, d, a, block[15], 15);

                a += aa;
                b += bb;
                c += cc;
                d += dd;
            }

            byte[] digest = new byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(0, 4), a);
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(4, 4), b);
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(8, 4), c);
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(12, 4), d);
            return digest;
        }

        private static int CalculatePaddingLength(int messageLength)
        {
            int remainder = (messageLength + 1) % 64;

            if (remainder <= 56)
            {
                return 56 - remainder;
            }

            return 56 + (64 - remainder);
        }

        private static uint F(uint x, uint y, uint z)
        {
            return (x & y) | (~x & z);
        }

        private static uint G(uint x, uint y, uint z)
        {
            return (x & y) | (x & z) | (y & z);
        }

        private static uint H(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }

        private static uint RotateLeft(uint value, int shift)
        {
            return (value << shift) | (value >> (32 - shift));
        }

        private static void Round1(ref uint a, uint b, uint c, uint d, uint x, int shift)
        {
            a = RotateLeft(a + F(b, c, d) + x, shift);
        }

        private static void Round2(ref uint a, uint b, uint c, uint d, uint x, int shift)
        {
            a = RotateLeft(a + G(b, c, d) + x + 0x5A827999U, shift);
        }

        private static void Round3(ref uint a, uint b, uint c, uint d, uint x, int shift)
        {
            a = RotateLeft(a + H(b, c, d) + x + 0x6ED9EBA1U, shift);
        }
    }
}

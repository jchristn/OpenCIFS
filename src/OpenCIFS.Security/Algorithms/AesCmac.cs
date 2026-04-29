namespace OpenCIFS.Security
{
    using System.Security.Cryptography;

    /// <summary>
    /// Computes AES-CMAC authentication values.
    /// </summary>
    public static class AesCmac
    {
        private const int BlockLength = 16;
        private const byte Rb = 0x87;

        /// <summary>
        /// Compute an AES-CMAC value for the supplied message bytes.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="message">Message bytes.</param>
        /// <returns>Sixteen-byte CMAC value.</returns>
        public static byte[] ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
        {
            byte[] subkeySeed = EncryptBlock(key, new byte[BlockLength]);
            byte[] subkey1 = DoubleBlock(subkeySeed);
            byte[] subkey2 = DoubleBlock(subkey1);
            byte[] lastBlock = CreateLastBlock(message, subkey1, subkey2);
            byte[] current = new byte[BlockLength];
            int fullBlocks = message.Length == 0 ? 0 : (message.Length - 1) / BlockLength;

            for (int blockIndex = 0; blockIndex < fullBlocks; blockIndex++)
            {
                byte[] xorInput = XorBlock(current, message.Slice(blockIndex * BlockLength, BlockLength));
                current = EncryptBlock(key, xorInput);
            }

            byte[] finalInput = XorBlock(current, lastBlock);
            return EncryptBlock(key, finalInput);
        }

        /// <summary>
        /// Verify an AES-CMAC value for the supplied message bytes.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="message">Message bytes.</param>
        /// <param name="expectedMac">Expected CMAC bytes.</param>
        /// <returns><c>true</c> if the CMAC is valid.</returns>
        public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expectedMac)
        {
            if (expectedMac.Length != BlockLength)
            {
                return false;
            }

            byte[] actualMac = ComputeMac(key, message);
            return CryptographicOperations.FixedTimeEquals(actualMac, expectedMac);
        }

        private static byte[] CreateLastBlock(ReadOnlySpan<byte> message, ReadOnlySpan<byte> subkey1, ReadOnlySpan<byte> subkey2)
        {
            byte[] lastBlock = new byte[BlockLength];

            if (message.Length != 0 && message.Length % BlockLength == 0)
            {
                message.Slice(message.Length - BlockLength, BlockLength).CopyTo(lastBlock);
                return XorBlock(lastBlock, subkey1);
            }

            int remainderLength = message.Length % BlockLength;

            if (remainderLength != 0)
            {
                message.Slice(message.Length - remainderLength, remainderLength).CopyTo(lastBlock);
            }

            lastBlock[remainderLength] = 0x80;
            return XorBlock(lastBlock, subkey2);
        }

        private static byte[] DoubleBlock(ReadOnlySpan<byte> block)
        {
            byte[] output = new byte[BlockLength];
            byte carry = 0;

            for (int index = BlockLength - 1; index >= 0; index--)
            {
                byte value = block[index];
                output[index] = (byte)((value << 1) | carry);
                carry = (byte)((value & 0x80) == 0x80 ? 1 : 0);
            }

            if ((block[0] & 0x80) == 0x80)
            {
                output[BlockLength - 1] ^= Rb;
            }

            return output;
        }

        private static byte[] EncryptBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> block)
        {
            using Aes algorithm = Aes.Create();
            algorithm.Key = key.ToArray();
            algorithm.Mode = CipherMode.ECB;
            algorithm.Padding = PaddingMode.None;

            using ICryptoTransform encryptor = algorithm.CreateEncryptor();
            return encryptor.TransformFinalBlock(block.ToArray(), 0, BlockLength);
        }

        private static byte[] XorBlock(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            byte[] output = new byte[BlockLength];

            for (int index = 0; index < BlockLength; index++)
            {
                output[index] = (byte)(left[index] ^ right[index]);
            }

            return output;
        }
    }
}

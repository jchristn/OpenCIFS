namespace OpenCIFS.Security
{
    using System;

    /// <summary>
    /// Helpers that build the SMB 3.1.1 AES-GMAC signing nonce per MS-SMB2 section 3.1.4.1.
    /// </summary>
    public static class Smb2SigningNonce
    {
        /// <summary>
        /// AES-GMAC signing nonce length.
        /// </summary>
        public const int Smb311SigningNonceLength = 12;

        private const byte ServerToClientFlag = 0x80;

        /// <summary>
        /// Build the 12-byte SMB 3.1.1 AES-GMAC signing nonce.
        /// </summary>
        /// <param name="messageId">SMB2 header MessageId.</param>
        /// <param name="isServerToClient"><c>true</c> when the message is being sent or verified by the server side, <c>false</c> for client-originated messages.</param>
        /// <returns>Twelve-byte nonce.</returns>
        public static byte[] BuildSmb311GmacNonce(ulong messageId, bool isServerToClient)
        {
            byte[] nonce = new byte[Smb311SigningNonceLength];
            nonce[0] = (byte)(messageId & 0xFF);
            nonce[1] = (byte)((messageId >> 8) & 0xFF);
            nonce[2] = (byte)((messageId >> 16) & 0xFF);
            nonce[3] = (byte)((messageId >> 24) & 0xFF);
            nonce[4] = (byte)((messageId >> 32) & 0xFF);
            nonce[5] = (byte)((messageId >> 40) & 0xFF);
            nonce[6] = (byte)((messageId >> 48) & 0xFF);
            nonce[7] = (byte)((messageId >> 56) & 0xFF);
            nonce[8] = 0;
            nonce[9] = 0;
            nonce[10] = 0;
            nonce[11] = isServerToClient ? ServerToClientFlag : (byte)0;
            return nonce;
        }
    }
}

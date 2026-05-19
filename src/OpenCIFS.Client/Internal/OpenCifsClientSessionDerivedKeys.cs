namespace OpenCIFS.Client
{
    using System;

    internal sealed class OpenCifsClientSessionDerivedKeys
    {
        public OpenCifsClientSessionDerivedKeys(bool isSessionEncryptionRequired, byte[] signingKey, byte[]? encryptionKey, byte[]? decryptionKey)
        {
            IsSessionEncryptionRequired = isSessionEncryptionRequired;
            SigningKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey), "SigningKey cannot be null.");
            EncryptionKey = encryptionKey;
            DecryptionKey = decryptionKey;
        }

        public bool IsSessionEncryptionRequired { get; }

        public byte[] SigningKey { get; }

        public byte[]? EncryptionKey { get; }

        public byte[]? DecryptionKey { get; }
    }
}

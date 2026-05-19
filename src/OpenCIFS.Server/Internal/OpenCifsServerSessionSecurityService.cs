namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsServerSessionSecurityService
    {
        private readonly Func<SmbDialect?> _GetNegotiatedDialect;
        private readonly Func<SmbCipherAlgorithmId> _GetNegotiatedCipher;
        private readonly Func<byte[]?> _GetCurrentPreauthIntegrityHash;
        private readonly Func<Smb2GlobalCapabilities> _GetNegotiatedServerCapabilities;
        private readonly Func<Smb2GlobalCapabilities> _GetNegotiatedClientCapabilities;

        public OpenCifsServerSessionSecurityService(
            Func<SmbDialect?> getNegotiatedDialect,
            Func<SmbCipherAlgorithmId> getNegotiatedCipher,
            Func<byte[]?> getCurrentPreauthIntegrityHash,
            Func<Smb2GlobalCapabilities> getNegotiatedServerCapabilities,
            Func<Smb2GlobalCapabilities> getNegotiatedClientCapabilities)
        {
            _GetNegotiatedDialect = getNegotiatedDialect ?? throw new ArgumentNullException(nameof(getNegotiatedDialect), "GetNegotiatedDialect cannot be null.");
            _GetNegotiatedCipher = getNegotiatedCipher ?? throw new ArgumentNullException(nameof(getNegotiatedCipher), "GetNegotiatedCipher cannot be null.");
            _GetCurrentPreauthIntegrityHash = getCurrentPreauthIntegrityHash ?? throw new ArgumentNullException(nameof(getCurrentPreauthIntegrityHash), "GetCurrentPreauthIntegrityHash cannot be null.");
            _GetNegotiatedServerCapabilities = getNegotiatedServerCapabilities ?? throw new ArgumentNullException(nameof(getNegotiatedServerCapabilities), "GetNegotiatedServerCapabilities cannot be null.");
            _GetNegotiatedClientCapabilities = getNegotiatedClientCapabilities ?? throw new ArgumentNullException(nameof(getNegotiatedClientCapabilities), "GetNegotiatedClientCapabilities cannot be null.");
        }

        public void ApplyAuthenticatedSessionKeys(ServerSessionRecord sessionRecord, byte[] sessionKey)
        {
            if (sessionRecord == null)
            {
                throw new ArgumentNullException(nameof(sessionRecord), "SessionRecord cannot be null.");
            }

            if (sessionKey == null)
            {
                throw new ArgumentNullException(nameof(sessionKey), "SessionKey cannot be null.");
            }

            SmbDialect? negotiatedDialect = _GetNegotiatedDialect();

            if (!negotiatedDialect.HasValue || negotiatedDialect.Value < SmbDialect.Smb30)
            {
                sessionRecord.SessionKey = (byte[])sessionKey.Clone();
                sessionRecord.EncryptionKey = null;
                sessionRecord.DecryptionKey = null;
                sessionRecord.EncryptData = false;
                return;
            }

            SmbKeyDerivationInputs derivationInputs = new SmbKeyDerivationInputs
            {
                SessionKey = (byte[])sessionKey.Clone(),
                Dialect = negotiatedDialect.Value,
                CipherAlgorithmId = _GetNegotiatedCipher()
            };

            if (negotiatedDialect.Value == SmbDialect.Smb311)
            {
                byte[]? preauthIntegrityHash = _GetCurrentPreauthIntegrityHash();

                if (preauthIntegrityHash == null)
                {
                    throw new OpenCifsServerStateException("SMB 3.1.1 session key derivation requires a preauthentication transcript hash.");
                }

                derivationInputs.PreauthIntegrityHash = preauthIntegrityHash;
            }

            SmbSessionKeySet keySet = SmbSessionKeyDerivation.DeriveKeys(derivationInputs);
            sessionRecord.SessionKey = keySet.SigningKey;

            if (ShouldEnableSessionEncryptionForNegotiatedSession(negotiatedDialect.Value))
            {
                sessionRecord.EncryptionKey = keySet.EncryptionKey;
                sessionRecord.DecryptionKey = keySet.DecryptionKey;
                sessionRecord.EncryptData = true;
                return;
            }

            sessionRecord.EncryptionKey = null;
            sessionRecord.DecryptionKey = null;
            sessionRecord.EncryptData = false;
        }

        public IMessageSigner CreateNegotiatedMessageSigner()
        {
            return MessageSignerFactory.Create(GetNegotiatedSigningAlgorithm());
        }

        private bool ShouldEnableSessionEncryptionForNegotiatedSession(SmbDialect negotiatedDialect)
        {
            return negotiatedDialect >= SmbDialect.Smb30 &&
                (_GetNegotiatedServerCapabilities() & Smb2GlobalCapabilities.Encryption) != 0 &&
                (_GetNegotiatedClientCapabilities() & Smb2GlobalCapabilities.Encryption) != 0;
        }

        private SigningAlgorithmId GetNegotiatedSigningAlgorithm()
        {
            SmbDialect? negotiatedDialect = _GetNegotiatedDialect();

            if (!negotiatedDialect.HasValue)
            {
                return SigningAlgorithmId.HmacSha256;
            }

            switch (negotiatedDialect.Value)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return SigningAlgorithmId.AesCmac;
                default:
                    return SigningAlgorithmId.HmacSha256;
            }
        }
    }
}

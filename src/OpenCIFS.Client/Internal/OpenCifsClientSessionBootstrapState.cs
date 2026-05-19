namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsClientSessionBootstrapState
    {
        public SessionState SessionState { get; set; } = new SessionState();

        public SmbDialect[]? LastOfferedDialects { get; set; }

        public Smb2SecurityMode NegotiatedClientSecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

        public Smb2GlobalCapabilities NegotiatedClientCapabilities { get; set; } = Smb2GlobalCapabilities.None;

        public Smb2GlobalCapabilities NegotiatedServerCapabilities { get; set; } = Smb2GlobalCapabilities.None;

        public Smb2SecurityMode NegotiatedServerSecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

        public byte[]? SessionBaseKey { get; set; }

        public byte[]? SessionSigningKey { get; set; }

        public byte[]? SessionEncryptionKey { get; set; }

        public byte[]? SessionDecryptionKey { get; set; }

        public byte[]? StandardNegotiateMessage { get; set; }

        public ulong? SessionId { get; set; }

        public bool IsSessionEncryptionRequired { get; set; }

        public PreauthIntegrityHashAccumulator? PreauthHashAccumulator { get; set; }

        public SmbCipherAlgorithmId NegotiatedCipher { get; set; } = SmbCipherAlgorithmId.Aes128Ccm;

        public SmbDialect? NegotiatedDialect { get; set; }

        public Guid? ServerGuid { get; set; }

        public uint NegotiatedMaxTransactSize { get; set; }

        public uint NegotiatedMaxReadSize { get; set; }

        public uint NegotiatedMaxWriteSize { get; set; }

        public bool IsSigningRequired { get; set; }

        public bool IsSecureNegotiateValidated { get; set; }
    }
}

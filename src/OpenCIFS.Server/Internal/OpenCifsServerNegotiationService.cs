namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class OpenCifsServerNegotiationService
    {
        private readonly OpenCifsServerOptions _Options;
        private readonly Guid _ServerGuid;
        private readonly ulong _ServerStartTime;
        private readonly Func<bool> _HasAnyDfsReferrals;
        private readonly Action<string> _WriteDiagnostic;

        private PreauthIntegrityHashAccumulator? _PreauthHashAccumulator;
        private string? _ReceivedClientNetname;

        public OpenCifsServerNegotiationService(
            OpenCifsServerOptions options,
            Guid serverGuid,
            ulong serverStartTime,
            Func<bool> hasAnyDfsReferrals,
            Action<string> writeDiagnostic)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _ServerGuid = serverGuid;
            _ServerStartTime = serverStartTime;
            _HasAnyDfsReferrals = hasAnyDfsReferrals ?? throw new ArgumentNullException(nameof(hasAnyDfsReferrals), "HasAnyDfsReferrals cannot be null.");
            _WriteDiagnostic = writeDiagnostic ?? throw new ArgumentNullException(nameof(writeDiagnostic), "WriteDiagnostic cannot be null.");
        }

        public Guid NegotiatedClientGuid { get; private set; } = Guid.Empty;

        public Smb2GlobalCapabilities NegotiatedClientCapabilities { get; private set; } = Smb2GlobalCapabilities.None;

        public Smb2SecurityMode NegotiatedClientSecurityMode { get; private set; } = Smb2SecurityMode.SigningEnabled;

        public Smb2SecurityMode NegotiatedServerSecurityMode { get; private set; } = Smb2SecurityMode.SigningEnabled;

        public Smb2GlobalCapabilities NegotiatedServerCapabilities { get; private set; } = Smb2GlobalCapabilities.None;

        public SmbDialect[] NegotiatedClientDialects { get; private set; } = Array.Empty<SmbDialect>();

        public SmbDialect? NegotiatedDialect { get; private set; }

        public SmbCipherAlgorithmId NegotiatedCipher { get; private set; } = SmbCipherAlgorithmId.Aes128Ccm;

        public SmbDialect[] GetAdvertisedDialects()
        {
            SmbDialect maximumImplementedDialect = GetMaximumImplementedDialect();
            SmbDialect effectiveMaximumDialect = _Options.MaximumDialect < maximumImplementedDialect ? _Options.MaximumDialect : maximumImplementedDialect;

            if (effectiveMaximumDialect < _Options.MinimumDialect)
            {
                return Array.Empty<SmbDialect>();
            }

            return SmbDialectCatalog.GetSmb2DialectsInRange(_Options.MinimumDialect, effectiveMaximumDialect);
        }

        public Smb2NegotiateResponse HandleNegotiate(Smb2NegotiateRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            Smb2NegotiateRequestValidator.Validate(request);
            SmbDialect[] advertisedDialects = GetAdvertisedDialects();

            _WriteDiagnostic(
                "Negotiate request received: capabilities=" +
                request.Capabilities +
                ", dialects=[" +
                string.Join(", ", request.Dialects) +
                "], negotiateContextCount=" +
                request.NegotiateContextCount +
                ", negotiateContextBytes=" +
                request.NegotiateContextData.Length +
                ", requireEncryptionForSmb3=" +
                _Options.RequireEncryptionForSmb3 +
                ".");

            if (advertisedDialects.Length == 0)
            {
                throw new OpenCifsServerConfigurationException("The configured server dialect range does not include any currently implemented SMB2 dialects.");
            }

            SmbDialect maximumAdvertisedDialect = advertisedDialects[^1];
            bool clientAdvertisedLegacySmb3Encryption = (request.Capabilities & Smb2GlobalCapabilities.Encryption) != 0;
            bool clientAdvertisedSmb311NegotiationShape = Array.IndexOf(request.Dialects, SmbDialect.Smb311) >= 0 &&
                (request.NegotiateContextCount != 0 || request.NegotiateContextData.Length != 0);

            if (_Options.RequireEncryptionForSmb3 &&
                !clientAdvertisedLegacySmb3Encryption &&
                !clientAdvertisedSmb311NegotiationShape &&
                advertisedDialects[0] <= SmbDialect.Smb21 &&
                maximumAdvertisedDialect > SmbDialect.Smb21)
            {
                maximumAdvertisedDialect = SmbDialect.Smb21;
            }

            if (!SmbDialectCatalog.TrySelectHighestCommonSmb2Dialect(
                request.Dialects,
                advertisedDialects[0],
                maximumAdvertisedDialect,
                out SmbDialect negotiatedDialect))
            {
                throw new OpenCifsServerStateException("No common SMB2 dialect is available for negotiation.");
            }

            Smb2SecurityMode securityMode = Smb2SecurityMode.SigningEnabled;

            if (_Options.RequireSigning)
            {
                securityMode |= Smb2SecurityMode.SigningRequired;
            }

            Smb2NegotiateResponse response = new Smb2NegotiateResponse
            {
                SecurityMode = securityMode,
                Dialect = negotiatedDialect,
                ServerGuid = _ServerGuid,
                Capabilities = GetNegotiatedServerCapabilities(negotiatedDialect),
                MaxTransactSize = 65536u,
                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(negotiatedDialect),
                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(negotiatedDialect),
                SystemTime = (ulong)DateTimeOffset.UtcNow.UtcDateTime.ToFileTimeUtc(),
                ServerStartTime = _ServerStartTime,
                SecurityBuffer = Array.Empty<byte>()
            };

            NegotiatedClientGuid = request.ClientGuid;
            NegotiatedClientCapabilities = request.Capabilities;
            NegotiatedClientSecurityMode = request.SecurityMode;
            NegotiatedClientDialects = (SmbDialect[])request.Dialects.Clone();
            NegotiatedServerSecurityMode = response.SecurityMode;
            NegotiatedServerCapabilities = response.Capabilities;
            NegotiatedDialect = response.Dialect;

            if (_Options.EnableSmb311Preview && clientAdvertisedSmb311NegotiationShape)
            {
                _PreauthHashAccumulator = new PreauthIntegrityHashAccumulator();

                if (negotiatedDialect == SmbDialect.Smb311)
                {
                    PopulateSmb311NegotiateResponseContexts(request, response);
                }
                else
                {
                    NegotiatedCipher = SmbCipherAlgorithmId.Aes128Ccm;
                    _ReceivedClientNetname = null;
                }
            }
            else
            {
                _PreauthHashAccumulator = null;
                NegotiatedCipher = SmbCipherAlgorithmId.Aes128Ccm;
                _ReceivedClientNetname = null;
            }

            Smb2NegotiateResponseValidator.Validate(response);
            return response;
        }

        public void AppendPreauthMessageBytes(Smb2Header header, byte[] body)
        {
            if (_PreauthHashAccumulator == null)
            {
                return;
            }

            if (header == null)
            {
                throw new ArgumentNullException(nameof(header), "Header cannot be null.");
            }

            if (body == null)
            {
                throw new ArgumentNullException(nameof(body), "Body cannot be null.");
            }

            byte[] headerBytes = header.ToByteArray();
            byte[] message = new byte[headerBytes.Length + body.Length];
            Buffer.BlockCopy(headerBytes, 0, message, 0, headerBytes.Length);
            Buffer.BlockCopy(body, 0, message, headerBytes.Length, body.Length);
            _PreauthHashAccumulator.Append(message);
        }

        public byte[]? GetCurrentPreauthIntegrityHash()
        {
            return _PreauthHashAccumulator?.CurrentHash;
        }

        public string? GetReceivedClientNetname()
        {
            return _ReceivedClientNetname;
        }

        private void PopulateSmb311NegotiateResponseContexts(Smb2NegotiateRequest request, Smb2NegotiateResponse response)
        {
            Smb2NegotiateContextEntry[] clientEntries = request.DecodeNegotiateContextEntries();
            PreauthIntegrityCapabilities? clientPreauth = null;
            EncryptionCapabilities? clientEncryption = null;
            SigningCapabilities? clientSigning = null;

            foreach (Smb2NegotiateContextEntry entry in clientEntries)
            {
                switch (entry.ContextType)
                {
                    case Smb2NegotiateContextType.PreauthIntegrityCapabilities:
                        clientPreauth = PreauthIntegrityCapabilities.ReadFrom(entry.Payload);
                        break;
                    case Smb2NegotiateContextType.EncryptionCapabilities:
                        clientEncryption = EncryptionCapabilities.ReadFrom(entry.Payload);
                        break;
                    case Smb2NegotiateContextType.SigningCapabilities:
                        clientSigning = SigningCapabilities.ReadFrom(entry.Payload);
                        break;
                }
            }

            if (clientPreauth == null)
            {
                throw new ProtocolEncodingException("SMB 3.1.1 negotiate requests must include a preauth integrity context.");
            }

            HashAlgorithmId selectedHash = Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(clientPreauth);
            SigningAlgorithmId selectedSigning = Smb311NegotiateContextSelector.SelectSigningAlgorithm(clientSigning);
            SmbCipherAlgorithmId? selectedCipher = Smb311NegotiateContextSelector.SelectCipher(clientEncryption);

            NegotiatedCipher = selectedCipher ?? SmbCipherAlgorithmId.Aes128Ccm;
            _ReceivedClientNetname = null;

            for (int index = 0; index < clientEntries.Length; index++)
            {
                if (clientEntries[index].ContextType == Smb2NegotiateContextType.Netname)
                {
                    NetnameNegotiateContext clientNetname = NetnameNegotiateContext.ReadFrom(clientEntries[index].Payload);
                    _ReceivedClientNetname = clientNetname.ServerName;
                    break;
                }
            }

            byte[] serverSalt = new byte[32];
            RandomNumberGenerator.Fill(serverSalt);
            List<Smb2NegotiateContextEntry> responseEntries = new List<Smb2NegotiateContextEntry>(3);
            responseEntries.Add(new Smb2NegotiateContextEntry
            {
                ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities,
                Payload = new PreauthIntegrityCapabilities
                {
                    HashAlgorithms = new HashAlgorithmId[1] { selectedHash },
                    Salt = serverSalt
                }.ToByteArray()
            });

            if (selectedCipher.HasValue)
            {
                responseEntries.Add(new Smb2NegotiateContextEntry
                {
                    ContextType = Smb2NegotiateContextType.EncryptionCapabilities,
                    Payload = new EncryptionCapabilities
                    {
                        Ciphers = new SmbCipherAlgorithmId[1] { selectedCipher.Value }
                    }.ToByteArray()
                });
            }

            if (clientSigning != null)
            {
                responseEntries.Add(new Smb2NegotiateContextEntry
                {
                    ContextType = Smb2NegotiateContextType.SigningCapabilities,
                    Payload = new SigningCapabilities
                    {
                        SigningAlgorithms = new SigningAlgorithmId[1] { selectedSigning }
                    }.ToByteArray()
                });
            }

            response.SetNegotiateContextEntries(responseEntries);
        }

        private SmbDialect GetMaximumImplementedDialect()
        {
            return SmbImplementationDialectPolicy.GetMaximumImplementedDialect(_Options.EnableSmb311Preview);
        }

        private Smb2GlobalCapabilities GetNegotiatedServerCapabilities(SmbDialect negotiatedDialect)
        {
            Smb2GlobalCapabilities capabilities = Smb2GlobalCapabilities.None;

            if (negotiatedDialect >= SmbDialect.Smb21)
            {
                capabilities |= Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.LargeMtu;

                if (_HasAnyDfsReferrals())
                {
                    capabilities |= Smb2GlobalCapabilities.Dfs;
                }
            }

            if (negotiatedDialect >= SmbDialect.Smb30)
            {
                capabilities |= Smb2GlobalCapabilities.Encryption;
            }

            return capabilities;
        }
    }
}

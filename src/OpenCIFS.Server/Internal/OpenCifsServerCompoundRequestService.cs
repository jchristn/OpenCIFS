namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerCompoundRequestService
    {
        private readonly Action<string> _WriteDiagnostic;
        private readonly OpenCifsServerRelatedCompoundRequestDispatcher _RelatedRequestDispatcher;
        private readonly OpenCifsServerUnrelatedCompoundRequestDispatcher _UnrelatedRequestDispatcher;

        public OpenCifsServerCompoundRequestService(
            OpenCifsServerHost ownerHost,
            Action<string> writeDiagnostic,
            Action<Smb2Header, uint, string> validateReadWriteCreditCharge)
        {
            if (ownerHost == null)
            {
                throw new ArgumentNullException(nameof(ownerHost), "OwnerHost cannot be null.");
            }

            _WriteDiagnostic = writeDiagnostic ?? throw new ArgumentNullException(nameof(writeDiagnostic), "WriteDiagnostic cannot be null.");

            if (validateReadWriteCreditCharge == null)
            {
                throw new ArgumentNullException(nameof(validateReadWriteCreditCharge), "ValidateReadWriteCreditCharge cannot be null.");
            }

            _UnrelatedRequestDispatcher = new OpenCifsServerUnrelatedCompoundRequestDispatcher(ownerHost, _WriteDiagnostic, validateReadWriteCreditCharge);
            _RelatedRequestDispatcher = new OpenCifsServerRelatedCompoundRequestDispatcher(ownerHost, _WriteDiagnostic, validateReadWriteCreditCharge);
        }

        public Smb2CompoundPacket HandleCompoundRequestPacket(Smb2CompoundPacket requestPacket)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            _WriteDiagnostic("Dispatching compounded request packet with " + requestPacket.Entries.Count + " entr" + (requestPacket.Entries.Count == 1 ? "y" : "ies") + ".");

            if ((requestPacket.Entries[0].Header.Flags & Smb2HeaderFlags.RelatedOperations) != 0)
            {
                throw new ProtocolValidationException("The first compounded SMB2 request cannot set RelatedOperations.", nameof(requestPacket));
            }

            bool anyRelatedEntries = false;
            bool anyUnrelatedEntriesAfterFirst = false;

            for (int index = 1; index < requestPacket.Entries.Count; index++)
            {
                if ((requestPacket.Entries[index].Header.Flags & Smb2HeaderFlags.RelatedOperations) != 0)
                {
                    anyRelatedEntries = true;
                }
                else
                {
                    anyUnrelatedEntriesAfterFirst = true;
                }
            }

            if (anyRelatedEntries && anyUnrelatedEntriesAfterFirst)
            {
                throw new ProtocolValidationException("SMB2 compounded request chains cannot mix unrelated and related styles in the current surface.", nameof(requestPacket));
            }

            if (anyRelatedEntries)
            {
                _WriteDiagnostic("Dispatching related compounded request packet.");
                return _RelatedRequestDispatcher.HandleRequestPacket(requestPacket);
            }

            return _UnrelatedRequestDispatcher.HandleRequestPacket(requestPacket);
        }
    }
}

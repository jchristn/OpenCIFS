namespace OpenCIFS.Security
{
    using System.Collections.Generic;

    /// <summary>
    /// Selects a mutually supported SPNEGO mechanism from an initiator offer list.
    /// </summary>
    public static class SpnegoMechanismNegotiator
    {
        /// <summary>
        /// Try to select a mutually supported mechanism from the initiator token.
        /// </summary>
        /// <param name="request">Initiator negotiation token.</param>
        /// <param name="supportedMechanisms">Server-supported mechanism OID list.</param>
        /// <param name="selectedMechanism">Selected mechanism OID when successful.</param>
        /// <returns><c>true</c> if a mutual mechanism was found.</returns>
        public static bool TrySelectMechanism(SpnegoNegTokenInit request, IReadOnlyCollection<string> supportedMechanisms, out string? selectedMechanism)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (supportedMechanisms == null)
            {
                throw new ArgumentNullException(nameof(supportedMechanisms), "SupportedMechanisms cannot be null.");
            }

            HashSet<string> supportedLookup = new HashSet<string>(supportedMechanisms, StringComparer.Ordinal);

            for (int index = 0; index < request.MechanismTypes.Length; index++)
            {
                string offeredMechanism = request.MechanismTypes[index];

                if (supportedLookup.Contains(offeredMechanism))
                {
                    selectedMechanism = offeredMechanism;
                    return true;
                }
            }

            selectedMechanism = null;
            return false;
        }

        /// <summary>
        /// Create a SPNEGO response token that reflects mechanism selection.
        /// </summary>
        /// <param name="request">Initiator negotiation token.</param>
        /// <param name="supportedMechanisms">Server-supported mechanism OID list.</param>
        /// <param name="mechanismResponseToken">Optional response token from the selected mechanism.</param>
        /// <param name="completed">Whether the mechanism exchange completed on this token.</param>
        /// <returns>Server negotiation response.</returns>
        public static SpnegoNegTokenResp CreateNegotiationResponse(SpnegoNegTokenInit request, IReadOnlyCollection<string> supportedMechanisms, byte[]? mechanismResponseToken = null, bool completed = false)
        {
            if (TrySelectMechanism(request, supportedMechanisms, out string? selectedMechanism))
            {
                return new SpnegoNegTokenResp
                {
                    NegotiationState = completed ? SpnegoNegState.AcceptCompleted : SpnegoNegState.AcceptIncomplete,
                    SupportedMechanism = selectedMechanism,
                    ResponseToken = mechanismResponseToken
                };
            }

            return new SpnegoNegTokenResp
            {
                NegotiationState = SpnegoNegState.Reject
            };
        }
    }
}

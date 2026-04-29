namespace OpenCIFS.Security
{
    /// <summary>
    /// Represents a SPNEGO <c>NegTokenInit</c> message.
    /// </summary>
    public sealed class SpnegoNegTokenInit
    {
        /// <summary>
        /// Ordered mechanism OID list offered by the initiator.
        /// </summary>
        public string[] MechanismTypes
        {
            get
            {
                return _MechanismTypes;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(MechanismTypes), "MechanismTypes cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(MechanismTypes), "At least one mechanism OID is required.");
                }

                for (int index = 0; index < value.Length; index++)
                {
                    if (string.IsNullOrWhiteSpace(value[index]))
                    {
                        throw new ArgumentException("MechanismTypes cannot contain null or whitespace entries.", nameof(MechanismTypes));
                    }
                }

                _MechanismTypes = value;
            }
        }

        /// <summary>
        /// Optional GSS context flags value.
        /// </summary>
        public uint? RequestFlags { get; set; }

        /// <summary>
        /// Optional optimistic mechanism token.
        /// </summary>
        public byte[]? MechanismToken { get; set; }

        /// <summary>
        /// Optional mechanism-list MIC bytes.
        /// </summary>
        public byte[]? MechanismListMic { get; set; }

        private string[] _MechanismTypes = new string[] { SpnegoMechanismOid.Ntlm };
    }
}

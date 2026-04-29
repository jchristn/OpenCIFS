namespace OpenCIFS.Security
{
    using System.Buffers.Binary;
    using System.Collections.Generic;
    using System.Formats.Asn1;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Encodes and decodes SPNEGO negotiation tokens.
    /// </summary>
    public static class SpnegoTokenCodec
    {
        private static readonly Asn1Tag ApplicationZeroTag = new Asn1Tag(TagClass.Application, 0, true);
        private static readonly Asn1Tag ContextZeroTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        private static readonly Asn1Tag ContextOneTag = new Asn1Tag(TagClass.ContextSpecific, 1, true);
        private static readonly Asn1Tag ContextTwoTag = new Asn1Tag(TagClass.ContextSpecific, 2, true);
        private static readonly Asn1Tag ContextThreeTag = new Asn1Tag(TagClass.ContextSpecific, 3, true);

        /// <summary>
        /// Encode a SPNEGO <c>NegTokenInit</c> message.
        /// </summary>
        /// <param name="token">Negotiation token.</param>
        /// <param name="includeGssApiWrapper">Whether to include the initial GSS-API wrapper.</param>
        /// <returns>DER-encoded token bytes.</returns>
        public static byte[] EncodeNegTokenInit(SpnegoNegTokenInit token, bool includeGssApiWrapper = true)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token), "Token cannot be null.");
            }

            byte[] negTokenInitChoice = EncodeNegTokenInitChoice(token);

            if (!includeGssApiWrapper)
            {
                return negTokenInitChoice;
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence(ApplicationZeroTag);
            writer.WriteObjectIdentifier(SpnegoMechanismOid.Spnego);
            writer.WriteEncodedValue(negTokenInitChoice);
            writer.PopSequence(ApplicationZeroTag);
            return writer.Encode();
        }

        /// <summary>
        /// Decode a SPNEGO <c>NegTokenInit</c> message.
        /// </summary>
        /// <param name="buffer">DER-encoded token bytes.</param>
        /// <returns>Parsed negotiation token.</returns>
        public static SpnegoNegTokenInit DecodeNegTokenInit(ReadOnlyMemory<byte> buffer)
        {
            try
            {
                AsnReader reader = new AsnReader(buffer, AsnEncodingRules.DER);
                AsnReader choiceReader;

                if (reader.PeekTag().HasSameClassAndValue(ApplicationZeroTag))
                {
                    AsnReader gssWrapper = reader.ReadSequence(ApplicationZeroTag);
                    string mechanismOid = gssWrapper.ReadObjectIdentifier();

                    if (!string.Equals(mechanismOid, SpnegoMechanismOid.Spnego, StringComparison.Ordinal))
                    {
                        throw new ProtocolEncodingException("The initial GSS token does not carry the SPNEGO mechanism OID.");
                    }

                    choiceReader = gssWrapper;
                }
                else
                {
                    choiceReader = reader;
                }

                AsnReader outerChoice = choiceReader.ReadSequence(ContextZeroTag);
                AsnReader sequence = outerChoice.ReadSequence();
                SpnegoNegTokenInit token = new SpnegoNegTokenInit
                {
                    MechanismTypes = ReadMechanismTypes(sequence)
                };

                if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(ContextOneTag))
                {
                    token.RequestFlags = ReadRequestFlags(sequence);
                }

                if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(ContextTwoTag))
                {
                    token.MechanismToken = ReadOctetString(sequence, ContextTwoTag);
                }

                if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(ContextThreeTag))
                {
                    token.MechanismListMic = ReadOctetString(sequence, ContextThreeTag);
                }

                sequence.ThrowIfNotEmpty();
                outerChoice.ThrowIfNotEmpty();
                choiceReader.ThrowIfNotEmpty();
                reader.ThrowIfNotEmpty();
                return token;
            }
            catch (AsnContentException exception)
            {
                throw new ProtocolEncodingException("The buffer does not contain a valid SPNEGO NegTokenInit message.", exception);
            }
        }

        /// <summary>
        /// Encode a SPNEGO <c>NegTokenResp</c> message.
        /// </summary>
        /// <param name="token">Negotiation response token.</param>
        /// <returns>DER-encoded token bytes.</returns>
        public static byte[] EncodeNegTokenResp(SpnegoNegTokenResp token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token), "Token cannot be null.");
            }

            AsnWriter sequenceWriter = new AsnWriter(AsnEncodingRules.DER);
            sequenceWriter.PushSequence();

            if (token.NegotiationState.HasValue)
            {
                AsnWriter negStateWriter = new AsnWriter(AsnEncodingRules.DER);
                negStateWriter.WriteEnumeratedValue(token.NegotiationState.Value);
                WriteExplicit(sequenceWriter, ContextZeroTag, negStateWriter.Encode());
            }

            if (!string.IsNullOrWhiteSpace(token.SupportedMechanism))
            {
                AsnWriter mechanismWriter = new AsnWriter(AsnEncodingRules.DER);
                mechanismWriter.WriteObjectIdentifier(token.SupportedMechanism);
                WriteExplicit(sequenceWriter, ContextOneTag, mechanismWriter.Encode());
            }

            if (token.ResponseToken != null)
            {
                AsnWriter responseTokenWriter = new AsnWriter(AsnEncodingRules.DER);
                responseTokenWriter.WriteOctetString(token.ResponseToken);
                WriteExplicit(sequenceWriter, ContextTwoTag, responseTokenWriter.Encode());
            }

            if (token.MechanismListMic != null)
            {
                AsnWriter micWriter = new AsnWriter(AsnEncodingRules.DER);
                micWriter.WriteOctetString(token.MechanismListMic);
                WriteExplicit(sequenceWriter, ContextThreeTag, micWriter.Encode());
            }

            sequenceWriter.PopSequence();
            byte[] sequenceBytes = sequenceWriter.Encode();
            AsnWriter choiceWriter = new AsnWriter(AsnEncodingRules.DER);
            WriteExplicit(choiceWriter, ContextOneTag, sequenceBytes);
            return choiceWriter.Encode();
        }

        /// <summary>
        /// Decode a SPNEGO <c>NegTokenResp</c> message.
        /// </summary>
        /// <param name="buffer">DER-encoded token bytes.</param>
        /// <returns>Parsed response token.</returns>
        public static SpnegoNegTokenResp DecodeNegTokenResp(ReadOnlyMemory<byte> buffer)
        {
            try
            {
                AsnReader reader = new AsnReader(buffer, AsnEncodingRules.DER);
                AsnReader outerChoice = reader.ReadSequence(ContextOneTag);
                AsnReader sequence = outerChoice.ReadSequence();
                SpnegoNegTokenResp token = new SpnegoNegTokenResp();

                if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(ContextZeroTag))
                {
                    AsnReader negStateReader = sequence.ReadSequence(ContextZeroTag);
                    token.NegotiationState = negStateReader.ReadEnumeratedValue<SpnegoNegState>();
                    negStateReader.ThrowIfNotEmpty();
                }

                if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(ContextOneTag))
                {
                    AsnReader supportedMechanismReader = sequence.ReadSequence(ContextOneTag);
                    token.SupportedMechanism = supportedMechanismReader.ReadObjectIdentifier();
                    supportedMechanismReader.ThrowIfNotEmpty();
                }

                if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(ContextTwoTag))
                {
                    token.ResponseToken = ReadOctetString(sequence, ContextTwoTag);
                }

                if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(ContextThreeTag))
                {
                    token.MechanismListMic = ReadOctetString(sequence, ContextThreeTag);
                }

                sequence.ThrowIfNotEmpty();
                outerChoice.ThrowIfNotEmpty();
                reader.ThrowIfNotEmpty();
                return token;
            }
            catch (AsnContentException exception)
            {
                throw new ProtocolEncodingException("The buffer does not contain a valid SPNEGO NegTokenResp message.", exception);
            }
        }

        private static byte[] EncodeNegTokenInitChoice(SpnegoNegTokenInit token)
        {
            AsnWriter sequenceWriter = new AsnWriter(AsnEncodingRules.DER);
            sequenceWriter.PushSequence();

            AsnWriter mechanismTypesWriter = new AsnWriter(AsnEncodingRules.DER);
            mechanismTypesWriter.PushSequence();

            for (int index = 0; index < token.MechanismTypes.Length; index++)
            {
                mechanismTypesWriter.WriteObjectIdentifier(token.MechanismTypes[index]);
            }

            mechanismTypesWriter.PopSequence();
            WriteExplicit(sequenceWriter, ContextZeroTag, mechanismTypesWriter.Encode());

            if (token.RequestFlags.HasValue)
            {
                AsnWriter requestFlagsWriter = new AsnWriter(AsnEncodingRules.DER);
                Span<byte> flags = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(flags, token.RequestFlags.Value);
                requestFlagsWriter.WriteBitString(flags, 0);
                WriteExplicit(sequenceWriter, ContextOneTag, requestFlagsWriter.Encode());
            }

            if (token.MechanismToken != null)
            {
                AsnWriter mechanismTokenWriter = new AsnWriter(AsnEncodingRules.DER);
                mechanismTokenWriter.WriteOctetString(token.MechanismToken);
                WriteExplicit(sequenceWriter, ContextTwoTag, mechanismTokenWriter.Encode());
            }

            if (token.MechanismListMic != null)
            {
                AsnWriter micWriter = new AsnWriter(AsnEncodingRules.DER);
                micWriter.WriteOctetString(token.MechanismListMic);
                WriteExplicit(sequenceWriter, ContextThreeTag, micWriter.Encode());
            }

            sequenceWriter.PopSequence();
            byte[] sequenceBytes = sequenceWriter.Encode();
            AsnWriter choiceWriter = new AsnWriter(AsnEncodingRules.DER);
            WriteExplicit(choiceWriter, ContextZeroTag, sequenceBytes);
            return choiceWriter.Encode();
        }

        private static string[] ReadMechanismTypes(AsnReader sequence)
        {
            AsnReader outerMechanismTypes = sequence.ReadSequence(ContextZeroTag);
            AsnReader mechanismTypesReader = outerMechanismTypes.ReadSequence();
            List<string> mechanismTypes = new List<string>();

            while (mechanismTypesReader.HasData)
            {
                mechanismTypes.Add(mechanismTypesReader.ReadObjectIdentifier());
            }

            outerMechanismTypes.ThrowIfNotEmpty();

            if (mechanismTypes.Count == 0)
            {
                throw new ProtocolEncodingException("The SPNEGO NegTokenInit message does not contain any mechanism OIDs.");
            }

            return mechanismTypes.ToArray();
        }

        private static uint ReadRequestFlags(AsnReader sequence)
        {
            AsnReader requestFlagsReader = sequence.ReadSequence(ContextOneTag);
            ReadOnlyMemory<byte> flagsBytes = requestFlagsReader.ReadBitString(out int unusedBitCount);
            requestFlagsReader.ThrowIfNotEmpty();

            if (unusedBitCount != 0)
            {
                throw new ProtocolEncodingException("SPNEGO request flags must use whole bytes.");
            }

            if (flagsBytes.Length > 4)
            {
                throw new ProtocolEncodingException("SPNEGO request flags exceed the supported 32-bit width.");
            }

            uint flags = 0;

            for (int index = 0; index < flagsBytes.Length; index++)
            {
                flags = (flags << 8) | flagsBytes.Span[index];
            }

            return flags;
        }

        private static byte[] ReadOctetString(AsnReader sequence, Asn1Tag tag)
        {
            AsnReader octetStringReader = sequence.ReadSequence(tag);
            byte[] value = octetStringReader.ReadOctetString();
            octetStringReader.ThrowIfNotEmpty();
            return value;
        }

        private static void WriteExplicit(AsnWriter writer, Asn1Tag tag, byte[] encodedValue)
        {
            writer.PushSequence(tag);
            writer.WriteEncodedValue(encodedValue);
            writer.PopSequence(tag);
        }
    }
}

namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 create responses.
    /// </summary>
    public static class Smb2CreateResponseValidator
    {
        /// <summary>
        /// Validate a create response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2CreateResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 create response cannot be null.", nameof(response));
            }

            if (!Enum.IsDefined(typeof(Smb2OplockLevel), response.OplockLevel))
            {
                throw new ProtocolValidationException("The SMB2 create response oplock level is not recognized.", nameof(response));
            }

            if (!Enum.IsDefined(typeof(Smb2CreateAction), response.CreateAction))
            {
                throw new ProtocolValidationException("The SMB2 create response action is not recognized.", nameof(response));
            }

            if (response.Flags != 0)
            {
                throw new ProtocolValidationException("The SMB2 create response contains unsupported flags for the current SMB 2.0.2 slice.", nameof(response));
            }

            if (response.PersistentFileId == 0 && response.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 create response must carry a non-zero file identifier.", nameof(response));
            }

            ValidateCreateContexts(response);
        }

        private static void ValidateCreateContexts(Smb2CreateResponse response)
        {
            Smb2CreateContext[] contexts;

            try
            {
                contexts = Smb2CreateContextCodec.Decode(response.CreateContexts);
            }
            catch (ProtocolEncodingException)
            {
                throw new ProtocolValidationException("The SMB2 create response create-context buffer is malformed.", nameof(response));
            }

            int durableResponseCount = 0;
            int durableResponseV2Count = 0;
            int leaseResponseCount = 0;
            bool hasLeaseV2Response = false;

            for (int index = 0; index < contexts.Length; index++)
            {
                if (Smb2DurableHandleResponseContext.IsMatch(contexts[index]))
                {
                    Smb2DurableHandleResponseContext.Validate(contexts[index]);
                    durableResponseCount++;
                    continue;
                }

                if (Smb2CreateResponseLeaseContext.IsMatch(contexts[index]))
                {
                    Smb2CreateResponseLeaseContext.Validate(Smb2CreateResponseLeaseContext.ReadFrom(contexts[index]));
                    leaseResponseCount++;
                    continue;
                }

                if (Smb2DurableHandleResponseV2Context.IsMatch(contexts[index]))
                {
                    Smb2DurableHandleResponseV2Context.Validate(Smb2DurableHandleResponseV2Context.ReadFrom(contexts[index]));
                    durableResponseV2Count++;
                    continue;
                }

                if (Smb2CreateResponseLeaseContext.HasLeaseContextName(contexts[index]))
                {
                    hasLeaseV2Response = true;
                }
            }

            if (durableResponseCount > 1 || durableResponseV2Count > 1 || (durableResponseCount != 0 && durableResponseV2Count != 0))
            {
                throw new ProtocolValidationException("The SMB2 create response contains duplicate durable-handle response contexts.", nameof(response));
            }

            if (leaseResponseCount > 1)
            {
                throw new ProtocolValidationException("The SMB2 create response contains duplicate lease response contexts.", nameof(response));
            }

            if (hasLeaseV2Response)
            {
                throw new ProtocolValidationException("SMB 3.x lease-v2 create response contexts are not supported in the current SMB 2.1 slice.", nameof(response));
            }
        }
    }
}

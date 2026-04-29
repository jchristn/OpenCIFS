namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 create requests.
    /// </summary>
    public static class Smb2CreateRequestValidator
    {
        private const uint DeleteAccess = 0x00010000U;
        private const uint ValidShareAccessMask = 0x00000007U;

        /// <summary>
        /// Validate a create request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2CreateRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 create request cannot be null.", nameof(request));
            }

            if (request.Name.Length != 0 && String.IsNullOrWhiteSpace(request.Name))
            {
                throw new ProtocolValidationException("The SMB2 create request name cannot be null or whitespace.", nameof(request));
            }

            if (request.Name.Length == 0 &&
                request.CreateDisposition != Smb2CreateDisposition.Open &&
                request.CreateDisposition != Smb2CreateDisposition.OpenIf)
            {
                throw new ProtocolValidationException("Empty SMB2 create names are supported only for OPEN and OPEN_IF requests that target the connected share root.", nameof(request));
            }

            if (request.Name.Length == 0 &&
                (request.CreateOptions & Smb2CreateOptions.NonDirectoryFile) != 0)
            {
                throw new ProtocolValidationException("Empty SMB2 create names cannot request a non-directory share-root open.", nameof(request));
            }

            if (!Enum.IsDefined(typeof(Smb2OplockLevel), request.RequestedOplockLevel))
            {
                throw new ProtocolValidationException("The SMB2 create request oplock level is not recognized.", nameof(request));
            }

            if (!Enum.IsDefined(typeof(Smb2ImpersonationLevel), request.ImpersonationLevel))
            {
                throw new ProtocolValidationException("The SMB2 create request impersonation level is not recognized.", nameof(request));
            }

            if (!Enum.IsDefined(typeof(Smb2CreateDisposition), request.CreateDisposition))
            {
                throw new ProtocolValidationException("The SMB2 create request disposition is not recognized.", nameof(request));
            }

            if ((request.CreateOptions & Smb2CreateOptions.DirectoryFile) != 0 &&
                (request.CreateOptions & Smb2CreateOptions.NonDirectoryFile) != 0)
            {
                throw new ProtocolValidationException("The SMB2 create request cannot specify both directory and non-directory options.", nameof(request));
            }

            if ((request.CreateOptions & Smb2CreateOptions.DirectoryFile) != 0)
            {
                if (request.CreateDisposition != Smb2CreateDisposition.Create &&
                    request.CreateDisposition != Smb2CreateDisposition.Open &&
                    request.CreateDisposition != Smb2CreateDisposition.OpenIf)
                {
                    throw new ProtocolValidationException("Directory opens are limited to CREATE, OPEN, and OPEN_IF for the current SMB 2.0.2 directory slice.", nameof(request));
                }
            }

            if ((request.ShareAccess & ~ValidShareAccessMask) != 0)
            {
                throw new ProtocolValidationException("The SMB2 create request share-access mask contains unsupported bits.", nameof(request));
            }

            if ((request.CreateOptions & Smb2CreateOptions.DeleteOnClose) != 0 &&
                (request.DesiredAccess & DeleteAccess) == 0)
            {
                throw new ProtocolValidationException("The SMB2 create request must include DELETE access when FILE_DELETE_ON_CLOSE is requested.", nameof(request));
            }

            if (request.CreateDisposition == Smb2CreateDisposition.Supersede &&
                (request.DesiredAccess & DeleteAccess) == 0)
            {
                throw new ProtocolValidationException("The SMB2 create request must include DELETE access when FILE_SUPERSEDE is requested.", nameof(request));
            }

            ValidateCreateContexts(request);
        }

        private static void ValidateCreateContexts(Smb2CreateRequest request)
        {
            Smb2CreateContext[] contexts;

            try
            {
                contexts = Smb2CreateContextCodec.Decode(request.CreateContexts);
            }
            catch (ProtocolEncodingException exception)
            {
                throw new ProtocolValidationException("The SMB2 create request create-context buffer is malformed: " + exception.Message, nameof(request));
            }

            int durableRequestCount = 0;
            int durableReconnectCount = 0;
            bool hasDurableV2Request = false;
            bool hasDurableV2Reconnect = false;
            int leaseRequestCount = 0;
            bool hasLeaseV2Request = false;

            for (int index = 0; index < contexts.Length; index++)
            {
                Smb2CreateContext context = contexts[index];

                if (Smb2DurableHandleRequestContext.IsMatch(context))
                {
                    Smb2DurableHandleRequestContext.Validate(context);
                    durableRequestCount++;
                    continue;
                }

                if (Smb2DurableHandleReconnectContext.IsMatch(context))
                {
                    Smb2DurableHandleReconnectContext.ReadFrom(context);
                    durableReconnectCount++;
                    continue;
                }

                if (IsCreateContextName(context, 0x44, 0x48, 0x32, 0x51))
                {
                    hasDurableV2Request = true;
                    continue;
                }

                if (IsCreateContextName(context, 0x44, 0x48, 0x32, 0x43))
                {
                    hasDurableV2Reconnect = true;
                    continue;
                }

                if (Smb2CreateRequestLeaseContext.IsMatch(context))
                {
                    Smb2CreateRequestLeaseContext.Validate(Smb2CreateRequestLeaseContext.ReadFrom(context));
                    leaseRequestCount++;
                    continue;
                }

                if (Smb2CreateRequestLeaseContext.HasLeaseContextName(context))
                {
                    hasLeaseV2Request = true;
                    continue;
                }
            }

            if (durableRequestCount > 1 || durableReconnectCount > 1)
            {
                throw new ProtocolValidationException("The SMB2 create request contains duplicate durable-handle contexts.", nameof(request));
            }

            if (hasDurableV2Request || hasDurableV2Reconnect)
            {
                throw new ProtocolValidationException("SMB 3.x durable-handle v2 create contexts are not supported in the current SMB 2.0.2 slice.", nameof(request));
            }

            if (leaseRequestCount > 1)
            {
                throw new ProtocolValidationException("The SMB2 create request contains duplicate lease request contexts.", nameof(request));
            }

            if (hasLeaseV2Request)
            {
                throw new ProtocolValidationException("SMB 3.x lease-v2 create contexts are not supported in the current SMB 2.1 slice.", nameof(request));
            }
        }

        private static bool IsCreateContextName(Smb2CreateContext context, byte b0, byte b1, byte b2, byte b3)
        {
            return context.Name.Length == 4 &&
                context.Name[0] == b0 &&
                context.Name[1] == b1 &&
                context.Name[2] == b2 &&
                context.Name[3] == b3;
        }
    }
}

namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    internal static class OpenCifsClientResponseDecoder
    {
        public static byte[] GetResponsePayloadBytes(Smb2CompoundPacketEntry responseEntry)
        {
            if (responseEntry == null)
            {
                throw new ArgumentNullException(nameof(responseEntry), "ResponseEntry cannot be null.");
            }

            if (!ResponseCarriesCommandPayload(responseEntry.Header))
            {
                return (byte[])responseEntry.Payload.Clone();
            }

            try
            {
                return Smb2CompoundPayloadHelper.TrimResponsePayload(responseEntry.Header.Command, responseEntry.Payload);
            }
            catch (ProtocolEncodingException exception)
            {
                throw new OpenCifsClientStateException(
                    "The server response payload could not be trimmed for command " +
                    responseEntry.Header.Command +
                    " with status " +
                    responseEntry.Header.Status +
                    " and " +
                    responseEntry.Payload.Length +
                    " payload bytes.",
                    exception);
            }
        }

        public static TResponse ReadSuccessResponseOrDefault<TResponse>(
            NtStatus status,
            byte[] responsePayload,
            Func<ReadOnlyMemory<byte>, TResponse> readFrom)
            where TResponse : class, new()
        {
            if (responsePayload == null)
            {
                throw new ArgumentNullException(nameof(responsePayload), "ResponsePayload cannot be null.");
            }

            if (readFrom == null)
            {
                throw new ArgumentNullException(nameof(readFrom), "ReadFrom cannot be null.");
            }

            if (status != NtStatus.Success)
            {
                return new TResponse();
            }

            return readFrom(responsePayload);
        }

        private static bool ResponseCarriesCommandPayload(Smb2Header responseHeader)
        {
            if (responseHeader == null)
            {
                throw new ArgumentNullException(nameof(responseHeader), "ResponseHeader cannot be null.");
            }

            if (responseHeader.Status == NtStatus.Success)
            {
                return true;
            }

            return responseHeader.Command == Smb2Command.SessionSetup &&
                responseHeader.Status == NtStatus.MoreProcessingRequired;
        }
    }
}

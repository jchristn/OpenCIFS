namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerCreateRequestContextParser
    {
        public bool TryAnalyze(
            Smb2CreateRequest request,
            SmbDialect? negotiatedDialect,
            out OpenCifsServerCreateRequestContextAnalysis? analysis,
            out NtStatus status)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            analysis = new OpenCifsServerCreateRequestContextAnalysis();

            try
            {
                analysis.CreateContexts = Smb2CreateContextCodec.Decode(request.CreateContexts);
            }
            catch (ProtocolEncodingException)
            {
                analysis = null;
                status = NtStatus.InvalidParameter;
                return false;
            }

            for (int index = 0; index < analysis.CreateContexts.Length; index++)
            {
                Smb2CreateContext createContext = analysis.CreateContexts[index];

                if (Smb2DurableHandleRequestContext.IsMatch(createContext))
                {
                    analysis.DurableHandleRequested = true;
                    continue;
                }

                if (Smb2DurableHandleReconnectContext.IsMatch(createContext))
                {
                    analysis.DurableHandleReconnectContext = Smb2DurableHandleReconnectContext.ReadFrom(createContext);
                    continue;
                }

                if (Smb2DurableHandleRequestV2Context.IsMatch(createContext))
                {
                    analysis.DurableHandleRequested = true;
                    analysis.DurableHandleRequestV2Context = Smb2DurableHandleRequestV2Context.ReadFrom(createContext);
                    continue;
                }

                if (Smb2DurableHandleReconnectV2Context.IsMatch(createContext))
                {
                    analysis.DurableHandleReconnectV2Context = Smb2DurableHandleReconnectV2Context.ReadFrom(createContext);
                    continue;
                }

                if (Smb2CreateRequestLeaseContext.IsMatch(createContext))
                {
                    analysis.LeaseRequestContext = Smb2CreateRequestLeaseContext.ReadFrom(createContext);
                    continue;
                }
            }

            if ((analysis.DurableHandleRequestV2Context != null || analysis.DurableHandleReconnectV2Context != null) &&
                (!negotiatedDialect.HasValue || negotiatedDialect.Value < SmbDialect.Smb30))
            {
                analysis = null;
                status = NtStatus.InvalidParameter;
                return false;
            }

            if (analysis.DurableHandleRequestV2Context != null &&
                (analysis.DurableHandleRequestV2Context.Flags & Smb2DurableHandleFlags.Persistent) != 0)
            {
                analysis = null;
                status = NtStatus.InvalidParameter;
                return false;
            }

            if (analysis.DurableHandleReconnectV2Context != null &&
                (analysis.DurableHandleReconnectV2Context.Flags & Smb2DurableHandleFlags.Persistent) != 0)
            {
                analysis = null;
                status = NtStatus.InvalidParameter;
                return false;
            }

            status = NtStatus.Success;
            return true;
        }
    }
}

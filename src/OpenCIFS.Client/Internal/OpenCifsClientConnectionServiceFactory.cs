namespace OpenCIFS.Client
{
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    internal static class OpenCifsClientConnectionServiceFactory
    {
        public static OpenCifsClientConnectionServices Create(OpenCifsClientOptions options)
        {
            OpenCifsClientConnectionStateService stateService = new OpenCifsClientConnectionStateService(options);
            OpenCifsClientRequestDispatchService requestDispatchService = new OpenCifsClientRequestDispatchService(
                () => stateService.Connection,
                stateService.GetCurrentSession);
            OpenCifsClientTreeOpenOperationService treeOpenOperationService = new OpenCifsClientTreeOpenOperationService(
                stateService.ActiveTreesById,
                stateService.ActiveOpensByKey,
                stateService.ConnectionId,
                stateService.GetSessionGeneration,
                stateService.GetCurrentSession,
                stateService.EnsureAuthenticatedSession,
                requestDispatchService.SendSingleRequestAsync,
                requestDispatchService.ReadNextResponsePacketBytesAsync,
                OpenCifsClientResponseDecoder.GetResponsePayloadBytes);

            OpenCifsClientConnectionControlService? controlService = null;
            OpenCifsClientAdministrationService? administrationService = null;

            OpenCifsClientConnectionLifecycleService lifecycleService = new OpenCifsClientConnectionLifecycleService(
                options,
                stateService.ThrowIfDisposed,
                () => stateService.Connection,
                stateService.SetTcpClient,
                stateService.SetConnection,
                () => controlService!.ResetSession(),
                stateService.ResetTransportAsync,
                stateService.GetCurrentSession,
                stateService.EnsureNegotiatedConnection,
                stateService.EnsureAuthenticatedSession,
                () => stateService.ActiveTreeHandles,
                treeOpenOperationService.MarkTreeDisconnected,
                requestDispatchService.SendSingleRequestAsync);

            OpenCifsClientCompoundOperationService compoundOperationService = new OpenCifsClientCompoundOperationService(
                stateService.GetCurrentSession,
                treeOpenOperationService.ValidateTreeHandle,
                lifecycleService.EnsureCreditsAsync,
                requestDispatchService.SendCompoundRequestAsync,
                OpenCifsClientResponseDecoder.GetResponsePayloadBytes);

            OpenCifsClientFileOperationService fileOperationService = new OpenCifsClientFileOperationService(
                stateService.GetCurrentSession,
                treeOpenOperationService.ValidateOpenHandle,
                treeOpenOperationService.ValidateFileOpenHandle,
                treeOpenOperationService.ValidateDirectoryOpenHandle,
                treeOpenOperationService.RemoveOpenHandle,
                OpenCifsClientConnectionControlService.NormalizeRelativePath,
                requestDispatchService.SendSingleRequestAsync,
                requestDispatchService.SendChangeNotifyRequestAsync,
                lifecycleService.EnsureCreditsAsync);

            OpenCifsClientTreeConnectionService treeConnectionService = new OpenCifsClientTreeConnectionService(
                stateService.GetCurrentSession,
                stateService.EnsureAuthenticatedSession,
                treeOpenOperationService.ValidateTreeHandle,
                treeOpenOperationService.MarkTreeDisconnected,
                treeOpenOperationService.CreateTrackedTreeHandle,
                stateService.ResetTransportAsync,
                () => controlService!.ResetSession(),
                requestDispatchService.SendSingleRequestAsync);

            controlService = new OpenCifsClientConnectionControlService(
                stateService,
                treeOpenOperationService,
                lifecycleService,
                () => administrationService!.ClearCachedReferrals(),
                treeConnectionService.TreeConnectAsync,
                (OpenCifsClientTreeHandle treeHandle, string path, CancellationToken cancellationToken) =>
                    treeOpenOperationService.OpenAsync(
                        treeHandle,
                        path,
                        0xC0000000U,
                        FileAttributes.Normal,
                        0x00000007U,
                        Smb2CreateDisposition.OpenIf,
                        Smb2CreateOptions.NonDirectoryFile,
                        cancellationToken,
                        Smb2OplockLevel.None,
                        false,
                        Smb2LeaseState.None,
                        null),
                async (OpenCifsClientOpenHandle openHandle, CancellationToken cancellationToken) =>
                {
                    await fileOperationService.CloseAsync(openHandle, false, cancellationToken).ConfigureAwait(false);
                },
                treeConnectionService.TreeDisconnectAsync);

            administrationService = new OpenCifsClientAdministrationService(
                options,
                stateService.GetCurrentSession,
                stateService.EnsureAuthenticatedSession,
                treeOpenOperationService.ValidateOpenHandle,
                controlService.ConnectIpcTreeAsync,
                controlService.OpenPipeAsync,
                controlService.CloseOpenHandleAsync,
                controlService.DisconnectTreeHandleAsync,
                requestDispatchService.SendSingleRequestAsync);

            return new OpenCifsClientConnectionServices(
                administrationService,
                compoundOperationService,
                controlService,
                fileOperationService,
                lifecycleService,
                stateService,
                treeConnectionService,
                treeOpenOperationService);
        }
    }
}

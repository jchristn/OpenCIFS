namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;

    internal sealed class OpenCifsClientConnectionControlService
    {
        public OpenCifsClientConnectionControlService(
            OpenCifsClientConnectionStateService stateService,
            OpenCifsClientTreeOpenOperationService treeOpenOperationService,
            OpenCifsClientConnectionLifecycleService lifecycleService,
            Action clearCachedReferrals,
            Func<string, CancellationToken, Task<OpenCifsClientTreeHandle>> treeConnectAsync,
            Func<OpenCifsClientTreeHandle, string, CancellationToken, Task<OpenCifsClientOpenHandle>> openAsync,
            Func<OpenCifsClientOpenHandle, CancellationToken, Task> closeAsync,
            Func<OpenCifsClientTreeHandle, CancellationToken, Task> treeDisconnectAsync)
        {
            _StateService = stateService ?? throw new ArgumentNullException(nameof(stateService), "StateService cannot be null.");
            _TreeOpenOperationService = treeOpenOperationService ?? throw new ArgumentNullException(nameof(treeOpenOperationService), "TreeOpenOperationService cannot be null.");
            _LifecycleService = lifecycleService ?? throw new ArgumentNullException(nameof(lifecycleService), "LifecycleService cannot be null.");
            _ClearCachedReferrals = clearCachedReferrals ?? throw new ArgumentNullException(nameof(clearCachedReferrals), "ClearCachedReferrals cannot be null.");
            _TreeConnectAsync = treeConnectAsync ?? throw new ArgumentNullException(nameof(treeConnectAsync), "TreeConnectAsync cannot be null.");
            _OpenAsync = openAsync ?? throw new ArgumentNullException(nameof(openAsync), "OpenAsync cannot be null.");
            _CloseAsync = closeAsync ?? throw new ArgumentNullException(nameof(closeAsync), "CloseAsync cannot be null.");
            _TreeDisconnectAsync = treeDisconnectAsync ?? throw new ArgumentNullException(nameof(treeDisconnectAsync), "TreeDisconnectAsync cannot be null.");
        }

        public static string NormalizeRelativePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            return path.Replace('/', '\\').TrimStart('\\');
        }

        public void ResetSession(bool invalidateDurableReconnect = true)
        {
            _TreeOpenOperationService.InvalidateTrackedHandles(invalidateDurableReconnect);
            _ClearCachedReferrals();
            _StateService.ResetSession();
        }

        public async Task SimulateTransportDisconnectAsync()
        {
            _StateService.ThrowIfDisposed();

            if (!_StateService.IsConnected)
            {
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            await _StateService.ResetTransportAsync().ConfigureAwait(false);
            ResetSession(invalidateDurableReconnect: false);

            // This helper exists for the shared direct-TCP tests. Give the server a brief
            // window to observe the abrupt socket teardown and detach any durable state
            // before the test issues competing or reconnecting operations.
            await Task.Delay(200).ConfigureAwait(false);
        }

        public async Task<OpenCifsClientTreeHandle> ConnectIpcTreeAsync(CancellationToken cancellationToken)
        {
            return await _TreeConnectAsync(IpcShareName, cancellationToken).ConfigureAwait(false);
        }

        public async Task<OpenCifsClientOpenHandle> OpenPipeAsync(
            OpenCifsClientTreeHandle treeHandle,
            string pipeName,
            CancellationToken cancellationToken)
        {
            return await _OpenAsync(treeHandle, pipeName, cancellationToken).ConfigureAwait(false);
        }

        public async Task CloseOpenHandleAsync(OpenCifsClientOpenHandle openHandle, CancellationToken cancellationToken)
        {
            await _CloseAsync(openHandle, cancellationToken).ConfigureAwait(false);
        }

        public async Task DisconnectTreeHandleAsync(OpenCifsClientTreeHandle treeHandle, CancellationToken cancellationToken)
        {
            await _TreeDisconnectAsync(treeHandle, cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask DisposeAsyncCore()
        {
            try
            {
                await _LifecycleService.DisconnectCoreAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                await _StateService.ResetTransportAsync().ConfigureAwait(false);
                ResetSession();
            }
        }

        private const string IpcShareName = "IPC$";
        private readonly Action _ClearCachedReferrals;
        private readonly Func<OpenCifsClientOpenHandle, CancellationToken, Task> _CloseAsync;
        private readonly OpenCifsClientConnectionLifecycleService _LifecycleService;
        private readonly Func<OpenCifsClientTreeHandle, string, CancellationToken, Task<OpenCifsClientOpenHandle>> _OpenAsync;
        private readonly OpenCifsClientConnectionStateService _StateService;
        private readonly Func<OpenCifsClientTreeHandle, CancellationToken, Task> _TreeDisconnectAsync;
        private readonly Func<string, CancellationToken, Task<OpenCifsClientTreeHandle>> _TreeConnectAsync;
        private readonly OpenCifsClientTreeOpenOperationService _TreeOpenOperationService;
    }
}

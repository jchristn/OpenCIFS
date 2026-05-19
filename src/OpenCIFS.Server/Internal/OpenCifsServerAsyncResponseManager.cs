namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Concurrent;
    using System.Threading;
    using System.Threading.Tasks;

    internal sealed class OpenCifsServerAsyncResponseManager
    {
        private readonly ConcurrentQueue<OpenCifsServerAsyncResponse> _ReadyAsyncResponses = new ConcurrentQueue<OpenCifsServerAsyncResponse>();
        private readonly SemaphoreSlim _AsyncResponseSignal = new SemaphoreSlim(0);

        public bool TryDequeue(out OpenCifsServerAsyncResponse? response)
        {
            return _ReadyAsyncResponses.TryDequeue(out response);
        }

        public Task WaitAsync(CancellationToken cancellationToken)
        {
            if (!_ReadyAsyncResponses.IsEmpty)
            {
                return Task.CompletedTask;
            }

            return _AsyncResponseSignal.WaitAsync(cancellationToken);
        }

        public void Enqueue(OpenCifsServerAsyncResponse response)
        {
            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            _ReadyAsyncResponses.Enqueue(response);
            _AsyncResponseSignal.Release();
        }

        public void Clear()
        {
            OpenCifsServerAsyncResponse? result;

            while (_ReadyAsyncResponses.TryDequeue(out result))
            {
            }
        }
    }
}

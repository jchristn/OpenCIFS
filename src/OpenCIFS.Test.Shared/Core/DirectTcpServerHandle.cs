namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Running direct-TCP test server state.
    /// </summary>
    public sealed class DirectTcpServerHandle
    {
        /// <summary>
        /// Initialize a running direct-TCP test server handle.
        /// </summary>
        /// <param name="cancellationTokenSource">Cancellation token source for the server.</param>
        /// <param name="serverTask">Background server task.</param>
        public DirectTcpServerHandle(CancellationTokenSource cancellationTokenSource, Task serverTask)
        {
            CancellationTokenSource = cancellationTokenSource ?? throw new ArgumentNullException(nameof(cancellationTokenSource));
            ServerTask = serverTask ?? throw new ArgumentNullException(nameof(serverTask));
        }

        /// <summary>
        /// Cancellation token source for the server.
        /// </summary>
        public CancellationTokenSource CancellationTokenSource { get; }

        /// <summary>
        /// Background server task.
        /// </summary>
        public Task ServerTask { get; }
    }
}

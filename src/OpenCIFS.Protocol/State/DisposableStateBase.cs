namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Internal disposable base for protocol state objects.
    /// </summary>
    public abstract class DisposableStateBase : IDisposable
    {
        /// <summary>
        /// Whether the object has been disposed.
        /// </summary>
        public bool IsDisposed
        {
            get
            {
                return _IsDisposed;
            }
        }

        /// <summary>
        /// Dispose the state object.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose the state object.
        /// </summary>
        /// <param name="disposing">Whether managed resources are being disposed.</param>
        protected virtual void Dispose(bool disposing)
        {
            _IsDisposed = true;
        }

        /// <summary>
        /// Throw if the object has been disposed.
        /// </summary>
        protected void EnsureNotDisposed()
        {
            if (_IsDisposed)
            {
                throw new ObjectDisposedException(GetType().FullName, "The protocol state object has been disposed.");
            }
        }

        private bool _IsDisposed = false;
    }
}

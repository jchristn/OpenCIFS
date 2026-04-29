namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Tracks SMB credit accounting state.
    /// </summary>
    public sealed class CreditState : DisposableStateBase
    {
        /// <summary>
        /// Currently available credits.
        /// </summary>
        public int AvailableCredits
        {
            get
            {
                return _AvailableCredits;
            }
        }

        /// <summary>
        /// Grant additional credits.
        /// </summary>
        /// <param name="count">Credit count to add.</param>
        public void Grant(int count)
        {
            EnsureNotDisposed();

            if (count <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count), "Granted credits must be positive.");
            }

            _AvailableCredits += count;
        }

        /// <summary>
        /// Consume credits for an outbound request.
        /// </summary>
        /// <param name="count">Credit count to consume.</param>
        public void Consume(int count)
        {
            EnsureNotDisposed();

            if (count <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count), "Consumed credits must be positive.");
            }

            if (count > _AvailableCredits)
            {
                throw new InvalidOperationException("The requested credit count exceeds the available credits.");
            }

            _AvailableCredits -= count;
        }

        /// <summary>
        /// Return credits to the pool.
        /// </summary>
        /// <param name="count">Credit count to return.</param>
        public void Return(int count)
        {
            Grant(count);
        }

        private int _AvailableCredits = 0;
    }
}


namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Tracks SMB compound request ordering state.
    /// </summary>
    public sealed class CompoundChainState : DisposableStateBase
    {
        /// <summary>
        /// Commands in the compound chain.
        /// </summary>
        public IReadOnlyList<Smb2Command> Commands
        {
            get
            {
                return _Commands.AsReadOnly();
            }
        }

        /// <summary>
        /// Whether the chain has been sealed.
        /// </summary>
        public bool IsSealed { get; private set; } = false;

        /// <summary>
        /// Append a command to the chain.
        /// </summary>
        /// <param name="command">Command to append.</param>
        public void Append(Smb2Command command)
        {
            EnsureNotDisposed();

            if (IsSealed)
            {
                throw new InvalidOperationException("The compound chain has already been sealed.");
            }

            _Commands.Add(command);
        }

        /// <summary>
        /// Seal the compound chain to prevent additional commands.
        /// </summary>
        public void Seal()
        {
            EnsureNotDisposed();
            IsSealed = true;
        }

        private readonly List<Smb2Command> _Commands = new List<Smb2Command>();
    }
}


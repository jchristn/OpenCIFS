namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB1 command identifiers used by OpenCIFS foundations.
    /// </summary>
    public enum Smb1Command : byte
    {
        /// <summary>
        /// Negotiate protocol.
        /// </summary>
        Negotiate = 0x72,

        /// <summary>
        /// Session setup.
        /// </summary>
        SessionSetupAndX = 0x73,

        /// <summary>
        /// Logoff.
        /// </summary>
        LogoffAndX = 0x74,

        /// <summary>
        /// Tree connect.
        /// </summary>
        TreeConnectAndX = 0x75,

        /// <summary>
        /// Tree disconnect.
        /// </summary>
        TreeDisconnect = 0x71,

        /// <summary>
        /// NT create.
        /// </summary>
        NtCreateAndX = 0xA2,

        /// <summary>
        /// Read.
        /// </summary>
        ReadAndX = 0x2E,

        /// <summary>
        /// Write.
        /// </summary>
        WriteAndX = 0x2F,

        /// <summary>
        /// Close.
        /// </summary>
        Close = 0x04,

        /// <summary>
        /// Locking.
        /// </summary>
        LockingAndX = 0x24,

        /// <summary>
        /// Echo.
        /// </summary>
        Echo = 0x2B,

        /// <summary>
        /// Transaction.
        /// </summary>
        Transaction = 0x25,

        /// <summary>
        /// Transaction2.
        /// </summary>
        Transaction2 = 0x32,

        /// <summary>
        /// NT transact.
        /// </summary>
        NtTransact = 0xA0,

        /// <summary>
        /// Transaction secondary (continuation fragment of an in-progress <see cref="Transaction" />).
        /// </summary>
        TransactionSecondary = 0x26,

        /// <summary>
        /// Transaction2 secondary (continuation fragment of an in-progress <see cref="Transaction2" />).
        /// </summary>
        Transaction2Secondary = 0x33,

        /// <summary>
        /// NT transact secondary (continuation fragment of an in-progress <see cref="NtTransact" />).
        /// </summary>
        NtTransactSecondary = 0xA1
    }
}


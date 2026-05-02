namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 NT LM 0.12 NEGOTIATE response server capability flags. Values per MS-CIFS section 2.2.4.5.2.
    /// </summary>
    [Flags]
    public enum Smb1Capabilities : uint
    {
        /// <summary>
        /// No capabilities set.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Server supports raw mode read/write.
        /// </summary>
        RawMode = 0x00000001,

        /// <summary>
        /// Server supports multiplexed message handling.
        /// </summary>
        MpxMode = 0x00000002,

        /// <summary>
        /// Server supports unicode strings on the wire.
        /// </summary>
        Unicode = 0x00000004,

        /// <summary>
        /// Server supports large 64-bit file sizes and offsets.
        /// </summary>
        LargeFiles = 0x00000008,

        /// <summary>
        /// Server supports SMB_COM_NT_TRANSACT and the NT-style command family.
        /// </summary>
        NtSmbs = 0x00000010,

        /// <summary>
        /// Server supports remote API requests over named-pipe transport.
        /// </summary>
        RpcRemoteApis = 0x00000020,

        /// <summary>
        /// Server returns NTSTATUS response codes.
        /// </summary>
        Status32 = 0x00000040,

        /// <summary>
        /// Server supports level-II oplocks.
        /// </summary>
        LevelIIOplocks = 0x00000080,

        /// <summary>
        /// Server supports SMB_COM_LOCK_AND_READ.
        /// </summary>
        LockAndRead = 0x00000100,

        /// <summary>
        /// Server supports SMB_COM_NT_FIND.
        /// </summary>
        NtFind = 0x00000200,

        /// <summary>
        /// Server supports DFS referrals.
        /// </summary>
        Dfs = 0x00001000,

        /// <summary>
        /// Server supports passthrough information levels.
        /// </summary>
        InfoLevelPassthrough = 0x00002000,

        /// <summary>
        /// Server supports SMB_COM_READ_ANDX with payloads larger than 64 KiB.
        /// </summary>
        LargeReadX = 0x00004000,

        /// <summary>
        /// Server supports SMB_COM_WRITE_ANDX with payloads larger than 64 KiB.
        /// </summary>
        LargeWriteX = 0x00008000,

        /// <summary>
        /// Server supports the extended-security negotiate flow that carries SPNEGO blobs in the buffer.
        /// </summary>
        ExtendedSecurity = 0x80000000
    }
}

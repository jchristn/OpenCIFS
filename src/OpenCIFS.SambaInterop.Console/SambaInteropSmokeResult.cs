namespace OpenCIFS.SambaInterop.Console
{
    using System;

    internal sealed class SambaInteropSmokeResult
    {
        public SambaInteropAdvancedSmb3Result AdvancedSmb3 { get; init; } = new SambaInteropAdvancedSmb3Result();

        public string[] BrowsedShareNames { get; init; } = Array.Empty<string>();

        public string BrowsedShareLocalPath { get; init; } = string.Empty;

        public uint BrowsedShareCurrentUses { get; init; }

        public string Dialect { get; init; } = string.Empty;

        public string[] DirectoryEntryNames { get; init; } = Array.Empty<string>();

        public bool DeletedDirectoryReopenRejected { get; init; }

        public bool DeletedFileReopenRejected { get; init; }

        public string Directory { get; init; } = string.Empty;

        public ulong FinalEndOfFile { get; init; }

        public ulong InitialEndOfFile { get; init; }

        public ulong LargeEndOfFile { get; init; }

        public string LargeFilePath { get; init; } = string.Empty;

        public int LargePayloadLength { get; init; }

        public uint LargeWroteBytes { get; init; }

        public bool LockConflictRejected { get; init; }

        public ulong MutatedLastWriteTime { get; init; }

        public string NestedDirectory { get; init; } = string.Empty;

        public bool NonEmptyDirectoryDeleteRejected { get; init; }

        public bool OriginalDirectoryMissingRejected { get; init; }

        public string RenamedDirectory { get; init; } = string.Empty;

        public string RenamedFilePath { get; init; } = string.Empty;

        public string[] RenamedDirectoryEntryNames { get; init; } = Array.Empty<string>();

        public string RenamedNestedDirectory { get; init; } = string.Empty;

        public string RoundTripText { get; init; } = string.Empty;

        public string Server { get; init; } = string.Empty;

        public string Share { get; init; } = string.Empty;

        public ulong StandardInfoEndOfFile { get; init; }

        public ulong TruncatedEndOfFile { get; init; }

        public string TruncatedRoundTripText { get; init; } = string.Empty;

        public string UserName { get; init; } = string.Empty;

        public int Port { get; init; }

        public uint WroteBytes { get; init; }
    }

    internal sealed class SambaInteropAdvancedSmb3Result
    {
        public bool DialectIsSmb3 { get; init; }

        public bool EncryptionExpected { get; init; }

        public bool SecureNegotiateValidationExpected { get; init; }

        public SambaInteropDurableHandleV2Result DurableHandleV2 { get; init; } = new SambaInteropDurableHandleV2Result();

        public SambaInteropOplockBreakResult Oplock { get; init; } = new SambaInteropOplockBreakResult();

        public SambaInteropLeaseBreakResult Lease { get; init; } = new SambaInteropLeaseBreakResult();
    }

    internal sealed class SambaInteropDurableHandleV2Result
    {
        public bool Attempted { get; set; }

        public bool CanReconnectDurably { get; set; }

        public uint DurableTimeoutMs { get; set; }

        public string Failure { get; set; } = string.Empty;

        public bool Granted { get; set; }

        public string GrantedOplockLevel { get; set; } = string.Empty;

        public bool IsPersistent { get; set; }

        public string Outcome { get; set; } = string.Empty;

        public bool PostReconnectCompetingLockSucceeded { get; set; }

        public bool PreservedLockConflict { get; set; }

        public bool PreservedReadLockConflict { get; set; }

        public bool Reconnected { get; set; }

        public string SkipReason { get; set; } = string.Empty;

        public bool UsesDurableHandleV2 { get; set; }
    }

    internal sealed class SambaInteropOplockBreakResult
    {
        public bool Acknowledged { get; set; }

        public bool Attempted { get; set; }

        public bool BreakObserved { get; set; }

        public string Failure { get; set; } = string.Empty;

        public string GrantedLevel { get; set; } = string.Empty;

        public string NewLevel { get; set; } = string.Empty;

        public string Outcome { get; set; } = string.Empty;

        public string PreviousLevel { get; set; } = string.Empty;

        public string RequestedLevel { get; set; } = string.Empty;

        public string SkipReason { get; set; } = string.Empty;
    }

    internal sealed class SambaInteropLeaseBreakResult
    {
        public bool Acknowledged { get; set; }

        public bool Attempted { get; set; }

        public bool BreakObserved { get; set; }

        public string Failure { get; set; } = string.Empty;

        public string GrantedState { get; set; } = string.Empty;

        public string NewState { get; set; } = string.Empty;

        public string Outcome { get; set; } = string.Empty;

        public string PreviousState { get; set; } = string.Empty;

        public string RequestedState { get; set; } = string.Empty;

        public string SkipReason { get; set; } = string.Empty;
    }
}

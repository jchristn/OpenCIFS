namespace OpenCIFS.Core.Tests.Shared
{
    using OpenCIFS.Protocol;

    internal sealed class Smb1StatusToDosCase
    {
        public Smb1StatusToDosCase(NtStatus status, Smb1DosErrorClass expectedClass, ushort expectedCode)
        {
            Status = status;
            ExpectedClass = expectedClass;
            ExpectedCode = expectedCode;
        }

        public NtStatus Status { get; }

        public Smb1DosErrorClass ExpectedClass { get; }

        public ushort ExpectedCode { get; }
    }
}

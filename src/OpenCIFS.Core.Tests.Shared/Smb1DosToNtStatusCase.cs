namespace OpenCIFS.Core.Tests.Shared
{
    using OpenCIFS.Protocol;

    internal sealed class Smb1DosToNtStatusCase
    {
        public Smb1DosToNtStatusCase(Smb1DosErrorClass dosErrorClass, ushort code, NtStatus expected)
        {
            DosErrorClass = dosErrorClass;
            Code = code;
            Expected = expected;
        }

        public Smb1DosErrorClass DosErrorClass { get; }

        public ushort Code { get; }

        public NtStatus Expected { get; }
    }
}

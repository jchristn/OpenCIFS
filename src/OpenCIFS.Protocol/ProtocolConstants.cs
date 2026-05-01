namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Internal protocol constants shared by OpenCIFS codecs.
    /// </summary>
    internal static class ProtocolConstants
    {
        internal static readonly byte[] Smb1ProtocolId = new byte[] { 0xFF, 0x53, 0x4D, 0x42 };
        internal static readonly byte[] Smb2ProtocolId = new byte[] { 0xFE, 0x53, 0x4D, 0x42 };
        internal static readonly byte[] Smb2TransformProtocolId = new byte[] { 0xFD, 0x53, 0x4D, 0x42 };
        internal static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(5);
        internal static readonly int DirectTcpHeaderLength = 4;
        internal static readonly int NetBiosSessionServiceHeaderLength = 4;
        internal static readonly int Smb1HeaderLength = 32;
        internal static readonly int Smb2HeaderLength = 64;
        internal static readonly int Smb2TransformHeaderLength = 52;
    }
}

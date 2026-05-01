namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    internal sealed class SrvsvcShareInfo1
    {
        public string Name { get; set; } = string.Empty;

        public uint Type { get; set; }

        public string Remark { get; set; } = string.Empty;
    }

    internal sealed class SrvsvcShareInfo2
    {
        public string Name { get; set; } = string.Empty;

        public uint Type { get; set; }

        public string Remark { get; set; } = string.Empty;

        public uint Permissions { get; set; }

        public uint MaximumUses { get; set; }

        public uint CurrentUses { get; set; }

        public string Path { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;
    }

    internal sealed class SrvsvcNetrShareEnumRequest
    {
        private const uint MaxPreferredLength = 0xFFFFFFFFU;

        public const ushort OperationNumber = 15;

        public string ServerName { get; set; } = string.Empty;

        public uint Level { get; set; } = 1;

        public uint PreferredMaximumLength { get; set; } = MaxPreferredLength;

        public uint? ResumeHandle { get; set; }

        public byte[] ToByteArray()
        {
            if (Level != 1)
            {
                throw new ArgumentOutOfRangeException(nameof(Level), "The bounded OpenCIFS SRVSVC request slice only supports SHARE_INFO_1 enumeration.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            DceRpcEncoding.WriteUniquePointer(writer, 0x00010000);
            DceRpcEncoding.WriteNdrUtf16String(writer, ServerName);
            writer.WriteUInt32(Level);
            writer.WriteUInt32(Level);
            DceRpcEncoding.WriteUniquePointer(writer, 0x00020000);
            writer.WriteUInt32(0);
            DceRpcEncoding.WriteUniquePointer(writer, 0);
            writer.WriteUInt32(PreferredMaximumLength);

            if (ResumeHandle.HasValue)
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0x00030000);
                writer.WriteUInt32(ResumeHandle.Value);
            }
            else
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0);
            }

            return writer.ToArray();
        }

        public static SrvsvcNetrShareEnumRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 28)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareEnum request payload is truncated.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            uint serverNamePointer = reader.ReadUInt32();
            string serverName = serverNamePointer == 0 ? string.Empty : DceRpcEncoding.ReadNdrUtf16String(reader);
            uint level = reader.ReadUInt32();
            uint unionTag = reader.ReadUInt32();

            if (level != 1 || unionTag != 1)
            {
                throw new ProtocolEncodingException("The bounded OpenCIFS SRVSVC request slice only supports SHARE_INFO_1 enumeration.");
            }

            uint containerPointer = reader.ReadUInt32();

            if (containerPointer != 0)
            {
                _ = reader.ReadUInt32();
                uint bufferPointer = reader.ReadUInt32();

                if (bufferPointer != 0)
                {
                    _ = reader.ReadUInt32();
                }
            }

            uint preferredMaximumLength = reader.ReadUInt32();
            uint resumeHandlePointer = reader.ReadUInt32();
            uint? resumeHandle = resumeHandlePointer == 0 ? null : reader.ReadUInt32();

            return new SrvsvcNetrShareEnumRequest
            {
                ServerName = serverName,
                Level = level,
                PreferredMaximumLength = preferredMaximumLength,
                ResumeHandle = resumeHandle
            };
        }
    }

    internal sealed class SrvsvcNetrShareEnumResponse
    {
        private const uint ErrorSuccess = 0;
        private const uint ErrorMoreData = 234;

        public uint Level { get; private set; }

        public SrvsvcShareInfo1[] Shares { get; private set; } = Array.Empty<SrvsvcShareInfo1>();

        public uint TotalEntries { get; private set; }

        public uint? ResumeHandle { get; private set; }

        public uint ReturnCode { get; private set; }

        public static SrvsvcNetrShareEnumResponse ReadFrom(ReadOnlyMemory<byte> responseBuffer)
        {
            if (responseBuffer.Length < 20)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareEnum response payload is truncated.");
            }

            LittleEndianReader reader = new LittleEndianReader(responseBuffer);
            SrvsvcNetrShareEnumResponse response = new SrvsvcNetrShareEnumResponse
            {
                Level = reader.ReadUInt32()
            };

            if (response.Level != 1)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareEnum response level is outside the bounded OpenCIFS slice.");
            }

            uint unionTag = reader.ReadUInt32();

            if (unionTag != response.Level)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareEnum response union tag does not match the requested level.");
            }

            uint containerPointer = reader.ReadUInt32();
            uint entriesRead = 0;
            uint bufferPointer = 0;
            uint maximumCount = 0;

            if (containerPointer != 0)
            {
                entriesRead = reader.ReadUInt32();
                bufferPointer = reader.ReadUInt32();

                if (bufferPointer != 0)
                {
                    maximumCount = reader.ReadUInt32();

                    if (maximumCount < entriesRead)
                    {
                        throw new ProtocolEncodingException("The SRVSVC NetrShareEnum response array count is smaller than EntriesRead.");
                    }
                }
                else if (entriesRead != 0)
                {
                    throw new ProtocolEncodingException("The SRVSVC NetrShareEnum response omitted the share-entry buffer while reporting non-zero entries.");
                }
            }

            uint[] namePointers = new uint[entriesRead];
            uint[] shareTypes = new uint[entriesRead];
            uint[] remarkPointers = new uint[entriesRead];

            for (int index = 0; index < entriesRead; index++)
            {
                namePointers[index] = reader.ReadUInt32();
                shareTypes[index] = reader.ReadUInt32();
                remarkPointers[index] = reader.ReadUInt32();
            }

            string[] names = new string[entriesRead];
            string[] remarks = new string[entriesRead];

            for (int index = 0; index < entriesRead; index++)
            {
                if (namePointers[index] == 0)
                {
                    throw new ProtocolEncodingException("The SRVSVC NetrShareEnum response contains a null share-name pointer.");
                }

                names[index] = DceRpcEncoding.ReadNdrUtf16String(reader);
                remarks[index] = remarkPointers[index] == 0 ? string.Empty : DceRpcEncoding.ReadNdrUtf16String(reader);
            }

            response.TotalEntries = reader.ReadUInt32();
            uint resumeHandlePointer = reader.ReadUInt32();

            if (resumeHandlePointer != 0)
            {
                response.ResumeHandle = reader.ReadUInt32();
            }

            response.ReturnCode = reader.ReadUInt32();

            if (response.ReturnCode != ErrorSuccess && response.ReturnCode != ErrorMoreData)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareEnum response returned unexpected error code " + response.ReturnCode + '.');
            }

            List<SrvsvcShareInfo1> shares = new List<SrvsvcShareInfo1>(checked((int)entriesRead));

            for (int index = 0; index < entriesRead; index++)
            {
                shares.Add(new SrvsvcShareInfo1
                {
                    Name = names[index],
                    Type = shareTypes[index],
                    Remark = remarks[index]
                });
            }

            response.Shares = shares.ToArray();
            return response;
        }

        public static SrvsvcNetrShareEnumResponse Create(
            IReadOnlyList<SrvsvcShareInfo1> shares,
            uint totalEntries,
            uint? resumeHandle,
            uint returnCode)
        {
            if (shares == null)
            {
                throw new ArgumentNullException(nameof(shares), "Shares cannot be null.");
            }

            if (returnCode != ErrorSuccess && returnCode != ErrorMoreData)
            {
                throw new ArgumentOutOfRangeException(nameof(returnCode), "The bounded OpenCIFS SRVSVC response slice only supports ERROR_SUCCESS and ERROR_MORE_DATA.");
            }

            SrvsvcShareInfo1[] clonedShares = new SrvsvcShareInfo1[shares.Count];

            for (int index = 0; index < shares.Count; index++)
            {
                SrvsvcShareInfo1 share = shares[index] ?? throw new ArgumentException("Shares cannot contain null entries.", nameof(shares));
                clonedShares[index] = new SrvsvcShareInfo1
                {
                    Name = share.Name ?? string.Empty,
                    Type = share.Type,
                    Remark = share.Remark ?? string.Empty
                };
            }

            return new SrvsvcNetrShareEnumResponse
            {
                Level = 1,
                Shares = clonedShares,
                TotalEntries = totalEntries,
                ResumeHandle = resumeHandle,
                ReturnCode = returnCode
            };
        }

        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(Level);
            writer.WriteUInt32(Level);
            DceRpcEncoding.WriteUniquePointer(writer, 0x00020000);
            writer.WriteUInt32((uint)Shares.Length);

            if (Shares.Length == 0)
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0);
            }
            else
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0x00030000);
                writer.WriteUInt32((uint)Shares.Length);
            }

            uint nextReferentId = 0x00040000;

            for (int index = 0; index < Shares.Length; index++)
            {
                DceRpcEncoding.WriteUniquePointer(writer, nextReferentId++);
                writer.WriteUInt32(Shares[index].Type);
                if (string.IsNullOrWhiteSpace(Shares[index].Remark))
                {
                    DceRpcEncoding.WriteUniquePointer(writer, 0);
                }
                else
                {
                    DceRpcEncoding.WriteUniquePointer(writer, nextReferentId++);
                }
            }

            for (int index = 0; index < Shares.Length; index++)
            {
                DceRpcEncoding.WriteNdrUtf16String(writer, Shares[index].Name);

                if (!string.IsNullOrWhiteSpace(Shares[index].Remark))
                {
                    DceRpcEncoding.WriteNdrUtf16String(writer, Shares[index].Remark);
                }
            }

            writer.WriteUInt32(TotalEntries);

            if (ResumeHandle.HasValue)
            {
                DceRpcEncoding.WriteUniquePointer(writer, nextReferentId++);
                writer.WriteUInt32(ResumeHandle.Value);
            }
            else
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0);
            }

            writer.WriteUInt32(ReturnCode);
            return writer.ToArray();
        }
    }

    internal sealed class SrvsvcNetrShareGetInfoRequest
    {
        public const ushort OperationNumber = 16;

        public string ServerName { get; set; } = string.Empty;

        public string ShareName { get; set; } = string.Empty;

        public uint Level { get; set; } = 2;

        public byte[] ToByteArray()
        {
            if (Level != 2)
            {
                throw new ArgumentOutOfRangeException(nameof(Level), "The bounded OpenCIFS SRVSVC get-info slice only supports SHARE_INFO_2.");
            }

            if (string.IsNullOrWhiteSpace(ShareName))
            {
                throw new ArgumentNullException(nameof(ShareName), "ShareName cannot be null or whitespace.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();

            if (string.IsNullOrWhiteSpace(ServerName))
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0);
            }
            else
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0x00010000);
                DceRpcEncoding.WriteNdrUtf16String(writer, ServerName);
            }

            DceRpcEncoding.WriteNdrUtf16String(writer, ShareName);
            writer.WriteUInt32(Level);
            return writer.ToArray();
        }

        public static SrvsvcNetrShareGetInfoRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 20)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareGetInfo request payload is truncated.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            uint serverNamePointer = reader.ReadUInt32();
            string serverName = serverNamePointer == 0 ? string.Empty : DceRpcEncoding.ReadNdrUtf16String(reader);
            string shareName = DceRpcEncoding.ReadNdrUtf16String(reader);
            uint level = reader.ReadUInt32();

            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareGetInfo request share name is missing.");
            }

            if (level != 2)
            {
                throw new ProtocolEncodingException("The bounded OpenCIFS SRVSVC get-info slice only supports SHARE_INFO_2.");
            }

            return new SrvsvcNetrShareGetInfoRequest
            {
                ServerName = serverName,
                ShareName = shareName,
                Level = level
            };
        }
    }

    internal sealed class SrvsvcNetrShareGetInfoResponse
    {
        public const uint ErrorSuccess = 0;
        public const uint ErrorAccessDenied = 5;
        public const uint ErrorInvalidLevel = 124;
        public const uint ErrorInvalidParameter = 87;
        public const uint NerrNetNameNotFound = 0x00000906;

        public SrvsvcShareInfo2? Share { get; private set; }

        public uint ReturnCode { get; private set; }

        public static SrvsvcNetrShareGetInfoResponse ReadFrom(ReadOnlyMemory<byte> responseBuffer)
        {
            if (responseBuffer.Length < 8)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareGetInfo response payload is truncated.");
            }

            LittleEndianReader reader = new LittleEndianReader(responseBuffer);
            uint discriminantOrPointer = reader.ReadUInt32();
            uint shareInfoPointer;

            if (discriminantOrPointer == 2)
            {
                shareInfoPointer = reader.ReadUInt32();
            }
            else
            {
                shareInfoPointer = discriminantOrPointer;
            }

            SrvsvcShareInfo2? share = null;

            if (shareInfoPointer != 0)
            {
                uint namePointer = reader.ReadUInt32();
                uint shareType = reader.ReadUInt32();
                uint remarkPointer = reader.ReadUInt32();
                uint permissions = reader.ReadUInt32();
                uint maximumUses = reader.ReadUInt32();
                uint currentUses = reader.ReadUInt32();
                uint pathPointer = reader.ReadUInt32();
                uint passwordPointer = reader.ReadUInt32();

                if (namePointer == 0)
                {
                    throw new ProtocolEncodingException("The SRVSVC NetrShareGetInfo response omitted the required share-name pointer.");
                }

                string name = DceRpcEncoding.ReadNdrUtf16String(reader);
                string remark = remarkPointer == 0 ? string.Empty : DceRpcEncoding.ReadNdrUtf16String(reader);
                string path = pathPointer == 0 ? string.Empty : DceRpcEncoding.ReadNdrUtf16String(reader);
                string password = passwordPointer == 0 ? string.Empty : DceRpcEncoding.ReadNdrUtf16String(reader);

                share = new SrvsvcShareInfo2
                {
                    Name = name,
                    Type = shareType,
                    Remark = remark,
                    Permissions = permissions,
                    MaximumUses = maximumUses,
                    CurrentUses = currentUses,
                    Path = path,
                    Password = password
                };
            }

            uint returnCode = reader.ReadUInt32();

            if (returnCode == ErrorSuccess && share == null)
            {
                throw new ProtocolEncodingException("The SRVSVC NetrShareGetInfo response reported success without share details.");
            }

            return new SrvsvcNetrShareGetInfoResponse
            {
                Share = share,
                ReturnCode = returnCode
            };
        }

        public static SrvsvcNetrShareGetInfoResponse Create(SrvsvcShareInfo2? share, uint returnCode)
        {
            return new SrvsvcNetrShareGetInfoResponse
            {
                Share = share,
                ReturnCode = returnCode
            };
        }

        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(2);

            if (Share == null)
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0);
            }
            else
            {
                DceRpcEncoding.WriteUniquePointer(writer, 0x00020000);
                DceRpcEncoding.WriteUniquePointer(writer, 0x00030000);
                writer.WriteUInt32(Share.Type);

                if (string.IsNullOrWhiteSpace(Share.Remark))
                {
                    DceRpcEncoding.WriteUniquePointer(writer, 0);
                }
                else
                {
                    DceRpcEncoding.WriteUniquePointer(writer, 0x00040000);
                }

                writer.WriteUInt32(Share.Permissions);
                writer.WriteUInt32(Share.MaximumUses);
                writer.WriteUInt32(Share.CurrentUses);

                if (string.IsNullOrWhiteSpace(Share.Path))
                {
                    DceRpcEncoding.WriteUniquePointer(writer, 0);
                }
                else
                {
                    DceRpcEncoding.WriteUniquePointer(writer, 0x00050000);
                }

                if (string.IsNullOrWhiteSpace(Share.Password))
                {
                    DceRpcEncoding.WriteUniquePointer(writer, 0);
                }
                else
                {
                    DceRpcEncoding.WriteUniquePointer(writer, 0x00060000);
                }

                DceRpcEncoding.WriteNdrUtf16String(writer, Share.Name);

                if (!string.IsNullOrWhiteSpace(Share.Remark))
                {
                    DceRpcEncoding.WriteNdrUtf16String(writer, Share.Remark);
                }

                if (!string.IsNullOrWhiteSpace(Share.Path))
                {
                    DceRpcEncoding.WriteNdrUtf16String(writer, Share.Path);
                }

                if (!string.IsNullOrWhiteSpace(Share.Password))
                {
                    DceRpcEncoding.WriteNdrUtf16String(writer, Share.Password);
                }
            }

            writer.WriteUInt32(ReturnCode);
            return writer.ToArray();
        }
    }
}

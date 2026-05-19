namespace OpenCIFS.Protocol
{
    using System;

    internal static class Smb2CompoundRequestPayloadLengthCalculator
    {
        internal static int GetPayloadLength(Smb2Command command, ReadOnlyMemory<byte> payload)
        {
            switch (command)
            {
                case Smb2Command.Negotiate:
                    return GetNegotiateRequestLength(payload);
                case Smb2Command.SessionSetup:
                    return GetSessionSetupRequestLength(payload);
                case Smb2Command.Cancel:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 cancel request.");
                case Smb2Command.Logoff:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 logoff request.");
                case Smb2Command.Echo:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 echo request.");
                case Smb2Command.TreeConnect:
                    return GetTreeConnectRequestLength(payload);
                case Smb2Command.TreeDisconnect:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 tree-disconnect request.");
                case Smb2Command.Create:
                    return GetCreateRequestLength(payload);
                case Smb2Command.Read:
                    return GetReadRequestLength(payload);
                case Smb2Command.Write:
                    return GetWriteRequestLength(payload);
                case Smb2Command.Lock:
                    return GetLockRequestLength(payload);
                case Smb2Command.OplockBreak:
                    return GetOplockBreakRequestLength(payload);
                case Smb2Command.Ioctl:
                    return GetIoctlRequestLength(payload);
                case Smb2Command.Close:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 close request.");
                case Smb2Command.Flush:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 flush request.");
                case Smb2Command.QueryInfo:
                    return GetQueryInfoRequestLength(payload);
                case Smb2Command.SetInfo:
                    return GetSetInfoRequestLength(payload);
                case Smb2Command.QueryDirectory:
                    return GetQueryDirectoryRequestLength(payload);
                case Smb2Command.ChangeNotify:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 32, "The buffer does not contain a complete SMB2 CHANGE_NOTIFY request.");
                default:
                    throw new ProtocolValidationException("Compound request trimming is only implemented for the current SMB 2.0.2 request surface.", nameof(command));
            }
        }

        private static int GetNegotiateRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 36;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 negotiate request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 36)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate request structure size must be 36 bytes.");
            }

            ushort dialectCount = reader.ReadUInt16();

            if (dialectCount == 0)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate request must advertise at least one dialect.");
            }

            int actualLength = checked(fixedBodyLength + (dialectCount * 2));

            if (actualLength > payload.Length)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate request dialect buffer exceeds the available payload.");
            }

            return payload.Length;
        }

        private static int GetSessionSetupRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 24;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 session-setup request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 25)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup request structure size must be 25 bytes.");
            }

            reader.Skip(10);
            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();

            if (securityBufferLength == 0)
            {
                return fixedBodyLength;
            }

            int relativeSecurityBufferOffset = securityBufferOffset - ProtocolConstants.Smb2HeaderLength;
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeSecurityBufferOffset,
                dataLength: securityBufferLength,
                invalidOffsetMessage: "The SMB2 session-setup request security-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 session-setup request security buffer exceeds the available payload.");
        }

        private static int GetTreeConnectRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 8;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 tree-connect request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 9)
            {
                throw new ProtocolEncodingException("The SMB2 tree-connect request structure size must be 9 bytes.");
            }

            reader.Skip(2);
            ushort pathOffset = reader.ReadUInt16();
            ushort pathLength = reader.ReadUInt16();
            int relativePathOffset = pathOffset - ProtocolConstants.Smb2HeaderLength;

            if ((pathLength % 2) != 0)
            {
                throw new ProtocolEncodingException("The SMB2 tree-connect request path bytes are invalid.");
            }

            if (pathLength == 0)
            {
                return fixedBodyLength;
            }

            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativePathOffset,
                dataLength: pathLength,
                invalidOffsetMessage: "The SMB2 tree-connect request path offset is invalid.",
                exceedsPayloadMessage: "The SMB2 tree-connect request path bytes are invalid.");
        }

        private static int GetOplockBreakRequestLength(ReadOnlyMemory<byte> payload)
        {
            ushort structureSize = Smb2CompoundPayloadValidationUtilities.ReadStructureSize(payload, "The buffer does not contain a complete SMB2 oplock-break acknowledgment.");

            switch (structureSize)
            {
                case 24:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 oplock-break acknowledgment.");
                case 36:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 36, "The buffer does not contain a complete SMB2 lease-break acknowledgment.");
                default:
                    throw new ProtocolValidationException("The SMB2 oplock-break request structure size is not supported in the current SMB 2.1 slice.", nameof(payload));
            }
        }

        private static int GetCreateRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 56;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 create request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 57)
            {
                throw new ProtocolEncodingException("The SMB2 create request structure size must be 57 bytes.");
            }

            reader.Skip(42);
            ushort nameOffset = reader.ReadUInt16();
            ushort nameLength = reader.ReadUInt16();
            uint createContextsOffset = reader.ReadUInt32();
            uint createContextsLength = reader.ReadUInt32();
            int actualLength = fixedBodyLength;

            if (nameLength != 0)
            {
                if ((nameLength % 2) != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 create request name bytes are invalid.");
                }

                int relativeNameOffset = nameOffset - ProtocolConstants.Smb2HeaderLength;
                int nameEnd = Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                    payloadLength: payload.Length,
                    fixedBodyLength: fixedBodyLength,
                    relativeOffset: relativeNameOffset,
                    dataLength: nameLength,
                    invalidOffsetMessage: "The SMB2 create request name offset is invalid.",
                    exceedsPayloadMessage: "The SMB2 create request name bytes are invalid.");
                actualLength = Math.Max(actualLength, nameEnd);
            }

            if (createContextsLength != 0)
            {
                if (createContextsLength > Int32.MaxValue)
                {
                    throw new ProtocolEncodingException("The SMB2 create request create-context length exceeds the supported maximum.");
                }

                int relativeCreateContextsOffset = checked((int)createContextsOffset) - ProtocolConstants.Smb2HeaderLength;
                int createContextsEnd = Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                    payloadLength: payload.Length,
                    fixedBodyLength: fixedBodyLength,
                    relativeOffset: relativeCreateContextsOffset,
                    dataLength: checked((int)createContextsLength),
                    invalidOffsetMessage: "The SMB2 create request create-context offset is invalid.",
                    exceedsPayloadMessage: "The SMB2 create request create-context buffer exceeds the available payload.");
                actualLength = Math.Max(actualLength, createContextsEnd);
            }

            return actualLength;
        }

        private static int GetReadRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 48;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 read request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 49)
            {
                throw new ProtocolEncodingException("The SMB2 read request structure size must be 49 bytes.");
            }

            reader.Skip(42);
            ushort readChannelInfoOffset = reader.ReadUInt16();
            ushort readChannelInfoLength = reader.ReadUInt16();

            if (readChannelInfoLength == 0)
            {
                return fixedBodyLength;
            }

            int relativeReadChannelInfoOffset = readChannelInfoOffset - ProtocolConstants.Smb2HeaderLength;
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeReadChannelInfoOffset,
                dataLength: readChannelInfoLength,
                invalidOffsetMessage: "The SMB2 read request channel-info offset is invalid.",
                exceedsPayloadMessage: "The SMB2 read request channel-info buffer exceeds the available payload.");
        }

        private static int GetWriteRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 48;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 write request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 49)
            {
                throw new ProtocolEncodingException("The SMB2 write request structure size must be 49 bytes.");
            }

            ushort dataOffset = reader.ReadUInt16();
            uint dataLength = reader.ReadUInt32();
            reader.Skip(32);
            ushort writeChannelInfoOffset = reader.ReadUInt16();
            ushort writeChannelInfoLength = reader.ReadUInt16();
            int actualLength = fixedBodyLength;

            if (dataLength != 0)
            {
                if (dataLength > Int32.MaxValue)
                {
                    throw new ProtocolEncodingException("The SMB2 write request data length exceeds the supported maximum.");
                }

                int relativeDataOffset = dataOffset - ProtocolConstants.Smb2HeaderLength;
                int dataEnd = Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                    payloadLength: payload.Length,
                    fixedBodyLength: fixedBodyLength,
                    relativeOffset: relativeDataOffset,
                    dataLength: checked((int)dataLength),
                    invalidOffsetMessage: "The SMB2 write request data offset is invalid.",
                    exceedsPayloadMessage: "The SMB2 write request data buffer exceeds the available payload.");
                actualLength = Math.Max(actualLength, dataEnd);
            }

            if (writeChannelInfoLength != 0)
            {
                int relativeWriteChannelInfoOffset = writeChannelInfoOffset - ProtocolConstants.Smb2HeaderLength;
                int channelInfoEnd = Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                    payloadLength: payload.Length,
                    fixedBodyLength: fixedBodyLength,
                    relativeOffset: relativeWriteChannelInfoOffset,
                    dataLength: writeChannelInfoLength,
                    invalidOffsetMessage: "The SMB2 write request channel-info offset is invalid.",
                    exceedsPayloadMessage: "The SMB2 write request channel-info buffer exceeds the available payload.");
                actualLength = Math.Max(actualLength, channelInfoEnd);
            }

            return actualLength;
        }

        private static int GetLockRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 24;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 lock request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 48)
            {
                throw new ProtocolEncodingException("The SMB2 lock request structure size must be 48 bytes.");
            }

            ushort lockCount = reader.ReadUInt16();

            if (lockCount == 0)
            {
                throw new ProtocolEncodingException("The SMB2 lock request must contain at least one lock element.");
            }

            int actualLength = checked(fixedBodyLength + (lockCount * Smb2LockElement.StructureLength));

            if (actualLength > payload.Length)
            {
                throw new ProtocolEncodingException("The SMB2 lock request lock array exceeds the available payload.");
            }

            return actualLength;
        }

        private static int GetIoctlRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 56;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 IOCTL request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 57)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request structure size must be 57 bytes.");
            }

            reader.Skip(22);
            uint inputOffset = reader.ReadUInt32();
            uint inputCount = reader.ReadUInt32();
            reader.Skip(8);
            uint outputCount = reader.ReadUInt32();

            if (outputCount != 0)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request output-count field must remain zero.");
            }

            if (inputCount == 0)
            {
                return fixedBodyLength;
            }

            if (inputCount > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request input buffer exceeds the supported maximum.");
            }

            if ((inputOffset % 8) != 0)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request input-buffer offset must be aligned to 8 bytes.");
            }

            int relativeInputOffset = checked((int)inputOffset - ProtocolConstants.Smb2HeaderLength);
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeInputOffset,
                dataLength: checked((int)inputCount),
                invalidOffsetMessage: "The SMB2 IOCTL request input-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 IOCTL request input buffer exceeds the available payload.");
        }

        private static int GetQueryInfoRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 40;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 query-info request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 41)
            {
                throw new ProtocolEncodingException("The SMB2 query-info request structure size must be 41 bytes.");
            }

            reader.Skip(6);
            ushort inputBufferOffset = reader.ReadUInt16();
            reader.Skip(2);
            uint inputBufferLength = reader.ReadUInt32();

            if (inputBufferLength == 0)
            {
                return fixedBodyLength;
            }

            if (inputBufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 query-info request input buffer exceeds the supported maximum.");
            }

            int relativeInputBufferOffset = inputBufferOffset - ProtocolConstants.Smb2HeaderLength;
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeInputBufferOffset,
                dataLength: checked((int)inputBufferLength),
                invalidOffsetMessage: "The SMB2 query-info request input-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 query-info request input buffer exceeds the available payload.");
        }

        private static int GetSetInfoRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 32;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 set-info request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 33)
            {
                throw new ProtocolEncodingException("The SMB2 set-info request structure size must be 33 bytes.");
            }

            reader.Skip(2);
            uint bufferLength = reader.ReadUInt32();
            ushort bufferOffset = reader.ReadUInt16();
            reader.Skip(2);

            if (bufferLength == 0)
            {
                return fixedBodyLength;
            }

            if (bufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 set-info request buffer exceeds the supported maximum.");
            }

            int relativeBufferOffset = bufferOffset - ProtocolConstants.Smb2HeaderLength;
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeBufferOffset,
                dataLength: checked((int)bufferLength),
                invalidOffsetMessage: "The SMB2 set-info request buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 set-info request buffer exceeds the available payload.");
        }

        private static int GetQueryDirectoryRequestLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 32;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 query-directory request.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 33)
            {
                throw new ProtocolEncodingException("The SMB2 query-directory request structure size must be 33 bytes.");
            }

            reader.Skip(22);
            ushort fileNameOffset = reader.ReadUInt16();
            ushort fileNameLength = reader.ReadUInt16();

            if (fileNameLength == 0)
            {
                return fixedBodyLength;
            }

            int relativeFileNameOffset = fileNameOffset - ProtocolConstants.Smb2HeaderLength;
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeFileNameOffset,
                dataLength: fileNameLength,
                invalidOffsetMessage: "The SMB2 query-directory request search-pattern offset is invalid.",
                exceedsPayloadMessage: "The SMB2 query-directory request search pattern exceeds the available payload.");
        }
    }
}

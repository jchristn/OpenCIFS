namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Trims zero padding from compounded SMB2 request and response payloads for the currently implemented command set.
    /// </summary>
    public static class Smb2CompoundPayloadHelper
    {
        /// <summary>
        /// Trim compound alignment padding from a raw request payload.
        /// </summary>
        /// <param name="command">SMB2 request command.</param>
        /// <param name="payload">Raw payload bytes taken from a compounded packet entry.</param>
        /// <returns>Request payload without trailing compound padding.</returns>
        public static byte[] TrimRequestPayload(Smb2Command command, ReadOnlyMemory<byte> payload)
        {
            int contentLength = GetRequestPayloadLength(command, payload);
            EnsureTrailingPaddingIsZero(payload, contentLength, "The SMB2 compounded request payload contains non-zero trailing padding.");
            return payload.Slice(0, contentLength).ToArray();
        }

        /// <summary>
        /// Trim compound alignment padding from a raw response payload.
        /// </summary>
        /// <param name="command">SMB2 response command.</param>
        /// <param name="payload">Raw payload bytes taken from a compounded packet entry.</param>
        /// <returns>Response payload without trailing compound padding.</returns>
        public static byte[] TrimResponsePayload(Smb2Command command, ReadOnlyMemory<byte> payload)
        {
            int contentLength = GetResponsePayloadLength(command, payload);
            EnsureTrailingPaddingIsZero(payload, contentLength, "The SMB2 compounded response payload contains non-zero trailing padding.");
            return payload.Slice(0, contentLength).ToArray();
        }

        private static int GetRequestPayloadLength(Smb2Command command, ReadOnlyMemory<byte> payload)
        {
            switch (command)
            {
                case Smb2Command.Negotiate:
                    return GetNegotiateRequestLength(payload);
                case Smb2Command.SessionSetup:
                    return GetSessionSetupRequestLength(payload);
                case Smb2Command.Cancel:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 cancel request.");
                case Smb2Command.Logoff:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 logoff request.");
                case Smb2Command.Echo:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 echo request.");
                case Smb2Command.TreeConnect:
                    return GetTreeConnectRequestLength(payload);
                case Smb2Command.TreeDisconnect:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 tree-disconnect request.");
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
                    return GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 close request.");
                case Smb2Command.Flush:
                    return GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 flush request.");
                case Smb2Command.QueryInfo:
                    return GetQueryInfoRequestLength(payload);
                case Smb2Command.SetInfo:
                    return GetSetInfoRequestLength(payload);
                case Smb2Command.QueryDirectory:
                    return GetQueryDirectoryRequestLength(payload);
                case Smb2Command.ChangeNotify:
                    return GetFixedPayloadLength(payload, 32, "The buffer does not contain a complete SMB2 CHANGE_NOTIFY request.");
                default:
                    throw new ProtocolValidationException("Compound request trimming is only implemented for the current SMB 2.0.2 request surface.", nameof(command));
            }
        }

        private static int GetResponsePayloadLength(Smb2Command command, ReadOnlyMemory<byte> payload)
        {
            switch (command)
            {
                case Smb2Command.Negotiate:
                    return GetNegotiateResponseLength(payload);
                case Smb2Command.SessionSetup:
                    return GetSessionSetupResponseLength(payload);
                case Smb2Command.Logoff:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 logoff response.");
                case Smb2Command.Echo:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 echo response.");
                case Smb2Command.TreeConnect:
                    return GetFixedPayloadLength(payload, 16, "The buffer does not contain a complete SMB2 tree-connect response.");
                case Smb2Command.TreeDisconnect:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 tree-disconnect response.");
                case Smb2Command.Create:
                    return GetCreateResponseLength(payload);
                case Smb2Command.Read:
                    return GetReadResponseLength(payload);
                case Smb2Command.Write:
                    return GetFixedPayloadLength(payload, 16, "The buffer does not contain a complete SMB2 write response.");
                case Smb2Command.Lock:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 lock response.");
                case Smb2Command.OplockBreak:
                    return GetOplockBreakResponseLength(payload);
                case Smb2Command.Ioctl:
                    return GetIoctlResponseLength(payload);
                case Smb2Command.Close:
                    return GetFixedPayloadLength(payload, 60, "The buffer does not contain a complete SMB2 close response.");
                case Smb2Command.Flush:
                    return GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 flush response.");
                case Smb2Command.QueryInfo:
                    return GetQueryInfoResponseLength(payload);
                case Smb2Command.SetInfo:
                    return GetFixedPayloadLength(payload, 2, "The buffer does not contain a complete SMB2 set-info response.");
                case Smb2Command.QueryDirectory:
                    return GetQueryDirectoryResponseLength(payload);
                case Smb2Command.ChangeNotify:
                    return GetChangeNotifyResponseLength(payload);
                default:
                    throw new ProtocolValidationException("Compound response trimming is only implemented for the current SMB 2.0.2 response surface.", nameof(command));
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

        private static int GetNegotiateResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 64;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 negotiate response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 65)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate response structure size must be 65 bytes.");
            }

            reader.Skip(54);
            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();

            if (securityBufferLength == 0)
            {
                return fixedBodyLength;
            }

            int relativeSecurityBufferOffset = securityBufferOffset - ProtocolConstants.Smb2HeaderLength;
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeSecurityBufferOffset,
                dataLength: securityBufferLength,
                invalidOffsetMessage: "The SMB2 negotiate response security-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 negotiate response security buffer exceeds the available payload.");
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
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeSecurityBufferOffset,
                dataLength: securityBufferLength,
                invalidOffsetMessage: "The SMB2 session-setup request security-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 session-setup request security buffer exceeds the available payload.");
        }

        private static int GetSessionSetupResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 8;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 session-setup response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 9)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup response structure size must be 9 bytes.");
            }

            reader.Skip(2);
            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();

            if (securityBufferLength == 0)
            {
                return fixedBodyLength;
            }

            int relativeSecurityBufferOffset = securityBufferOffset - ProtocolConstants.Smb2HeaderLength;
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeSecurityBufferOffset,
                dataLength: securityBufferLength,
                invalidOffsetMessage: "The SMB2 session-setup response security-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 session-setup response security buffer exceeds the available payload.");
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

            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativePathOffset,
                dataLength: pathLength,
                invalidOffsetMessage: "The SMB2 tree-connect request path offset is invalid.",
                exceedsPayloadMessage: "The SMB2 tree-connect request path bytes are invalid.");
        }

        private static int GetOplockBreakRequestLength(ReadOnlyMemory<byte> payload)
        {
            ushort structureSize = ReadStructureSize(payload, "The buffer does not contain a complete SMB2 oplock-break acknowledgment.");

            return structureSize switch
            {
                24 => GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 oplock-break acknowledgment."),
                36 => GetFixedPayloadLength(payload, 36, "The buffer does not contain a complete SMB2 lease-break acknowledgment."),
                _ => throw new ProtocolValidationException("The SMB2 oplock-break request structure size is not supported in the current SMB 2.1 slice.", nameof(payload))
            };
        }

        private static int GetOplockBreakResponseLength(ReadOnlyMemory<byte> payload)
        {
            ushort structureSize = ReadStructureSize(payload, "The buffer does not contain a complete SMB2 oplock-break response.");

            return structureSize switch
            {
                24 => GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 oplock-break response."),
                36 => GetFixedPayloadLength(payload, 36, "The buffer does not contain a complete SMB2 lease-break response."),
                44 => GetFixedPayloadLength(payload, 44, "The buffer does not contain a complete SMB2 lease-break notification."),
                _ => throw new ProtocolValidationException("The SMB2 oplock-break response structure size is not supported in the current SMB 2.1 slice.", nameof(payload))
            };
        }

        private static ushort ReadStructureSize(ReadOnlyMemory<byte> payload, string truncatedMessage)
        {
            if (payload.Length < 2)
            {
                throw new ProtocolEncodingException(truncatedMessage);
            }

            LittleEndianReader reader = new LittleEndianReader(payload);
            return reader.ReadUInt16();
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
                int nameEnd = GetVariableLengthPayloadEnd(
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
                int createContextsEnd = GetVariableLengthPayloadEnd(
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

        private static int GetCreateResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 88;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 create response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 89)
            {
                throw new ProtocolEncodingException("The SMB2 create response structure size must be 89 bytes.");
            }

            reader.Skip(78);
            uint createContextsOffset = reader.ReadUInt32();
            uint createContextsLength = reader.ReadUInt32();

            if (createContextsLength == 0)
            {
                return fixedBodyLength;
            }

            if (createContextsLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 create response create-context length exceeds the supported maximum.");
            }

            int relativeCreateContextsOffset = checked((int)createContextsOffset) - ProtocolConstants.Smb2HeaderLength;
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeCreateContextsOffset,
                dataLength: checked((int)createContextsLength),
                invalidOffsetMessage: "The SMB2 create response create-context offset is invalid.",
                exceedsPayloadMessage: "The SMB2 create response create-context buffer exceeds the available payload.");
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
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeReadChannelInfoOffset,
                dataLength: readChannelInfoLength,
                invalidOffsetMessage: "The SMB2 read request channel-info offset is invalid.",
                exceedsPayloadMessage: "The SMB2 read request channel-info buffer exceeds the available payload.");
        }

        private static int GetReadResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 16;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 read response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 17)
            {
                throw new ProtocolEncodingException("The SMB2 read response structure size must be 17 bytes.");
            }

            byte dataOffset = reader.ReadByte();
            reader.Skip(1);
            uint dataLength = reader.ReadUInt32();

            if (dataLength == 0)
            {
                return fixedBodyLength;
            }

            if (dataLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 read response data length exceeds the supported maximum.");
            }

            int relativeDataOffset = dataOffset - ProtocolConstants.Smb2HeaderLength;
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeDataOffset,
                dataLength: checked((int)dataLength),
                invalidOffsetMessage: "The SMB2 read response data offset is invalid.",
                exceedsPayloadMessage: "The SMB2 read response data buffer exceeds the available payload.");
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
                int dataEnd = GetVariableLengthPayloadEnd(
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
                int channelInfoEnd = GetVariableLengthPayloadEnd(
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
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeInputOffset,
                dataLength: checked((int)inputCount),
                invalidOffsetMessage: "The SMB2 IOCTL request input-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 IOCTL request input buffer exceeds the available payload.");
        }

        private static int GetIoctlResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 48;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 IOCTL response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 49)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL response structure size must be 49 bytes.");
            }

            reader.Skip(22);
            uint inputOffset = reader.ReadUInt32();
            uint inputCount = reader.ReadUInt32();
            uint outputOffset = reader.ReadUInt32();
            uint outputCount = reader.ReadUInt32();
            int actualLength = fixedBodyLength;

            if (inputCount != 0)
            {
                if (inputCount > Int32.MaxValue)
                {
                    throw new ProtocolEncodingException("The SMB2 IOCTL response input buffer exceeds the supported maximum.");
                }

                if ((inputOffset % 8) != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 IOCTL response input-buffer offset must be aligned to 8 bytes.");
                }

                int relativeInputOffset = checked((int)inputOffset - ProtocolConstants.Smb2HeaderLength);
                int inputEnd = GetVariableLengthPayloadEnd(
                    payloadLength: payload.Length,
                    fixedBodyLength: fixedBodyLength,
                    relativeOffset: relativeInputOffset,
                    dataLength: checked((int)inputCount),
                    invalidOffsetMessage: "The SMB2 IOCTL response input-buffer offset is invalid.",
                    exceedsPayloadMessage: "The SMB2 IOCTL response input buffer exceeds the available payload.");
                actualLength = Math.Max(actualLength, inputEnd);
            }

            if (outputCount != 0)
            {
                if (outputCount > Int32.MaxValue)
                {
                    throw new ProtocolEncodingException("The SMB2 IOCTL response output buffer exceeds the supported maximum.");
                }

                if ((outputOffset % 8) != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 IOCTL response output-buffer offset must be aligned to 8 bytes.");
                }

                int relativeOutputOffset = checked((int)outputOffset - ProtocolConstants.Smb2HeaderLength);
                int outputEnd = GetVariableLengthPayloadEnd(
                    payloadLength: payload.Length,
                    fixedBodyLength: fixedBodyLength,
                    relativeOffset: relativeOutputOffset,
                    dataLength: checked((int)outputCount),
                    invalidOffsetMessage: "The SMB2 IOCTL response output-buffer offset is invalid.",
                    exceedsPayloadMessage: "The SMB2 IOCTL response output buffer exceeds the available payload.");
                actualLength = Math.Max(actualLength, outputEnd);
            }

            return actualLength;
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
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeInputBufferOffset,
                dataLength: checked((int)inputBufferLength),
                invalidOffsetMessage: "The SMB2 query-info request input-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 query-info request input buffer exceeds the available payload.");
        }

        private static int GetQueryInfoResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 8;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 query-info response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 9)
            {
                throw new ProtocolEncodingException("The SMB2 query-info response structure size must be 9 bytes.");
            }

            ushort outputBufferOffset = reader.ReadUInt16();
            uint outputBufferLength = reader.ReadUInt32();

            if (outputBufferLength == 0)
            {
                return fixedBodyLength;
            }

            if (outputBufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 query-info response output buffer exceeds the supported maximum.");
            }

            int relativeOutputBufferOffset = outputBufferOffset - ProtocolConstants.Smb2HeaderLength;
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeOutputBufferOffset,
                dataLength: checked((int)outputBufferLength),
                invalidOffsetMessage: "The SMB2 query-info response output-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 query-info response output buffer exceeds the available payload.");
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
            return GetVariableLengthPayloadEnd(
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
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeFileNameOffset,
                dataLength: fileNameLength,
                invalidOffsetMessage: "The SMB2 query-directory request search-pattern offset is invalid.",
                exceedsPayloadMessage: "The SMB2 query-directory request search pattern exceeds the available payload.");
        }

        private static int GetQueryDirectoryResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 8;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 query-directory response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 9)
            {
                throw new ProtocolEncodingException("The SMB2 query-directory response structure size must be 9 bytes.");
            }

            ushort outputBufferOffset = reader.ReadUInt16();
            uint outputBufferLength = reader.ReadUInt32();

            if (outputBufferLength == 0)
            {
                return fixedBodyLength;
            }

            if (outputBufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 query-directory response output buffer exceeds the supported maximum.");
            }

            int relativeOutputBufferOffset = outputBufferOffset - ProtocolConstants.Smb2HeaderLength;
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeOutputBufferOffset,
                dataLength: checked((int)outputBufferLength),
                invalidOffsetMessage: "The SMB2 query-directory response output-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 query-directory response output buffer exceeds the available payload.");
        }

        private static int GetChangeNotifyResponseLength(ReadOnlyMemory<byte> payload)
        {
            const int fixedBodyLength = 8;

            if (payload.Length < fixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 CHANGE_NOTIFY response.");
            }

            LittleEndianReader reader = new LittleEndianReader(payload);

            if (reader.ReadUInt16() != 9)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY response structure size must be 9 bytes.");
            }

            ushort outputBufferOffset = reader.ReadUInt16();
            uint outputBufferLength = reader.ReadUInt32();

            if (outputBufferLength == 0)
            {
                return fixedBodyLength;
            }

            if (outputBufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY response output buffer exceeds the supported maximum.");
            }

            int relativeOutputBufferOffset = outputBufferOffset - ProtocolConstants.Smb2HeaderLength;
            return GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeOutputBufferOffset,
                dataLength: checked((int)outputBufferLength),
                invalidOffsetMessage: "The SMB2 CHANGE_NOTIFY response output-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 CHANGE_NOTIFY response output buffer exceeds the available payload.");
        }

        private static int GetFixedPayloadLength(ReadOnlyMemory<byte> payload, int expectedLength, string incompleteMessage)
        {
            if (payload.Length < expectedLength)
            {
                throw new ProtocolEncodingException(incompleteMessage);
            }

            return expectedLength;
        }

        private static int GetVariableLengthPayloadEnd(int payloadLength, int fixedBodyLength, int relativeOffset, int dataLength, string invalidOffsetMessage, string exceedsPayloadMessage)
        {
            if (relativeOffset < fixedBodyLength)
            {
                throw new ProtocolEncodingException(invalidOffsetMessage);
            }

            int endOffset = checked(relativeOffset + dataLength);

            if (endOffset > payloadLength)
            {
                throw new ProtocolEncodingException(exceedsPayloadMessage);
            }

            return endOffset;
        }

        private static void EnsureTrailingPaddingIsZero(ReadOnlyMemory<byte> payload, int contentLength, string errorMessage)
        {
            if (contentLength < 0 || contentLength > payload.Length)
            {
                throw new ProtocolEncodingException("The SMB2 compounded payload length is invalid.");
            }

            ReadOnlySpan<byte> trailingSpan = payload.Span.Slice(contentLength);

            for (int index = 0; index < trailingSpan.Length; index++)
            {
                if (trailingSpan[index] != 0)
                {
                    throw new ProtocolEncodingException(errorMessage);
                }
            }
        }
    }
}

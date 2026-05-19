namespace OpenCIFS.Protocol
{
    using System;

    internal static class Smb2CompoundResponsePayloadLengthCalculator
    {
        internal static int GetPayloadLength(Smb2Command command, ReadOnlyMemory<byte> payload)
        {
            switch (command)
            {
                case Smb2Command.Negotiate:
                    return GetNegotiateResponseLength(payload);
                case Smb2Command.SessionSetup:
                    return GetSessionSetupResponseLength(payload);
                case Smb2Command.Logoff:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 logoff response.");
                case Smb2Command.Echo:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 echo response.");
                case Smb2Command.TreeConnect:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 16, "The buffer does not contain a complete SMB2 tree-connect response.");
                case Smb2Command.TreeDisconnect:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 tree-disconnect response.");
                case Smb2Command.Create:
                    return GetCreateResponseLength(payload);
                case Smb2Command.Read:
                    return GetReadResponseLength(payload);
                case Smb2Command.Write:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 16, "The buffer does not contain a complete SMB2 write response.");
                case Smb2Command.Lock:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 lock response.");
                case Smb2Command.OplockBreak:
                    return GetOplockBreakResponseLength(payload);
                case Smb2Command.Ioctl:
                    return GetIoctlResponseLength(payload);
                case Smb2Command.Close:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 60, "The buffer does not contain a complete SMB2 close response.");
                case Smb2Command.Flush:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 4, "The buffer does not contain a complete SMB2 flush response.");
                case Smb2Command.QueryInfo:
                    return GetQueryInfoResponseLength(payload);
                case Smb2Command.SetInfo:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 2, "The buffer does not contain a complete SMB2 set-info response.");
                case Smb2Command.QueryDirectory:
                    return GetQueryDirectoryResponseLength(payload);
                case Smb2Command.ChangeNotify:
                    return GetChangeNotifyResponseLength(payload);
                default:
                    throw new ProtocolValidationException("Compound response trimming is only implemented for the current SMB 2.0.2 response surface.", nameof(command));
            }
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

            reader.Skip(2);
            ushort dialectRevision = reader.ReadUInt16();
            ushort negotiateContextCount = reader.ReadUInt16();
            reader.Skip(48);
            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();
            uint negotiateContextOffset = reader.ReadUInt32();
            int actualLength = fixedBodyLength;

            if (securityBufferLength != 0)
            {
                int relativeSecurityBufferOffset = securityBufferOffset - ProtocolConstants.Smb2HeaderLength;
                int securityEnd = Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                    payloadLength: payload.Length,
                    fixedBodyLength: fixedBodyLength,
                    relativeOffset: relativeSecurityBufferOffset,
                    dataLength: securityBufferLength,
                    invalidOffsetMessage: "The SMB2 negotiate response security-buffer offset is invalid.",
                    exceedsPayloadMessage: "The SMB2 negotiate response security buffer exceeds the available payload.");
                actualLength = Math.Max(actualLength, securityEnd);
            }

            if (dialectRevision == SmbDialectCatalog.ToSmb2WireDialect(SmbDialect.Smb311) && negotiateContextCount != 0)
            {
                if (negotiateContextOffset > Int32.MaxValue)
                {
                    throw new ProtocolEncodingException("The SMB 3.1.1 negotiate response negotiate-context offset is malformed.");
                }

                int relativeNegotiateContextOffset = checked((int)negotiateContextOffset - ProtocolConstants.Smb2HeaderLength);

                if (relativeNegotiateContextOffset < fixedBodyLength || relativeNegotiateContextOffset > payload.Length)
                {
                    throw new ProtocolEncodingException("The SMB 3.1.1 negotiate response negotiate-context offset is malformed.");
                }

                actualLength = Math.Max(actualLength, payload.Length);
            }

            return actualLength;
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
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeSecurityBufferOffset,
                dataLength: securityBufferLength,
                invalidOffsetMessage: "The SMB2 session-setup response security-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 session-setup response security buffer exceeds the available payload.");
        }

        private static int GetOplockBreakResponseLength(ReadOnlyMemory<byte> payload)
        {
            ushort structureSize = Smb2CompoundPayloadValidationUtilities.ReadStructureSize(payload, "The buffer does not contain a complete SMB2 oplock-break response.");

            switch (structureSize)
            {
                case 24:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 24, "The buffer does not contain a complete SMB2 oplock-break response.");
                case 36:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 36, "The buffer does not contain a complete SMB2 lease-break response.");
                case 44:
                    return Smb2CompoundPayloadValidationUtilities.GetFixedPayloadLength(payload, 44, "The buffer does not contain a complete SMB2 lease-break notification.");
                default:
                    throw new ProtocolValidationException("The SMB2 oplock-break response structure size is not supported in the current SMB 2.1 slice.", nameof(payload));
            }
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
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeCreateContextsOffset,
                dataLength: checked((int)createContextsLength),
                invalidOffsetMessage: "The SMB2 create response create-context offset is invalid.",
                exceedsPayloadMessage: "The SMB2 create response create-context buffer exceeds the available payload.");
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
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeDataOffset,
                dataLength: checked((int)dataLength),
                invalidOffsetMessage: "The SMB2 read response data offset is invalid.",
                exceedsPayloadMessage: "The SMB2 read response data buffer exceeds the available payload.");
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
                int inputEnd = Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
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
                int outputEnd = Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
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
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeOutputBufferOffset,
                dataLength: checked((int)outputBufferLength),
                invalidOffsetMessage: "The SMB2 query-info response output-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 query-info response output buffer exceeds the available payload.");
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
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
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
            return Smb2CompoundPayloadValidationUtilities.GetVariableLengthPayloadEnd(
                payloadLength: payload.Length,
                fixedBodyLength: fixedBodyLength,
                relativeOffset: relativeOutputBufferOffset,
                dataLength: checked((int)outputBufferLength),
                invalidOffsetMessage: "The SMB2 CHANGE_NOTIFY response output-buffer offset is invalid.",
                exceedsPayloadMessage: "The SMB2 CHANGE_NOTIFY response output buffer exceeds the available payload.");
        }
    }
}

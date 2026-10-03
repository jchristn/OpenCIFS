namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Reflection;
    using System.Text;

    /// <summary>
    /// Bounded, allocation-free label formatting shared by the client and server telemetry.
    /// </summary>
    /// <remarks>
    /// Every value returned here comes from a fixed vocabulary, so metric label cardinality stays bounded even when a peer
    /// sends unknown commands or status codes. Thread-safe: all lookup tables are built once and are read-only afterwards.
    /// </remarks>
    internal static class OpenCifsTelemetryFormat
    {
        internal const string OutcomeSuccess = "success";
        internal const string OutcomeWarning = "warning";
        internal const string OutcomeError = "error";
        internal const string OutcomeException = "exception";
        internal const string OutcomeCancelled = "cancelled";
        internal const string Other = "OTHER";
        internal const string Unknown = "unknown";

        internal static string CommandName(Smb2Command command)
        {
            int index = (int)command;
            return index >= 0 && index < _CommandNames.Length ? _CommandNames[index] : Other;
        }

        internal static string StatusName(NtStatus status)
        {
            return _StatusNames.TryGetValue(status, out string? name) ? name : Other;
        }

        internal static string Outcome(NtStatus status)
        {
            // MORE_PROCESSING_REQUIRED carries error severity on the wire but is the normal mid-handshake reply.
            if (status == NtStatus.MoreProcessingRequired)
            {
                return OutcomeSuccess;
            }

            uint severity = (uint)status >> 30;

            if (severity == 3)
            {
                return OutcomeError;
            }

            return severity == 2 ? OutcomeWarning : OutcomeSuccess;
        }

        internal static string DialectName(SmbDialect? dialect)
        {
            switch (dialect)
            {
                case SmbDialect.Cifs10:
                    return "1.0";
                case SmbDialect.Smb2002:
                    return "2.0.2";
                case SmbDialect.Smb21:
                    return "2.1";
                case SmbDialect.Smb30:
                    return "3.0";
                case SmbDialect.Smb302:
                    return "3.0.2";
                case SmbDialect.Smb311:
                    return "3.1.1";
                default:
                    return Unknown;
            }
        }

        internal static string ErrorType(Exception exception)
        {
            // Exception type names are bounded by the code base, unlike messages, which can carry paths or peer input.
            return exception.GetType().Name;
        }

        internal static double ElapsedSeconds(long startTimestamp)
        {
            return (Stopwatch.GetTimestamp() - startTimestamp) / (double)Stopwatch.Frequency;
        }

        internal static string AssemblyVersion(Assembly assembly)
        {
            AssemblyInformationalVersionAttribute? attribute = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
            string version = attribute?.InformationalVersion ?? assembly.GetName().Version?.ToString() ?? Unknown;
            int metadataIndex = version.IndexOf('+');
            return metadataIndex > 0 ? version.Substring(0, metadataIndex) : version;
        }

        private static string ToUpperSnake(string pascalName)
        {
            StringBuilder builder = new StringBuilder(pascalName.Length + 8);

            for (int index = 0; index < pascalName.Length; index++)
            {
                char current = pascalName[index];

                if (index > 0 && Char.IsUpper(current) && !Char.IsUpper(pascalName[index - 1]))
                {
                    builder.Append('_');
                }

                builder.Append(Char.ToUpperInvariant(current));
            }

            return builder.ToString();
        }

        private static string[] BuildCommandNames()
        {
            Smb2Command[] commands = Enum.GetValues<Smb2Command>();
            int maximum = 0;

            for (int index = 0; index < commands.Length; index++)
            {
                maximum = Math.Max(maximum, (int)commands[index]);
            }

            string[] names = new string[maximum + 1];

            for (int index = 0; index < names.Length; index++)
            {
                names[index] = Other;
            }

            for (int index = 0; index < commands.Length; index++)
            {
                names[(int)commands[index]] = ToUpperSnake(commands[index].ToString());
            }

            return names;
        }

        private static Dictionary<NtStatus, string> BuildStatusNames()
        {
            Dictionary<NtStatus, string> names = new Dictionary<NtStatus, string>();
            NtStatus[] statuses = Enum.GetValues<NtStatus>();

            for (int index = 0; index < statuses.Length; index++)
            {
                names[statuses[index]] = ToUpperSnake(statuses[index].ToString());
            }

            return names;
        }

        private static readonly string[] _CommandNames = BuildCommandNames();
        private static readonly Dictionary<NtStatus, string> _StatusNames = BuildStatusNames();
    }
}

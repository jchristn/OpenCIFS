namespace OpenCIFS.SambaInterop.Console
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using OpenCIFS.Protocol;

    internal static class SambaInteropArgumentParser
    {
        internal static SambaInteropOptions ParseArguments(string[] args)
        {
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            for (int index = 0; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException("Arguments must be provided as --name value pairs.");
                }

                values[args[index][2..]] = args[index + 1];
            }

            return new SambaInteropOptions
            {
                Server = GetRequired(values, "server"),
                Port = Int32.Parse(GetRequired(values, "port"), CultureInfo.InvariantCulture),
                Share = GetRequired(values, "share"),
                UserName = GetRequired(values, "username"),
                Password = GetRequired(values, "password"),
                Domain = GetRequired(values, "domain"),
                Dialect = values.TryGetValue("dialect", out string? dialectValue) ? ParseDialect(dialectValue) : SmbDialect.Smb21,
                LargePayloadLength = values.TryGetValue("large-payload-length", out string? largePayloadLengthValue)
                    ? Int32.Parse(largePayloadLengthValue, CultureInfo.InvariantCulture)
                    : 200000,
                OutputPath = values.TryGetValue("output", out string? outputPath) ? outputPath : String.Empty
            };
        }

        internal static SmbDialect ParseDialect(string value)
        {
            return value switch
            {
                "Smb2002" => SmbDialect.Smb2002,
                "Smb21" => SmbDialect.Smb21,
                "Smb30" => SmbDialect.Smb30,
                "Smb302" => SmbDialect.Smb302,
                "Smb311" => SmbDialect.Smb311,
                _ => throw new ArgumentException("Unsupported dialect '" + value + "'.")
            };
        }

        internal static string GetDialectLabel(SmbDialect dialect)
        {
            return dialect switch
            {
                SmbDialect.Smb2002 => "SMB 2.0.2",
                SmbDialect.Smb21 => "SMB 2.1",
                SmbDialect.Smb30 => "SMB 3.0",
                SmbDialect.Smb302 => "SMB 3.0.2",
                SmbDialect.Smb311 => "SMB 3.1.1",
                _ => dialect.ToString()
            };
        }

        private static string GetRequired(IReadOnlyDictionary<string, string> values, string name)
        {
            if (!values.TryGetValue(name, out string? value) || String.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("Missing required argument --" + name + ".");
            }

            return value;
        }
    }
}

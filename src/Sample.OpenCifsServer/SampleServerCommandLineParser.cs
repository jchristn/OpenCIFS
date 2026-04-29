namespace Sample.OpenCifsServer
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Parses command-line arguments for the sample server utility.
    /// </summary>
    public static class SampleServerCommandLineParser
    {
        /// <summary>
        /// Parse command-line arguments.
        /// </summary>
        /// <param name="args">Raw command-line arguments.</param>
        /// <returns>Parsed options.</returns>
        public static SampleServerCommandLineOptions Parse(string[] args)
        {
            SampleServerCommandLineOptions options = new SampleServerCommandLineOptions();

            for (int index = 0; index < args.Length; index++)
            {
                string argument = args[index];

                switch (argument.ToLowerInvariant())
                {
                    case "--config":
                        options.ConfigurationPath = ReadValue(args, ref index, argument);
                        break;
                    case "--write-default-config":
                        options.WriteDefaultConfiguration = true;
                        break;
                    case "--print-config":
                        options.PrintConfiguration = true;
                        break;
                    case "--validate-config":
                        options.ValidateConfiguration = true;
                        break;
                    case "--server-name":
                        options.ServerName = ReadValue(args, ref index, argument);
                        break;
                    case "--bind-address":
                        options.BindAddress = ReadValue(args, ref index, argument);
                        break;
                    case "--bind-port":
                        options.BindPort = ParseInt32(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--share-name":
                        options.ShareName = ReadValue(args, ref index, argument);
                        break;
                    case "--share-path":
                        options.SharePath = ReadValue(args, ref index, argument);
                        break;
                    case "--minimum-dialect":
                        options.MinimumDialect = ParseDialect(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--maximum-dialect":
                        options.MaximumDialect = ParseDialect(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--require-signing":
                        options.RequireSigning = ParseBoolean(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--require-ntlmv2":
                        options.RequireNtlmV2 = ParseBoolean(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--allow-anonymous":
                        options.AllowAnonymous = ParseBoolean(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--enable-smb1":
                        options.EnableSmb1 = ParseBoolean(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--require-encryption-for-smb3":
                        options.RequireEncryptionForSmb3 = ParseBoolean(argument, ReadValue(args, ref index, argument));
                        break;
                    case "--account-username":
                        options.AccountUserName = ReadValue(args, ref index, argument);
                        break;
                    case "--account-domain":
                        options.AccountUserDomain = ReadValue(args, ref index, argument);
                        break;
                    case "--account-password":
                        options.AccountPassword = ReadValue(args, ref index, argument);
                        break;
                    default:
                        throw new ArgumentException("Unknown argument: " + argument + ".", nameof(args));
                }
            }

            ValidateModes(options);
            return options;
        }

        private static void ValidateModes(SampleServerCommandLineOptions options)
        {
            int modeCount = 0;

            if (options.WriteDefaultConfiguration)
            {
                modeCount++;
            }

            if (options.PrintConfiguration)
            {
                modeCount++;
            }

            if (options.ValidateConfiguration)
            {
                modeCount++;
            }

            if (modeCount > 1)
            {
                throw new ArgumentException("Specify at most one of --write-default-config, --print-config, or --validate-config.");
            }
        }

        private static string ReadValue(string[] args, ref int index, string argumentName)
        {
            if (index + 1 >= args.Length)
            {
                throw new ArgumentException("Missing value for " + argumentName + ".", nameof(args));
            }

            index++;
            return args[index];
        }

        private static bool ParseBoolean(string argumentName, string value)
        {
            if (!Boolean.TryParse(value, out bool parsedValue))
            {
                throw new ArgumentException("Invalid Boolean value for " + argumentName + ": " + value + ".");
            }

            return parsedValue;
        }

        private static int ParseInt32(string argumentName, string value)
        {
            if (!Int32.TryParse(value, out int parsedValue))
            {
                throw new ArgumentException("Invalid integer value for " + argumentName + ": " + value + ".");
            }

            return parsedValue;
        }

        private static SmbDialect ParseDialect(string argumentName, string value)
        {
            if (!Enum.TryParse(value, ignoreCase: true, out SmbDialect parsedValue))
            {
                throw new ArgumentException("Invalid SMB dialect value for " + argumentName + ": " + value + ".");
            }

            return parsedValue;
        }
    }
}

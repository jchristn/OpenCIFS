namespace OpenCIFS.TestServer
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using OpenCIFS.Protocol;

    internal static class TestServerArgumentParsing
    {
        internal static string DisplayOrBlank(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "(blank)" : value;
        }

        internal static int ParsePositiveInt(string value, int minimum, int maximum)
        {
            if (!int.TryParse(value, out int parsed))
            {
                throw new ArgumentException("Expected an integer value.");
            }

            if (parsed < minimum || parsed > maximum)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Expected a value between " + minimum + " and " + maximum + ".");
            }

            return parsed;
        }

        internal static TimeSpan ParseDelay(string value)
        {
            if (!double.TryParse(value, out double seconds) || seconds < 0)
            {
                throw new ArgumentException("Expected a non-negative seconds value.");
            }

            return TimeSpan.FromSeconds(seconds);
        }

        internal static bool ParseBooleanSwitch(string value)
        {
            switch (value.Trim().ToLowerInvariant())
            {
                case "1":
                case "true":
                case "on":
                case "yes":
                    return true;
                case "0":
                case "false":
                case "off":
                case "no":
                    return false;
                default:
                    throw new ArgumentException("Expected on/off, true/false, yes/no, or 1/0.");
            }
        }

        internal static SmbDialect ParseDialect(string value)
        {
            switch (value.Trim().ToLowerInvariant())
            {
                case "cifs":
                case "cifs10":
                case "smb1":
                    return SmbDialect.Cifs10;
                case "smb2002":
                case "2.0.2":
                case "smb2":
                    return SmbDialect.Smb2002;
                case "smb21":
                case "2.1":
                    return SmbDialect.Smb21;
                case "smb30":
                case "3.0":
                    return SmbDialect.Smb30;
                case "smb302":
                case "3.0.2":
                    return SmbDialect.Smb302;
                case "smb311":
                case "3.1.1":
                    return SmbDialect.Smb311;
                default:
                    if (Enum.TryParse(value, ignoreCase: true, out SmbDialect parsedDialect))
                    {
                        return parsedDialect;
                    }

                    throw new ArgumentException("Unknown dialect value: " + value);
            }
        }

        internal static void ValidateDialectRange(SmbDialect minimumDialect, SmbDialect maximumDialect)
        {
            if (maximumDialect < minimumDialect)
            {
                throw new ArgumentException("Maximum dialect must be greater than or equal to minimum dialect.");
            }
        }

        internal static void RequireArgumentCount(string[] parts, int minimumLength, string usage)
        {
            if (parts.Length < minimumLength)
            {
                throw new ArgumentException("Usage: " + usage);
            }
        }

        internal static string ReadSecret(string prompt)
        {
            Console.Write(prompt);

            if (Console.IsInputRedirected)
            {
                string? redirectedValue = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(redirectedValue))
                {
                    throw new ArgumentException("A password value is required.");
                }

                return redirectedValue;
            }

            StringBuilder builder = new StringBuilder();

            while (true)
            {
                ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);

                if (keyInfo.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (keyInfo.Key == ConsoleKey.Backspace)
                {
                    if (builder.Length > 0)
                    {
                        builder.Length -= 1;
                        Console.Write("\b \b");
                    }

                    continue;
                }

                if (!char.IsControl(keyInfo.KeyChar))
                {
                    builder.Append(keyInfo.KeyChar);
                    Console.Write("*");
                }
            }

            if (builder.Length == 0)
            {
                throw new ArgumentException("A password value is required.");
            }

            return builder.ToString();
        }

        internal static string[] Tokenize(string commandText)
        {
            StringBuilder current = new StringBuilder();
            List<string> tokens = new List<string>();
            bool inQuotes = false;

            for (int index = 0; index < commandText.Length; index++)
            {
                char currentCharacter = commandText[index];

                if (currentCharacter == '"')
                {
                    inQuotes = !inQuotes;
                    continue;
                }

                if (!inQuotes && char.IsWhiteSpace(currentCharacter))
                {
                    if (current.Length > 0)
                    {
                        tokens.Add(current.ToString());
                        current.Clear();
                    }

                    continue;
                }

                current.Append(currentCharacter);
            }

            if (current.Length > 0)
            {
                tokens.Add(current.ToString());
            }

            return tokens.ToArray();
        }
    }
}

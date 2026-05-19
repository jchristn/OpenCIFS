namespace OpenCIFS.TestServer
{
    using System;

    internal static class TestServerConsoleHelpers
    {
        internal static void ShowMenu(TestServerState state)
        {
            if (state == null)
            {
                throw new ArgumentNullException(nameof(state), "State cannot be null.");
            }

            Console.WriteLine();
            Console.WriteLine("Available commands:");
            WriteMenuCommand("?", "help");
            WriteMenuCommand("q", "quit");
            WriteMenuCommand("cls", "clear the screen");
            WriteMenuCommand("status", "show current configuration and runtime state");
            Console.WriteLine();
            WriteMenuCommand("server <name>", "set the SMB server name advertised to clients", state.ServerName);
            WriteMenuCommand("bind <address>", "set the bind address", state.BindAddress);
            WriteMenuCommand("port <number>", "set the bind port", state.BindPort.ToString());
            WriteMenuCommand("share <name>", "set the exposed share name", state.ShareName);
            WriteMenuCommand("user <name>", "set the in-memory account name", state.UserName);
            WriteMenuCommand("domain [value]", "set or clear the in-memory account domain", FormatCurrentText(state.UserDomain));
            WriteMenuCommand("password [value]", "set the in-memory account password; omit value to prompt", FormatPasswordState(state.Password));
            WriteMenuCommand("dialects <min> <max>", "set the dialect range", FormatDialectRange(state.MinimumDialect, state.MaximumDialect));
            WriteMenuCommand("signing <on|off>", "require or relax signing", FormatOnOff(state.RequireSigning));
            WriteMenuCommand("encryption <on|off>", "require or relax SMB3 encryption", FormatOnOff(state.RequireEncryptionForSmb3));
            Console.WriteLine();
            WriteMenuCommand("root", "show the temporary backing-store path", state.RootPath);
            WriteMenuCommand("root reset", "replace the temporary backing store with a new directory");
            WriteMenuCommand("openroot", "open the backing store in Explorer");
            WriteMenuCommand("dir [relative-path]", "list the local backing-store directory");
            WriteMenuCommand("shares", "show the shares that the configured server exposes");
            WriteMenuCommand("pipes", "show the bounded named-pipe endpoints exposed under IPC$");
            Console.WriteLine();
            WriteMenuCommand("start", "start the server listener");
            WriteMenuCommand("stop", "stop the server listener");
            WriteMenuCommand("wait <seconds>", "pause the console, useful for scripted smoke runs");
            Console.WriteLine();
        }

        internal static void ShowStatus(TestServerState state, string connectHostHint, string[] defaultPipeNames)
        {
            Console.WriteLine();
            Console.WriteLine("Configuration:");
            Console.WriteLine("  ServerName          : " + state.ServerName);
            Console.WriteLine("  BindAddress         : " + state.BindAddress);
            Console.WriteLine("  BindPort            : " + state.BindPort);
            Console.WriteLine("  ShareName           : " + state.ShareName);
            Console.WriteLine("  Temporary Root      : " + state.RootPath);
            Console.WriteLine("  User                : " + state.UserName);
            Console.WriteLine("  Domain              : " + TestServerArgumentParsing.DisplayOrBlank(state.UserDomain));
            Console.WriteLine("  Password Set        : " + (!string.IsNullOrWhiteSpace(state.Password)));
            Console.WriteLine("  Dialects            : " + state.MinimumDialect + " -> " + state.MaximumDialect);
            Console.WriteLine("  Require Signing     : " + state.RequireSigning);
            Console.WriteLine("  Require SMB3 Encryption: " + state.RequireEncryptionForSmb3);
            Console.WriteLine();
            Console.WriteLine("Runtime:");
            Console.WriteLine("  Running             : " + (state.Application != null && state.Application.IsRunning));
            Console.WriteLine("  UNC Hint            : \\\\" + state.ServerName + "\\" + state.ShareName);
            Console.WriteLine("  Direct-TCP Hint     : " + connectHostHint + ":" + state.BindPort);
            Console.WriteLine("  Named Pipes         : " + string.Join(", ", defaultPipeNames));
            Console.WriteLine();
        }

        private static void WriteMenuCommand(string command, string description, string? currentValue = null)
        {
            string line = "  " + command.PadRight(26) + description;
            if (!string.IsNullOrWhiteSpace(currentValue))
            {
                line += " (current: " + currentValue + ")";
            }

            Console.WriteLine(line);
        }

        private static string FormatPasswordState(string password)
        {
            return string.IsNullOrWhiteSpace(password) ? "not set" : "set";
        }

        private static string FormatDialectRange(OpenCIFS.Protocol.SmbDialect minimumDialect, OpenCIFS.Protocol.SmbDialect maximumDialect)
        {
            return minimumDialect + " -> " + maximumDialect;
        }

        private static string FormatOnOff(bool value)
        {
            return value ? "on" : "off";
        }

        private static string FormatCurrentText(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "blank" : value;
        }
    }
}

namespace OpenCIFS.TestClient
{
    using System;
    using OpenCIFS.Client;
    using OpenCIFS.Protocol;

    internal static class TestClientConsoleHelpers
    {
        internal static void ShowMenu(TestClientState state)
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
            WriteMenuCommand("status", "show client configuration and connection state");
            Console.WriteLine();
            WriteMenuCommand("server <host>", "set the SMB server host or address", state.ServerName);
            WriteMenuCommand("port <number>", "set the direct-TCP port", state.ServerPort.ToString());
            WriteMenuCommand("user <name>", "set the user name", state.UserName);
            WriteMenuCommand("domain [value]", "set or clear the user domain", FormatCurrentText(state.UserDomain));
            WriteMenuCommand("password [value]", "set the password; omit value to prompt", FormatPasswordState(state.Password));
            WriteMenuCommand("dialects <min> <max>", "set the dialect range", FormatDialectRange(state.MinimumDialect, state.MaximumDialect));
            WriteMenuCommand("signing <on|off>", "require or relax signing", FormatOnOff(state.RequireSigning));
            WriteMenuCommand("encryption <on|off>", "prefer or avoid encryption when supported", FormatOnOff(state.PreferEncryption));
            WriteMenuCommand("timeout <milliseconds>", "set the connect timeout", state.ConnectTimeoutMs + " ms");
            Console.WriteLine();
            WriteMenuCommand("shares [server]", "list shares through OpenCIFS IPC$/srvsvc browsing");
            Console.WriteLine("                             requires credentials that can authenticate to the target SMB server");
            WriteMenuCommand("shareinfo <share>", "query bounded detailed share information through OpenCIFS IPC$/srvsvc");
            WriteMenuCommand("pipe <name> <text>", "transceive UTF-8 text through a bounded named pipe under IPC$");
            WriteMenuCommand("connect", "connect and authenticate");
            WriteMenuCommand("disconnect", "close the active client session");
            WriteMenuCommand("open <share>", "open a share-scoped work session", state.ShareSession?.ShareName ?? "none");
            WriteMenuCommand("close", "close the active share session");
            Console.WriteLine();
            WriteMenuCommand("pwd", "show the current remote directory", TestClientPathUtilities.GetDisplayRemotePath(state.CurrentRemotePath));
            WriteMenuCommand("cd [path]", "change the current remote directory", TestClientPathUtilities.GetDisplayRemotePath(state.CurrentRemotePath));
            WriteMenuCommand("ls [path] [pattern]", "enumerate a directory");
            WriteMenuCommand("tree [path]", "recursively enumerate a directory");
            WriteMenuCommand("stat [path]", "show metadata for a file or directory");
            WriteMenuCommand("mkdir <path>", "create a directory");
            WriteMenuCommand("rmdir <path>", "delete an empty directory");
            WriteMenuCommand("cat <path>", "read a UTF-8 text file");
            WriteMenuCommand("write-text <path> <text>", "write UTF-8 text to a file");
            WriteMenuCommand("put <local> <remote>", "upload a local file");
            WriteMenuCommand("get <remote> <local>", "download a remote file");
            WriteMenuCommand("rm <path>", "delete a file");
            WriteMenuCommand("mv <source> <dest>", "rename a file or directory");
            WriteMenuCommand("wait <seconds>", "pause the console, useful for scripted smoke runs");
            Console.WriteLine();
        }

        internal static void ShowStatus(
            string serverName,
            int serverPort,
            string userName,
            string userDomain,
            string password,
            SmbDialect minimumDialect,
            SmbDialect maximumDialect,
            bool requireSigning,
            bool preferEncryption,
            int connectTimeoutMs,
            OpenCifsClient? client,
            OpenCifsShareSession? shareSession,
            string currentRemotePath)
        {
            Console.WriteLine();
            Console.WriteLine("Configuration:");
            Console.WriteLine("  Server           : " + serverName);
            Console.WriteLine("  Port             : " + serverPort);
            Console.WriteLine("  User             : " + userName);
            Console.WriteLine("  Domain           : " + DisplayOrBlank(userDomain));
            Console.WriteLine("  Password Set     : " + (!string.IsNullOrWhiteSpace(password)));
            Console.WriteLine("  Dialects         : " + minimumDialect + " -> " + maximumDialect);
            Console.WriteLine("  Require Signing  : " + requireSigning);
            Console.WriteLine("  Prefer Encryption: " + preferEncryption);
            Console.WriteLine("  Connect Timeout  : " + connectTimeoutMs + " ms");
            Console.WriteLine();
            Console.WriteLine("Runtime:");

            if (client == null)
            {
                Console.WriteLine("  Client           : not connected");
            }
            else
            {
                Console.WriteLine("  Client           : created");
                Console.WriteLine("  Connected        : " + client.IsConnected);
                Console.WriteLine("  Authenticated    : " + client.IsAuthenticated);
                Console.WriteLine("  SessionId        : " + (client.Session.SessionId?.ToString() ?? "(none)"));
                Console.WriteLine("  Negotiated Dialect: " + (client.Session.NegotiatedDialect?.ToString() ?? "(none)"));
                Console.WriteLine("  Available Credits: " + client.Session.AvailableCredits);
                Console.WriteLine("  Max Read Size    : " + client.Session.NegotiatedMaxReadSize);
            }

            if (shareSession == null)
            {
                Console.WriteLine("  Open Share       : (none)");
            }
            else
            {
                Console.WriteLine("  Open Share       : " + shareSession.ShareName);
                Console.WriteLine("  Remote Directory : " + TestClientPathUtilities.GetDisplayRemotePath(currentRemotePath));
            }

            Console.WriteLine();
        }

        internal static string FormatNullableDateTime(DateTime? value)
        {
            return value.HasValue ? value.Value.ToString("u") : "(none)";
        }

        internal static string DisplayOrBlank(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "(blank)" : value;
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

        private static string FormatDialectRange(SmbDialect minimumDialect, SmbDialect maximumDialect)
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

        internal static string FormatClientFailure(OpenCifsClientException exception)
        {
            if (exception is OpenCifsStatusException statusException)
            {
                return "[ERROR] " +
                    statusException.Category +
                    " - " +
                    statusException.Command +
                    " returned " +
                    statusException.Status +
                    ": " +
                    statusException.Message;
            }

            return "[ERROR] " + exception.Category + ": " + exception.Message;
        }
    }
}

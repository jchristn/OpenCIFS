namespace OpenCIFS.TestServer
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;

    /// <summary>
    /// Menu-driven manual OpenCIFS server exercise utility.
    /// </summary>
    public static class Program
    {
        private static bool _RunForever = true;
        private static string _ServerName = Environment.MachineName;
        private static string _BindAddress = "127.0.0.1";
        private static int _BindPort = 4450;
        private static string _ShareName = "public";
        private static string _UserName = "tester";
        private static string _UserDomain = string.Empty;
        private static string _Password = "Password123!";
        private static SmbDialect _MinimumDialect = SmbDialect.Smb2002;
        private static SmbDialect _MaximumDialect = SmbDialect.Smb311;
        private static bool _RequireSigning = true;
        private static bool _RequireEncryptionForSmb3 = true;
        private static string _RootPath = CreateTemporaryRootPath();
        private static OpenCifsServerApplication? _Application;
        private static readonly string[] _DefaultPipeNames = new[]
        {
            "srvsvc",
            OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName
        };

        /// <summary>
        /// Entry point.
        /// </summary>
        /// <param name="args">Unused command-line arguments.</param>
        /// <returns>Process exit code.</returns>
        public static async Task<int> Main(string[] args)
        {
            _ = args;
            Console.WriteLine("OpenCIFS.TestServer");
            Console.WriteLine("Type ? for help.");
            Console.WriteLine("[INFO] Temporary backing store: " + _RootPath);
            Console.WriteLine();

            try
            {
                while (_RunForever)
                {
                    Console.Write("test-server> ");
                    string? commandText = Console.ReadLine();

                    if (commandText == null)
                    {
                        break;
                    }

                    commandText = commandText.Trim().TrimStart('\uFEFF');
                    if (commandText.Length == 0)
                    {
                        continue;
                    }

                    try
                    {
                        await ExecuteCommandAsync(commandText, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (Exception exception)
                    {
                        Console.WriteLine("[ERROR] " + exception.GetType().Name + ": " + exception.Message);
                    }
                }

                return 0;
            }
            finally
            {
                await StopAsync().ConfigureAwait(false);
                DeleteDirectoryIfExists(_RootPath);
            }
        }

        private static async Task ExecuteCommandAsync(string commandText, CancellationToken cancellationToken)
        {
            string[] parts = Tokenize(commandText);
            if (parts.Length == 0)
            {
                return;
            }

            string command = parts[0].ToLowerInvariant();

            switch (command)
            {
                case "?":
                case "help":
                    ShowMenu();
                    return;
                case "q":
                case "quit":
                case "exit":
                    _RunForever = false;
                    return;
                case "cls":
                    Console.Clear();
                    return;
                case "status":
                    ShowStatus();
                    return;
                case "server":
                    RequireArgumentCount(parts, 2, "server <name>");
                    EnsureNotRunning();
                    _ServerName = parts[1];
                    Console.WriteLine("[OK] ServerName = " + _ServerName);
                    return;
                case "bind":
                    RequireArgumentCount(parts, 2, "bind <address>");
                    EnsureNotRunning();
                    _BindAddress = parts[1];
                    Console.WriteLine("[OK] BindAddress = " + _BindAddress);
                    return;
                case "port":
                    RequireArgumentCount(parts, 2, "port <number>");
                    EnsureNotRunning();
                    _BindPort = ParsePositiveInt(parts[1], 1, 65535);
                    Console.WriteLine("[OK] BindPort = " + _BindPort);
                    return;
                case "share":
                    RequireArgumentCount(parts, 2, "share <name>");
                    EnsureNotRunning();
                    _ShareName = parts[1];
                    Console.WriteLine("[OK] ShareName = " + _ShareName);
                    return;
                case "user":
                    RequireArgumentCount(parts, 2, "user <name>");
                    EnsureNotRunning();
                    _UserName = parts[1];
                    Console.WriteLine("[OK] User = " + _UserName);
                    return;
                case "domain":
                    EnsureNotRunning();
                    _UserDomain = parts.Length >= 2 ? parts[1] : string.Empty;
                    Console.WriteLine("[OK] Domain = " + DisplayOrBlank(_UserDomain));
                    return;
                case "password":
                    EnsureNotRunning();
                    _Password = parts.Length >= 2 ? parts[1] : ReadSecret("Password: ");
                    Console.WriteLine("[OK] Password updated.");
                    return;
                case "dialects":
                    RequireArgumentCount(parts, 3, "dialects <min> <max>");
                    EnsureNotRunning();
                    _MinimumDialect = ParseDialect(parts[1]);
                    _MaximumDialect = ParseDialect(parts[2]);
                    ValidateDialectRange(_MinimumDialect, _MaximumDialect);
                    Console.WriteLine("[OK] Dialects = " + _MinimumDialect + " -> " + _MaximumDialect);
                    return;
                case "signing":
                    RequireArgumentCount(parts, 2, "signing <on|off>");
                    EnsureNotRunning();
                    _RequireSigning = ParseBooleanSwitch(parts[1]);
                    Console.WriteLine("[OK] RequireSigning = " + _RequireSigning);
                    return;
                case "encryption":
                    RequireArgumentCount(parts, 2, "encryption <on|off>");
                    EnsureNotRunning();
                    _RequireEncryptionForSmb3 = ParseBooleanSwitch(parts[1]);
                    Console.WriteLine("[OK] RequireEncryptionForSmb3 = " + _RequireEncryptionForSmb3);
                    return;
                case "root":
                    await HandleRootCommandAsync(parts).ConfigureAwait(false);
                    return;
                case "openroot":
                    OpenRootInExplorer();
                    return;
                case "dir":
                    PrintLocalDirectory(parts);
                    return;
                case "shares":
                    PrintAvailableShares();
                    return;
                case "pipes":
                    PrintAvailablePipes();
                    return;
                case "start":
                    await StartAsync(cancellationToken).ConfigureAwait(false);
                    return;
                case "stop":
                    await StopAsync().ConfigureAwait(false);
                    return;
                case "wait":
                    RequireArgumentCount(parts, 2, "wait <seconds>");
                    await Task.Delay(ParseDelay(parts[1]), cancellationToken).ConfigureAwait(false);
                    Console.WriteLine("[OK] Wait completed.");
                    return;
                default:
                    Console.WriteLine("[ERROR] Unknown command. Type ? for help.");
                    return;
            }
        }

        private static void ShowMenu()
        {
            Console.WriteLine();
            Console.WriteLine("Available commands:");
            WriteMenuCommand("?", "help");
            WriteMenuCommand("q", "quit");
            WriteMenuCommand("cls", "clear the screen");
            WriteMenuCommand("status", "show current configuration and runtime state");
            Console.WriteLine();
            WriteMenuCommand("server <name>", "set the SMB server name advertised to clients", _ServerName);
            WriteMenuCommand("bind <address>", "set the bind address", _BindAddress);
            WriteMenuCommand("port <number>", "set the bind port", _BindPort.ToString());
            WriteMenuCommand("share <name>", "set the exposed share name", _ShareName);
            WriteMenuCommand("user <name>", "set the in-memory account name", _UserName);
            WriteMenuCommand("domain [value]", "set or clear the in-memory account domain", FormatCurrentText(_UserDomain));
            WriteMenuCommand("password [value]", "set the in-memory account password; omit value to prompt", FormatPasswordState(_Password));
            WriteMenuCommand("dialects <min> <max>", "set the dialect range", FormatDialectRange(_MinimumDialect, _MaximumDialect));
            WriteMenuCommand("signing <on|off>", "require or relax signing", FormatOnOff(_RequireSigning));
            WriteMenuCommand("encryption <on|off>", "require or relax SMB3 encryption", FormatOnOff(_RequireEncryptionForSmb3));
            Console.WriteLine();
            WriteMenuCommand("root", "show the temporary backing-store path", _RootPath);
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

        private static void ShowStatus()
        {
            Console.WriteLine();
            Console.WriteLine("Configuration:");
            Console.WriteLine("  ServerName          : " + _ServerName);
            Console.WriteLine("  BindAddress         : " + _BindAddress);
            Console.WriteLine("  BindPort            : " + _BindPort);
            Console.WriteLine("  ShareName           : " + _ShareName);
            Console.WriteLine("  Temporary Root      : " + _RootPath);
            Console.WriteLine("  User                : " + _UserName);
            Console.WriteLine("  Domain              : " + DisplayOrBlank(_UserDomain));
            Console.WriteLine("  Password Set        : " + (!string.IsNullOrWhiteSpace(_Password)));
            Console.WriteLine("  Dialects            : " + _MinimumDialect + " -> " + _MaximumDialect);
            Console.WriteLine("  Require Signing     : " + _RequireSigning);
            Console.WriteLine("  Require SMB3 Encryption: " + _RequireEncryptionForSmb3);
            Console.WriteLine();
            Console.WriteLine("Runtime:");
            Console.WriteLine("  Running             : " + (_Application != null && _Application.IsRunning));
            Console.WriteLine("  UNC Hint            : \\\\" + _ServerName + "\\" + _ShareName);
            Console.WriteLine("  Direct-TCP Hint     : " + GetConnectHostHint() + ":" + _BindPort);
            Console.WriteLine("  Named Pipes         : " + string.Join(", ", _DefaultPipeNames));
            Console.WriteLine();
        }

        private static async Task HandleRootCommandAsync(string[] parts)
        {
            if (parts.Length == 1)
            {
                Console.WriteLine("[INFO] Temporary backing store: " + _RootPath);
                return;
            }

            if (!parts[1].Equals("reset", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Usage: root [reset]");
            }

            EnsureNotRunning();
            string previousRootPath = _RootPath;
            _RootPath = CreateTemporaryRootPath();
            DeleteDirectoryIfExists(previousRootPath);
            Console.WriteLine("[OK] Temporary backing store reset: " + _RootPath);
        }

        private static void OpenRootInExplorer()
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = "\"" + _RootPath + "\"",
                UseShellExecute = true
            };
            Process.Start(processStartInfo);
            Console.WriteLine("[OK] Opened " + _RootPath + " in Explorer.");
        }

        private static void PrintLocalDirectory(string[] parts)
        {
            string relativePath = parts.Length >= 2 ? parts[1] : string.Empty;
            string targetPath = string.IsNullOrWhiteSpace(relativePath)
                ? _RootPath
                : Path.GetFullPath(Path.Combine(_RootPath, relativePath));

            if (!targetPath.StartsWith(_RootPath, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("[ERROR] Local path escapes the temporary backing store.");
                return;
            }

            if (!Directory.Exists(targetPath))
            {
                Console.WriteLine("[INFO] Directory does not exist: " + targetPath);
                return;
            }

            Console.WriteLine("[OK] Local directory listing for " + targetPath + ":");
            string[] directories = Directory.GetDirectories(targetPath).OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
            string[] files = Directory.GetFiles(targetPath).OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();

            if (directories.Length == 0 && files.Length == 0)
            {
                Console.WriteLine("  (empty)");
                return;
            }

            foreach (string directory in directories)
            {
                Console.WriteLine("  <DIR> " + Path.GetFileName(directory));
            }

            foreach (string file in files)
            {
                FileInfo fileInfo = new FileInfo(file);
                Console.WriteLine("  FILE  " + fileInfo.Length.ToString().PadLeft(10) + "  " + fileInfo.Name);
            }
        }

        private static void PrintAvailableShares()
        {
            OpenCifsServer server = BuildConfiguredServer();
            IReadOnlyList<OpenCifsServerShareInfo> shares = server.GetAvailableShares();
            Console.WriteLine("[OK] Available shares:");

            for (int index = 0; index < shares.Count; index++)
            {
                OpenCifsServerShareInfo share = shares[index];
                Console.WriteLine(
                    "  " +
                    share.ShareName +
                    " -> " +
                    share.RootPath +
                    " [" +
                    share.BackendKind +
                    "] files=" +
                    share.SupportsFiles +
                    " dirs=" +
                    share.SupportsDirectories +
                    " meta=" +
                    share.SupportsMetadata +
                    " locks=" +
                    share.SupportsLocking +
                    " notify=" +
                    share.SupportsNotifications);
            }
        }

        private static void PrintAvailablePipes()
        {
            Console.WriteLine("[OK] Available named pipes under IPC$:");

            for (int index = 0; index < _DefaultPipeNames.Length; index++)
            {
                Console.WriteLine("  " + _DefaultPipeNames[index]);
            }
        }

        private static async Task StartAsync(CancellationToken cancellationToken)
        {
            if (_Application != null && _Application.IsRunning)
            {
                Console.WriteLine("[ERROR] The server is already running.");
                return;
            }

            Directory.CreateDirectory(_RootPath);
            OpenCifsServer server = BuildConfiguredServer();
            OpenCifsServerApplication application = server.BuildApplication(
                exception => Console.WriteLine("[SERVER-ERROR] " + exception.GetType().Name + ": " + exception.Message));
            OpenCifsServerResult result = await application.TryStartAsync(cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine("[ERROR] " + result.Exception!.Message);
                await application.DisposeAsync().ConfigureAwait(false);
                return;
            }

            _Application = application;
            Console.WriteLine("[OK] Listener started.");
            Console.WriteLine("[OK] Temporary backing store: " + _RootPath);
            Console.WriteLine("[OK] UNC hint: \\\\" + _ServerName + "\\" + _ShareName);
            Console.WriteLine("[OK] Direct-TCP hint: " + GetConnectHostHint() + ":" + _BindPort);
        }

        private static async Task StopAsync()
        {
            if (_Application == null)
            {
                return;
            }

            OpenCifsServerApplication application = _Application;
            _Application = null;

            OpenCifsServerResult result = await application.TryStopAsync(CancellationToken.None).ConfigureAwait(false);
            if (!result.IsSuccess)
            {
                Console.WriteLine("[ERROR] " + result.Exception!.Message);
            }
            else
            {
                Console.WriteLine("[OK] Listener stopped.");
            }

            await application.DisposeAsync().ConfigureAwait(false);
        }

        private static OpenCifsServer BuildConfiguredServer()
        {
            OpenCifsServerRequestCallbacks callbacks = new OpenCifsServerRequestCallbacks
            {
                AuthenticatedSessionCallback = context =>
                {
                    Console.WriteLine(
                        "[AUTH] session=" +
                        context.SessionId +
                        " user=" +
                        context.UserDomain +
                        "\\" +
                        context.UserName +
                        " flavor=" +
                        context.AuthenticationFlavor);
                    return null;
                },
                TreeConnectCallback = context =>
                {
                    Console.WriteLine(
                        "[TREE] session=" +
                        context.SessionId +
                        " share=" +
                        context.ShareName +
                        " root=" +
                        context.ShareRootPath);
                    return null;
                },
                CreateCallback = context =>
                {
                    Console.WriteLine(
                        "[CREATE] session=" +
                        context.SessionId +
                        " share=" +
                        context.ShareName +
                        " path=" +
                        context.FullPath);
                    return null;
                },
                QueryDirectoryCallback = context =>
                {
                    Console.WriteLine(
                        "[QUERYDIR] session=" +
                        context.SessionId +
                        " share=" +
                        context.ShareName +
                        " path=" +
                        context.FullPath);
                    return null;
                },
                SetInfoCallback = context =>
                {
                    Console.WriteLine(
                        "[SETINFO] session=" +
                        context.SessionId +
                        " share=" +
                        context.ShareName +
                        " path=" +
                        context.FullPath +
                        " class=" +
                        context.Request.FileInfoClass);
                    return null;
                }
            };

            OpenCifsServerBuilder builder = new OpenCifsServerBuilder()
                .WithServerName(_ServerName)
                .WithBindAddress(_BindAddress)
                .WithBindPort(_BindPort)
                .WithDialectRange(_MinimumDialect, _MaximumDialect)
                .WithSigningRequired(_RequireSigning)
                .WithSmb3EncryptionRequired(_RequireEncryptionForSmb3)
                .ConfigureRequestCallbacks(callbacks)
                .WithDiagnosticLogger(message => Console.WriteLine("[TRACE] " + message));

            builder.AddFileSystemShare(_ShareName, _RootPath, createRootIfMissing: true);
            builder.AddSrvsvcShareEnumerationEndpoint();
            builder.AddUtf8EchoNamedPipeEndpoint();
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = _UserName,
                UserDomain = _UserDomain,
                Password = _Password
            });

            return builder.Build();
        }

        private static void EnsureNotRunning()
        {
            if (_Application != null && _Application.IsRunning)
            {
                throw new InvalidOperationException("Stop the server before changing configuration.");
            }
        }

        private static string GetConnectHostHint()
        {
            if (_BindAddress == "0.0.0.0" || _BindAddress == "::" || _BindAddress == "*" || _BindAddress == "+")
            {
                return "127.0.0.1";
            }

            return _BindAddress;
        }

        private static string CreateTemporaryRootPath()
        {
            string rootPath = Path.Combine(
                Path.GetTempPath(),
                "OpenCIFS.TestServer",
                DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(rootPath);
            return rootPath;
        }

        private static void DeleteDirectoryIfExists(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine("[WARN] Failed to delete temporary backing store '" + path + "': " + exception.Message);
            }
        }

        private static string DisplayOrBlank(string value)
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

        private static int ParsePositiveInt(string value, int minimum, int maximum)
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

        private static TimeSpan ParseDelay(string value)
        {
            if (!double.TryParse(value, out double seconds) || seconds < 0)
            {
                throw new ArgumentException("Expected a non-negative seconds value.");
            }

            return TimeSpan.FromSeconds(seconds);
        }

        private static bool ParseBooleanSwitch(string value)
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

        private static SmbDialect ParseDialect(string value)
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

        private static void ValidateDialectRange(SmbDialect minimumDialect, SmbDialect maximumDialect)
        {
            if (maximumDialect < minimumDialect)
            {
                throw new ArgumentException("Maximum dialect must be greater than or equal to minimum dialect.");
            }
        }

        private static void RequireArgumentCount(string[] parts, int minimumLength, string usage)
        {
            if (parts.Length < minimumLength)
            {
                throw new ArgumentException("Usage: " + usage);
            }
        }

        private static string ReadSecret(string prompt)
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

        private static string[] Tokenize(string commandText)
        {
            StringBuilder current = new StringBuilder();
            System.Collections.Generic.List<string> tokens = new System.Collections.Generic.List<string>();
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

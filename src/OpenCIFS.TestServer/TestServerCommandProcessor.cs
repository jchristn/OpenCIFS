namespace OpenCIFS.TestServer
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;

    internal sealed class TestServerCommandProcessor
    {
        internal static readonly string[] DefaultPipeNames = new[]
        {
            "srvsvc",
            OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName
        };

        public TestServerCommandProcessor(TestServerState state)
        {
            _State = state ?? throw new ArgumentNullException(nameof(state), "State cannot be null.");
        }

        internal async Task ExecuteCommandAsync(string commandText, CancellationToken cancellationToken)
        {
            string[] parts = TestServerArgumentParsing.Tokenize(commandText);
            if (parts.Length == 0)
            {
                return;
            }

            string command = parts[0].ToLowerInvariant();

            switch (command)
            {
                case "?":
                case "help":
                    TestServerConsoleHelpers.ShowMenu(_State);
                    return;
                case "q":
                case "quit":
                case "exit":
                    _State.RunForever = false;
                    return;
                case "cls":
                    Console.Clear();
                    return;
                case "status":
                    TestServerConsoleHelpers.ShowStatus(_State, GetConnectHostHint(), DefaultPipeNames);
                    return;
                case "server":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "server <name>");
                    EnsureNotRunning();
                    _State.ServerName = parts[1];
                    Console.WriteLine("[OK] ServerName = " + _State.ServerName);
                    return;
                case "bind":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "bind <address>");
                    EnsureNotRunning();
                    _State.BindAddress = parts[1];
                    Console.WriteLine("[OK] BindAddress = " + _State.BindAddress);
                    return;
                case "port":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "port <number>");
                    EnsureNotRunning();
                    _State.BindPort = TestServerArgumentParsing.ParsePositiveInt(parts[1], 1, 65535);
                    Console.WriteLine("[OK] BindPort = " + _State.BindPort);
                    return;
                case "share":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "share <name>");
                    EnsureNotRunning();
                    _State.ShareName = parts[1];
                    Console.WriteLine("[OK] ShareName = " + _State.ShareName);
                    return;
                case "user":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "user <name>");
                    EnsureNotRunning();
                    _State.UserName = parts[1];
                    Console.WriteLine("[OK] User = " + _State.UserName);
                    return;
                case "domain":
                    EnsureNotRunning();
                    _State.UserDomain = parts.Length >= 2 ? parts[1] : string.Empty;
                    Console.WriteLine("[OK] Domain = " + TestServerArgumentParsing.DisplayOrBlank(_State.UserDomain));
                    return;
                case "password":
                    EnsureNotRunning();
                    _State.Password = parts.Length >= 2 ? parts[1] : TestServerArgumentParsing.ReadSecret("Password: ");
                    Console.WriteLine("[OK] Password updated.");
                    return;
                case "dialects":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 3, "dialects <min> <max>");
                    EnsureNotRunning();
                    _State.MinimumDialect = TestServerArgumentParsing.ParseDialect(parts[1]);
                    _State.MaximumDialect = TestServerArgumentParsing.ParseDialect(parts[2]);
                    TestServerArgumentParsing.ValidateDialectRange(_State.MinimumDialect, _State.MaximumDialect);
                    Console.WriteLine("[OK] Dialects = " + _State.MinimumDialect + " -> " + _State.MaximumDialect);
                    return;
                case "signing":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "signing <on|off>");
                    EnsureNotRunning();
                    _State.RequireSigning = TestServerArgumentParsing.ParseBooleanSwitch(parts[1]);
                    Console.WriteLine("[OK] RequireSigning = " + _State.RequireSigning);
                    return;
                case "encryption":
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "encryption <on|off>");
                    EnsureNotRunning();
                    _State.RequireEncryptionForSmb3 = TestServerArgumentParsing.ParseBooleanSwitch(parts[1]);
                    Console.WriteLine("[OK] RequireEncryptionForSmb3 = " + _State.RequireEncryptionForSmb3);
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
                    TestServerArgumentParsing.RequireArgumentCount(parts, 2, "wait <seconds>");
                    await Task.Delay(TestServerArgumentParsing.ParseDelay(parts[1]), cancellationToken).ConfigureAwait(false);
                    Console.WriteLine("[OK] Wait completed.");
                    return;
                default:
                    Console.WriteLine("[ERROR] Unknown command. Type ? for help.");
                    return;
            }
        }

        internal async Task CleanupAsync()
        {
            await StopAsync().ConfigureAwait(false);
            DeleteDirectoryIfExists(_State.RootPath);
        }

        internal static string CreateTemporaryRootPath()
        {
            string rootPath = Path.Combine(
                Path.GetTempPath(),
                "OpenCIFS.TestServer",
                DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(rootPath);
            return rootPath;
        }

        internal static void DeleteDirectoryIfExists(string path)
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

        private async Task HandleRootCommandAsync(string[] parts)
        {
            if (parts.Length == 1)
            {
                Console.WriteLine("[INFO] Temporary backing store: " + _State.RootPath);
                return;
            }

            if (!parts[1].Equals("reset", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Usage: root [reset]");
            }

            EnsureNotRunning();
            string previousRootPath = _State.RootPath;
            _State.RootPath = CreateTemporaryRootPath();
            DeleteDirectoryIfExists(previousRootPath);
            Console.WriteLine("[OK] Temporary backing store reset: " + _State.RootPath);
        }

        private void OpenRootInExplorer()
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = "\"" + _State.RootPath + "\"",
                UseShellExecute = true
            };
            Process.Start(processStartInfo);
            Console.WriteLine("[OK] Opened " + _State.RootPath + " in Explorer.");
        }

        private void PrintLocalDirectory(string[] parts)
        {
            string relativePath = parts.Length >= 2 ? parts[1] : string.Empty;
            string targetPath = string.IsNullOrWhiteSpace(relativePath)
                ? _State.RootPath
                : Path.GetFullPath(Path.Combine(_State.RootPath, relativePath));

            if (!targetPath.StartsWith(_State.RootPath, StringComparison.OrdinalIgnoreCase))
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

        private void PrintAvailableShares()
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

            for (int index = 0; index < DefaultPipeNames.Length; index++)
            {
                Console.WriteLine("  " + DefaultPipeNames[index]);
            }
        }

        private async Task StartAsync(CancellationToken cancellationToken)
        {
            if (_State.Application != null && _State.Application.IsRunning)
            {
                Console.WriteLine("[ERROR] The server is already running.");
                return;
            }

            Directory.CreateDirectory(_State.RootPath);
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

            _State.Application = application;
            Console.WriteLine("[OK] Listener started.");
            Console.WriteLine("[OK] Temporary backing store: " + _State.RootPath);
            Console.WriteLine("[OK] UNC hint: \\\\" + _State.ServerName + "\\" + _State.ShareName);
            Console.WriteLine("[OK] Direct-TCP hint: " + GetConnectHostHint() + ":" + _State.BindPort);
        }

        private async Task StopAsync()
        {
            if (_State.Application == null)
            {
                return;
            }

            OpenCifsServerApplication application = _State.Application;
            _State.Application = null;

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

        private OpenCifsServer BuildConfiguredServer()
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
                .WithServerName(_State.ServerName)
                .WithBindAddress(_State.BindAddress)
                .WithBindPort(_State.BindPort)
                .WithDialectRange(_State.MinimumDialect, _State.MaximumDialect)
                .WithSigningRequired(_State.RequireSigning)
                .WithSmb3EncryptionRequired(_State.RequireEncryptionForSmb3)
                .ConfigureRequestCallbacks(callbacks)
                .WithDiagnosticLogger(message => Console.WriteLine("[TRACE] " + message));

            builder.AddFileSystemShare(_State.ShareName, _State.RootPath, createRootIfMissing: true);
            builder.AddSrvsvcShareEnumerationEndpoint();
            builder.AddUtf8EchoNamedPipeEndpoint();
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = _State.UserName,
                UserDomain = _State.UserDomain,
                Password = _State.Password
            });

            return builder.Build();
        }

        private void EnsureNotRunning()
        {
            if (_State.Application != null && _State.Application.IsRunning)
            {
                throw new InvalidOperationException("Stop the server before changing configuration.");
            }
        }

        private string GetConnectHostHint()
        {
            if (_State.BindAddress == "0.0.0.0" || _State.BindAddress == "::" || _State.BindAddress == "*" || _State.BindAddress == "+")
            {
                return "127.0.0.1";
            }

            return _State.BindAddress;
        }

        private readonly TestServerState _State;
    }
}

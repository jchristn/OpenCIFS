namespace OpenCIFS.TestClient
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Menu-driven manual OpenCIFS client exercise utility.
    /// </summary>
    public static class Program
    {
        private static bool _RunForever = true;
        private static string _ServerName = "127.0.0.1";
        private static int _ServerPort = 4450;
        private static string _UserName = "tester";
        private static string _UserDomain = string.Empty;
        private static string _Password = "Password123!";
        private static SmbDialect _MinimumDialect = SmbDialect.Smb2002;
        private static SmbDialect _MaximumDialect = SmbDialect.Smb311;
        private static bool _RequireSigning = true;
        private static bool _PreferEncryption = true;
        private static int _ConnectTimeoutMs = 30000;
        private static string _CurrentRemotePath = "/";
        private static OpenCifsClient? _Client;
        private static OpenCifsShareSession? _ShareSession;

        /// <summary>
        /// Entry point.
        /// </summary>
        /// <param name="args">Unused command-line arguments.</param>
        /// <returns>Process exit code.</returns>
        public static async Task<int> Main(string[] args)
        {
            _ = args;
            Console.WriteLine("OpenCIFS.TestClient");
            Console.WriteLine("Type ? for help.");
            Console.WriteLine();

            try
            {
                while (_RunForever)
                {
                    Console.Write("test-client> ");
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
                await CloseShareAsync().ConfigureAwait(false);
                await DisconnectAsync().ConfigureAwait(false);
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
                    RequireArgumentCount(parts, 2, "server <host>");
                    _ServerName = parts[1];
                    Console.WriteLine("[OK] Server = " + _ServerName);
                    return;
                case "port":
                    RequireArgumentCount(parts, 2, "port <number>");
                    _ServerPort = ParsePort(parts[1]);
                    Console.WriteLine("[OK] Port = " + _ServerPort);
                    return;
                case "user":
                    RequireArgumentCount(parts, 2, "user <name>");
                    _UserName = parts[1];
                    Console.WriteLine("[OK] User = " + _UserName);
                    return;
                case "domain":
                    _UserDomain = parts.Length >= 2 ? parts[1] : string.Empty;
                    Console.WriteLine("[OK] Domain = " + DisplayOrBlank(_UserDomain));
                    return;
                case "password":
                    _Password = parts.Length >= 2 ? parts[1] : ReadSecret("Password: ");
                    Console.WriteLine("[OK] Password updated.");
                    return;
                case "dialects":
                    RequireArgumentCount(parts, 3, "dialects <min> <max>");
                    _MinimumDialect = ParseDialect(parts[1]);
                    _MaximumDialect = ParseDialect(parts[2]);
                    ValidateDialectRange(_MinimumDialect, _MaximumDialect);
                    Console.WriteLine("[OK] Dialects = " + _MinimumDialect + " -> " + _MaximumDialect);
                    return;
                case "signing":
                    RequireArgumentCount(parts, 2, "signing <on|off>");
                    _RequireSigning = ParseBooleanSwitch(parts[1]);
                    Console.WriteLine("[OK] RequireSigning = " + _RequireSigning);
                    return;
                case "encryption":
                    RequireArgumentCount(parts, 2, "encryption <on|off>");
                    _PreferEncryption = ParseBooleanSwitch(parts[1]);
                    Console.WriteLine("[OK] PreferEncryption = " + _PreferEncryption);
                    return;
                case "timeout":
                    RequireArgumentCount(parts, 2, "timeout <milliseconds>");
                    _ConnectTimeoutMs = ParsePositiveInt(parts[1], 1000, 300000);
                    Console.WriteLine("[OK] ConnectTimeoutMs = " + _ConnectTimeoutMs);
                    return;
                case "shares":
                    await ListSharesAsync(parts, cancellationToken).ConfigureAwait(false);
                    return;
                case "share-info":
                case "shareinfo":
                    RequireArgumentCount(parts, 2, "shareinfo <share>");
                    await PrintShareInfoAsync(parts[1], cancellationToken).ConfigureAwait(false);
                    return;
                case "pipe":
                    RequireArgumentCount(parts, 3, "pipe <name> <text>");
                    await PipeTransceiveAsync(parts[1], string.Join(" ", parts.Skip(2)), cancellationToken).ConfigureAwait(false);
                    return;
                case "connect":
                    await ConnectAsync(cancellationToken).ConfigureAwait(false);
                    return;
                case "disconnect":
                    await DisconnectAsync().ConfigureAwait(false);
                    return;
                case "open":
                    RequireArgumentCount(parts, 2, "open <share>");
                    await OpenShareAsync(parts[1], cancellationToken).ConfigureAwait(false);
                    return;
                case "close":
                    await CloseShareAsync().ConfigureAwait(false);
                    return;
                case "pwd":
                    Console.WriteLine(GetDisplayRemotePath(_CurrentRemotePath));
                    return;
                case "cd":
                    await ChangeDirectoryAsync(parts, cancellationToken).ConfigureAwait(false);
                    return;
                case "ls":
                    await ListDirectoryAsync(parts, cancellationToken).ConfigureAwait(false);
                    return;
                case "tree":
                    await PrintTreeAsync(parts, cancellationToken).ConfigureAwait(false);
                    return;
                case "stat":
                    await PrintMetadataAsync(parts, cancellationToken).ConfigureAwait(false);
                    return;
                case "mkdir":
                    RequireArgumentCount(parts, 2, "mkdir <path>");
                    await CreateDirectoryAsync(parts[1], cancellationToken).ConfigureAwait(false);
                    return;
                case "rmdir":
                    RequireArgumentCount(parts, 2, "rmdir <path>");
                    await DeleteDirectoryAsync(parts[1], cancellationToken).ConfigureAwait(false);
                    return;
                case "cat":
                    RequireArgumentCount(parts, 2, "cat <path>");
                    await ReadTextFileAsync(parts[1], cancellationToken).ConfigureAwait(false);
                    return;
                case "write-text":
                    RequireArgumentCount(parts, 3, "write-text <path> <text>");
                    await WriteTextFileAsync(parts[1], string.Join(" ", parts.Skip(2)), cancellationToken).ConfigureAwait(false);
                    return;
                case "put":
                    RequireArgumentCount(parts, 3, "put <local-path> <remote-path>");
                    await UploadFileAsync(parts[1], parts[2], cancellationToken).ConfigureAwait(false);
                    return;
                case "get":
                    RequireArgumentCount(parts, 3, "get <remote-path> <local-path>");
                    await DownloadFileAsync(parts[1], parts[2], cancellationToken).ConfigureAwait(false);
                    return;
                case "rm":
                    RequireArgumentCount(parts, 2, "rm <path>");
                    await DeleteFileAsync(parts[1], cancellationToken).ConfigureAwait(false);
                    return;
                case "mv":
                    RequireArgumentCount(parts, 3, "mv <source-path> <destination-path>");
                    await RenamePathAsync(parts[1], parts[2], cancellationToken).ConfigureAwait(false);
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
            Console.WriteLine("  ?                          help");
            Console.WriteLine("  q                          quit");
            Console.WriteLine("  cls                        clear the screen");
            Console.WriteLine("  status                     show client configuration and connection state");
            Console.WriteLine();
            Console.WriteLine("  server <host>              set the SMB server host or address");
            Console.WriteLine("  port <number>              set the direct-TCP port");
            Console.WriteLine("  user <name>                set the user name");
            Console.WriteLine("  domain [value]             set or clear the user domain");
            Console.WriteLine("  password [value]           set the password; omit value to prompt");
            Console.WriteLine("  dialects <min> <max>       set the dialect range");
            Console.WriteLine("  signing <on|off>           require or relax signing");
            Console.WriteLine("  encryption <on|off>        prefer or avoid encryption when supported");
            Console.WriteLine("  timeout <milliseconds>     set the connect timeout");
            Console.WriteLine();
            Console.WriteLine("  shares [server]            list shares through OpenCIFS IPC$/srvsvc browsing");
            Console.WriteLine("                             requires credentials that can authenticate to the target SMB server");
            Console.WriteLine("  shareinfo <share>          query bounded detailed share information through OpenCIFS IPC$/srvsvc");
            Console.WriteLine("  pipe <name> <text>         transceive UTF-8 text through a bounded named pipe under IPC$");
            Console.WriteLine("  connect                    connect and authenticate");
            Console.WriteLine("  disconnect                 close the active client session");
            Console.WriteLine("  open <share>               open a share-scoped work session");
            Console.WriteLine("  close                      close the active share session");
            Console.WriteLine();
            Console.WriteLine("  pwd                        show the current remote directory");
            Console.WriteLine("  cd [path]                  change the current remote directory");
            Console.WriteLine("  ls [path] [pattern]        enumerate a directory");
            Console.WriteLine("  tree [path]                recursively enumerate a directory");
            Console.WriteLine("  stat [path]                show metadata for a file or directory");
            Console.WriteLine("  mkdir <path>               create a directory");
            Console.WriteLine("  rmdir <path>               delete an empty directory");
            Console.WriteLine("  cat <path>                 read a UTF-8 text file");
            Console.WriteLine("  write-text <path> <text>   write UTF-8 text to a file");
            Console.WriteLine("  put <local> <remote>       upload a local file");
            Console.WriteLine("  get <remote> <local>       download a remote file");
            Console.WriteLine("  rm <path>                  delete a file");
            Console.WriteLine("  mv <source> <dest>         rename a file or directory");
            Console.WriteLine("  wait <seconds>             pause the console, useful for scripted smoke runs");
            Console.WriteLine();
        }

        private static void ShowStatus()
        {
            Console.WriteLine();
            Console.WriteLine("Configuration:");
            Console.WriteLine("  Server           : " + _ServerName);
            Console.WriteLine("  Port             : " + _ServerPort);
            Console.WriteLine("  User             : " + _UserName);
            Console.WriteLine("  Domain           : " + DisplayOrBlank(_UserDomain));
            Console.WriteLine("  Password Set     : " + (!string.IsNullOrWhiteSpace(_Password)));
            Console.WriteLine("  Dialects         : " + _MinimumDialect + " -> " + _MaximumDialect);
            Console.WriteLine("  Require Signing  : " + _RequireSigning);
            Console.WriteLine("  Prefer Encryption: " + _PreferEncryption);
            Console.WriteLine("  Connect Timeout  : " + _ConnectTimeoutMs + " ms");
            Console.WriteLine();
            Console.WriteLine("Runtime:");

            if (_Client == null)
            {
                Console.WriteLine("  Client           : not connected");
            }
            else
            {
                Console.WriteLine("  Client           : created");
                Console.WriteLine("  Connected        : " + _Client.IsConnected);
                Console.WriteLine("  Authenticated    : " + _Client.IsAuthenticated);
                Console.WriteLine("  SessionId        : " + (_Client.Session.SessionId?.ToString() ?? "(none)"));
                Console.WriteLine("  Negotiated Dialect: " + (_Client.Session.NegotiatedDialect?.ToString() ?? "(none)"));
                Console.WriteLine("  Available Credits: " + _Client.Session.AvailableCredits);
                Console.WriteLine("  Max Read Size    : " + _Client.Session.NegotiatedMaxReadSize);
            }

            if (_ShareSession == null)
            {
                Console.WriteLine("  Open Share       : (none)");
            }
            else
            {
                Console.WriteLine("  Open Share       : " + _ShareSession.ShareName);
                Console.WriteLine("  Remote Directory : " + GetDisplayRemotePath(_CurrentRemotePath));
            }

            Console.WriteLine();
        }

        private static async Task ListSharesAsync(string[] parts, CancellationToken cancellationToken)
        {
            string serverName = parts.Length >= 2 ? parts[1] : _ServerName;
            bool canReuseConnectedClient =
                parts.Length < 2 &&
                _Client != null &&
                _Client.IsConnected &&
                _Client.IsAuthenticated &&
                StringComparer.OrdinalIgnoreCase.Equals(_Client.Settings.ServerName, _ServerName) &&
                _Client.Settings.ServerPort == _ServerPort;

            OpenCifsClient? transientClient = null;
            OpenCifsClient client;

            if (canReuseConnectedClient)
            {
                client = _Client!;
                Console.WriteLine("[INFO] Enumerating shares through the current OpenCIFS client session.");
            }
            else
            {
                Console.WriteLine("[INFO] Connecting through OpenCIFS to enumerate shares on " + serverName + ".");
                transientClient = CreateClientBuilder(serverName, _ServerPort).Build();
                OpenCifsClientResult connectResult = await transientClient.TryConnectAsync(CreateCredential(), cancellationToken).ConfigureAwait(false);

                if (!connectResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(connectResult.Exception!));
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                    return;
                }

                client = transientClient;
            }

            try
            {
                OpenCifsClientResult<OpenCifsRemoteShareInfo[]> sharesResult = await client.TryEnumerateSharesAsync(cancellationToken).ConfigureAwait(false);

                if (!sharesResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(sharesResult.Exception!));
                    return;
                }

                OpenCifsRemoteShareInfo[] shares = sharesResult.Value!;
                Console.WriteLine("[OK] Share listing for " + serverName + ":");

                if (shares.Length == 0)
                {
                    Console.WriteLine("  (empty)");
                    return;
                }

                foreach (OpenCifsRemoteShareInfo share in shares.OrderBy(share => share.Name, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine("  " + share.ToDisplayString());
                }
            }
            finally
            {
                if (transientClient != null)
                {
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        private static async Task PrintShareInfoAsync(string shareName, CancellationToken cancellationToken)
        {
            bool canReuseConnectedClient =
                _Client != null &&
                _Client.IsConnected &&
                _Client.IsAuthenticated;

            OpenCifsClient? transientClient = null;
            OpenCifsClient client;

            if (canReuseConnectedClient)
            {
                client = _Client!;
                Console.WriteLine("[INFO] Querying share information through the current OpenCIFS client session.");
            }
            else
            {
                Console.WriteLine("[INFO] Connecting through OpenCIFS to query share information for " + shareName + ".");
                transientClient = CreateClientBuilder(_ServerName, _ServerPort).Build();
                OpenCifsClientResult connectResult = await transientClient.TryConnectAsync(CreateCredential(), cancellationToken).ConfigureAwait(false);

                if (!connectResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(connectResult.Exception!));
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                    return;
                }

                client = transientClient;
            }

            try
            {
                OpenCifsClientResult<OpenCifsRemoteShareInfo> shareInfoResult = await client.TryGetShareInfoAsync(shareName, cancellationToken).ConfigureAwait(false);

                if (!shareInfoResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(shareInfoResult.Exception!));
                    return;
                }

                OpenCifsRemoteShareInfo share = shareInfoResult.Value!;
                Console.WriteLine("[OK] Share information for " + share.Name + ":");
                Console.WriteLine("  Type           : " + share.Kind + (share.IsSpecial ? " special" : string.Empty) + (share.IsTemporary ? " temporary" : string.Empty));
                Console.WriteLine("  Remark         : " + DisplayOrBlank(share.Remark));
                Console.WriteLine("  Permissions    : " + (share.Permissions?.ToString() ?? "(not provided)"));
                Console.WriteLine("  Maximum Uses   : " + (share.MaximumUses?.ToString() ?? "(not provided)"));
                Console.WriteLine("  Current Uses   : " + (share.CurrentUses?.ToString() ?? "(not provided)"));
                Console.WriteLine("  Local Path     : " + DisplayOrBlank(share.LocalPath));
            }
            finally
            {
                if (transientClient != null)
                {
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        private static async Task ConnectAsync(CancellationToken cancellationToken)
        {
            if (_Client != null && _Client.IsConnected)
            {
                Console.WriteLine("[ERROR] A client connection is already active. Disconnect first.");
                return;
            }

            await DisconnectAsync().ConfigureAwait(false);

            OpenCifsClient client = CreateClientBuilder(_ServerName, _ServerPort).Build();
            OpenCifsClientCredential credential = CreateCredential();
            OpenCifsClientResult result = await client.TryConnectAsync(credential, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                await client.DisposeAsync().ConfigureAwait(false);
                return;
            }

            _Client = client;
            Console.WriteLine("[OK] Connected and authenticated.");
            Console.WriteLine("[OK] Negotiated dialect: " + (_Client.Session.NegotiatedDialect?.ToString() ?? "(none)"));
        }

        private static async Task PipeTransceiveAsync(string pipeName, string requestText, CancellationToken cancellationToken)
        {
            bool canReuseConnectedClient =
                _Client != null &&
                _Client.IsConnected &&
                _Client.IsAuthenticated;

            OpenCifsClient? transientClient = null;
            OpenCifsClient client;

            if (canReuseConnectedClient)
            {
                client = _Client!;
                Console.WriteLine("[INFO] Transceiving through the current OpenCIFS client session.");
            }
            else
            {
                Console.WriteLine("[INFO] Connecting through OpenCIFS to transceive named pipe '" + pipeName + "'.");
                transientClient = CreateClientBuilder(_ServerName, _ServerPort).Build();
                OpenCifsClientResult connectResult = await transientClient.TryConnectAsync(CreateCredential(), cancellationToken).ConfigureAwait(false);

                if (!connectResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(connectResult.Exception!));
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                    return;
                }

                client = transientClient;
            }

            try
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(requestText);
                OpenCifsClientResult<byte[]> transceiveResult = await client.TryTransceiveNamedPipeAsync(pipeName, inputBytes, cancellationToken: cancellationToken).ConfigureAwait(false);

                if (!transceiveResult.IsSuccess)
                {
                    Console.WriteLine(FormatClientFailure(transceiveResult.Exception!));
                    return;
                }

                Console.WriteLine("[OK] Pipe response from " + pipeName + ":");
                Console.WriteLine(Encoding.UTF8.GetString(transceiveResult.Value!));
            }
            finally
            {
                if (transientClient != null)
                {
                    await transientClient.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        private static async Task DisconnectAsync()
        {
            await CloseShareAsync().ConfigureAwait(false);

            if (_Client == null)
            {
                return;
            }

            OpenCifsClient client = _Client;
            _Client = null;

            OpenCifsClientResult result = await client.TryDisconnectAsync(CancellationToken.None).ConfigureAwait(false);
            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
            }
            else
            {
                Console.WriteLine("[OK] Disconnected.");
            }

            await client.DisposeAsync().ConfigureAwait(false);
        }

        private static async Task OpenShareAsync(string shareName, CancellationToken cancellationToken)
        {
            if (_Client == null || !_Client.IsConnected || !_Client.IsAuthenticated)
            {
                Console.WriteLine("[ERROR] Connect first.");
                return;
            }

            await CloseShareAsync().ConfigureAwait(false);
            OpenCifsClientResult<OpenCifsShareSession> result = await _Client.TryOpenShareAsync(shareName, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            _ShareSession = result.Value;
            _CurrentRemotePath = "/";
            Console.WriteLine("[OK] Opened share '" + shareName + "'.");
        }

        private static async Task CloseShareAsync()
        {
            if (_ShareSession == null)
            {
                return;
            }

            OpenCifsShareSession shareSession = _ShareSession;
            _ShareSession = null;
            _CurrentRemotePath = "/";

            try
            {
                await shareSession.DisposeAsync().ConfigureAwait(false);
                Console.WriteLine("[OK] Closed share session.");
            }
            catch (OpenCifsClientException exception)
            {
                Console.WriteLine(FormatClientFailure(exception));
            }
        }

        private static async Task ChangeDirectoryAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            if (parts.Length == 1)
            {
                Console.WriteLine(GetDisplayRemotePath(_CurrentRemotePath));
                return;
            }

            string targetPath = NormalizeRemotePath(parts[1]);
            OpenCifsClientResult<OpenCifsClientFileMetadata> result = await _ShareSession!.Metadata.TryGetAttributesAsync(targetPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            if (!result.Value!.IsDirectory)
            {
                Console.WriteLine("[ERROR] The target path is not a directory.");
                return;
            }

            _CurrentRemotePath = targetPath;
            Console.WriteLine("[OK] Current directory = " + GetDisplayRemotePath(_CurrentRemotePath));
        }

        private static async Task ListDirectoryAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string path = _CurrentRemotePath;
            string? pattern = null;

            if (parts.Length >= 2)
            {
                if (parts.Length == 2 && ContainsWildcard(parts[1]))
                {
                    pattern = parts[1];
                }
                else
                {
                    path = NormalizeRemotePath(parts[1]);
                    if (parts.Length >= 3)
                    {
                        pattern = parts[2];
                    }
                }
            }

            OpenCifsClientResult<OpenCifsClientDirectoryEntry[]> result = await _ShareSession!.Directories.TryEnumerateAsync(path, pattern, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            OpenCifsClientDirectoryEntry[] entries = result.Value!;
            Console.WriteLine("[OK] Directory listing for " + GetDisplayRemotePath(path) + ":");

            if (entries.Length == 0)
            {
                Console.WriteLine("  (empty)");
                return;
            }

            foreach (OpenCifsClientDirectoryEntry entry in entries.OrderBy(entry => entry.FileName, StringComparer.OrdinalIgnoreCase))
            {
                bool isDirectory = (entry.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0;
                string itemType = isDirectory ? "<DIR>" : "FILE ";
                Console.WriteLine(
                    "  " +
                    itemType.PadRight(5) +
                    " " +
                    entry.EndOfFile.ToString().PadLeft(10) +
                    "  " +
                    entry.FileName +
                    "  [" +
                    entry.FileAttributes +
                    "]");
            }
        }

        private static async Task PrintTreeAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string path = parts.Length >= 2 ? NormalizeRemotePath(parts[1]) : _CurrentRemotePath;
            Console.WriteLine("[OK] Tree for " + GetDisplayRemotePath(path) + ":");
            await PrintTreeNodeAsync(path, depth: 0, cancellationToken).ConfigureAwait(false);
        }

        private static async Task PrintTreeNodeAsync(string path, int depth, CancellationToken cancellationToken)
        {
            OpenCifsClientResult<OpenCifsClientDirectoryEntry[]> result = await _ShareSession!.Directories.TryEnumerateAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(new string(' ', depth * 2) + FormatClientFailure(result.Exception!));
                return;
            }

            OpenCifsClientDirectoryEntry[] entries = result.Value!;
            foreach (OpenCifsClientDirectoryEntry entry in entries.OrderBy(entry => entry.FileName, StringComparer.OrdinalIgnoreCase))
            {
                if (entry.FileName == "." || entry.FileName == "..")
                {
                    continue;
                }

                bool isDirectory = (entry.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0;
                Console.WriteLine(new string(' ', depth * 2) + (isDirectory ? "[D] " : "[F] ") + entry.FileName);

                if (isDirectory)
                {
                    string childPath = CombineRemotePath(path, entry.FileName);
                    await PrintTreeNodeAsync(childPath, depth + 1, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private static async Task PrintMetadataAsync(string[] parts, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string path = parts.Length >= 2 ? NormalizeRemotePath(parts[1]) : _CurrentRemotePath;
            OpenCifsClientResult<OpenCifsClientFileMetadata> result = await _ShareSession!.Metadata.TryGetAttributesAsync(path, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            OpenCifsClientFileMetadata metadata = result.Value!;
            Console.WriteLine("[OK] Metadata for " + GetDisplayRemotePath(path) + ":");
            Console.WriteLine("  Path           : " + metadata.Path);
            Console.WriteLine("  Is Directory   : " + metadata.IsDirectory);
            Console.WriteLine("  Delete Pending : " + metadata.IsDeletePending);
            Console.WriteLine("  EOF            : " + metadata.EndOfFile);
            Console.WriteLine("  Allocation     : " + metadata.AllocationSize);
            Console.WriteLine("  Attributes     : " + metadata.FileAttributes);
            Console.WriteLine("  Created (UTC)  : " + FormatNullableDateTime(metadata.CreationTimeUtc));
            Console.WriteLine("  Accessed (UTC) : " + FormatNullableDateTime(metadata.LastAccessTimeUtc));
            Console.WriteLine("  Written (UTC)  : " + FormatNullableDateTime(metadata.LastWriteTimeUtc));
            Console.WriteLine("  Changed (UTC)  : " + FormatNullableDateTime(metadata.ChangeTimeUtc));
        }

        private static async Task CreateDirectoryAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult result = await _ShareSession!.Directories.TryCreateAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Created directory " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        private static async Task DeleteDirectoryAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult result = await _ShareSession!.Directories.TryDeleteAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Deleted directory " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        private static async Task ReadTextFileAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult<byte[]> result = await _ShareSession!.Files.TryReadAllBytesAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            string text = Encoding.UTF8.GetString(result.Value!);
            Console.WriteLine("[OK] File contents for " + GetDisplayRemotePath(normalizedPath) + ":");
            Console.WriteLine(text);
        }

        private static async Task WriteTextFileAsync(string path, string text, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            byte[] data = Encoding.UTF8.GetBytes(text);
            OpenCifsClientResult result = await _ShareSession!.Files.TryWriteAllBytesAsync(normalizedPath, data, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Wrote " + data.Length + " bytes to " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        private static async Task UploadFileAsync(string localPath, string remotePath, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string fullLocalPath = Path.GetFullPath(localPath);
            if (!File.Exists(fullLocalPath))
            {
                Console.WriteLine("[ERROR] Local file was not found: " + fullLocalPath);
                return;
            }

            byte[] data = await File.ReadAllBytesAsync(fullLocalPath, cancellationToken).ConfigureAwait(false);
            string normalizedRemotePath = NormalizeRemotePath(remotePath);
            OpenCifsClientResult result = await _ShareSession!.Files.TryWriteAllBytesAsync(normalizedRemotePath, data, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Uploaded " + data.Length + " bytes to " + GetDisplayRemotePath(normalizedRemotePath) + ".");
        }

        private static async Task DownloadFileAsync(string remotePath, string localPath, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedRemotePath = NormalizeRemotePath(remotePath);
            OpenCifsClientResult<byte[]> result = await _ShareSession!.Files.TryReadAllBytesAsync(normalizedRemotePath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            string fullLocalPath = Path.GetFullPath(localPath);
            string? localDirectory = Path.GetDirectoryName(fullLocalPath);
            if (!string.IsNullOrWhiteSpace(localDirectory))
            {
                Directory.CreateDirectory(localDirectory);
            }

            await File.WriteAllBytesAsync(fullLocalPath, result.Value!, cancellationToken).ConfigureAwait(false);
            Console.WriteLine("[OK] Downloaded " + result.Value!.Length + " bytes to " + fullLocalPath + ".");
        }

        private static async Task DeleteFileAsync(string path, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedPath = NormalizeRemotePath(path);
            OpenCifsClientResult result = await _ShareSession!.Files.TryDeleteAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(result.Exception!));
                return;
            }

            Console.WriteLine("[OK] Deleted file " + GetDisplayRemotePath(normalizedPath) + ".");
        }

        private static async Task RenamePathAsync(string sourcePath, string destinationPath, CancellationToken cancellationToken)
        {
            if (!EnsureShareIsOpen())
            {
                return;
            }

            string normalizedSourcePath = NormalizeRemotePath(sourcePath);
            string normalizedDestinationPath = NormalizeRemotePath(destinationPath);
            OpenCifsClientResult<OpenCifsClientFileMetadata> metadataResult = await _ShareSession!.Metadata.TryGetAttributesAsync(normalizedSourcePath, cancellationToken).ConfigureAwait(false);

            if (!metadataResult.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(metadataResult.Exception!));
                return;
            }

            OpenCifsClientResult renameResult = metadataResult.Value!.IsDirectory
                ? await _ShareSession.Directories.TryRenameAsync(normalizedSourcePath, normalizedDestinationPath, cancellationToken: cancellationToken).ConfigureAwait(false)
                : await _ShareSession.Files.TryRenameAsync(normalizedSourcePath, normalizedDestinationPath, cancellationToken: cancellationToken).ConfigureAwait(false);

            if (!renameResult.IsSuccess)
            {
                Console.WriteLine(FormatClientFailure(renameResult.Exception!));
                return;
            }

            Console.WriteLine(
                "[OK] Renamed " +
                GetDisplayRemotePath(normalizedSourcePath) +
                " -> " +
                GetDisplayRemotePath(normalizedDestinationPath) +
                ".");
        }

        private static OpenCifsClientCredential CreateCredential()
        {
            return new OpenCifsClientCredential
            {
                UserName = _UserName,
                UserDomain = _UserDomain,
                Password = _Password
            };
        }

        private static OpenCifsClientBuilder CreateClientBuilder(string serverName, int serverPort)
        {
            return new OpenCifsClientBuilder()
                .WithServer(serverName, serverPort)
                .WithDialectRange(_MinimumDialect, _MaximumDialect)
                .WithSigningRequired(_RequireSigning)
                .WithPreferredEncryption(_PreferEncryption)
                .WithConnectTimeoutMs(_ConnectTimeoutMs);
        }

        private static bool EnsureShareIsOpen()
        {
            if (_ShareSession != null)
            {
                return true;
            }

            Console.WriteLine("[ERROR] Open a share first.");
            return false;
        }

        private static string NormalizeRemotePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return _CurrentRemotePath;
            }

            string candidatePath = path.Replace('\\', '/');
            bool isAbsolute = candidatePath.StartsWith("/", StringComparison.Ordinal);
            List<string> segments = new List<string>();

            if (!isAbsolute)
            {
                AddSegments(segments, _CurrentRemotePath);
            }

            AddSegments(segments, candidatePath);
            return BuildRemotePath(segments);
        }

        private static void AddSegments(List<string> segments, string path)
        {
            string[] pathSegments = path.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            for (int index = 0; index < pathSegments.Length; index++)
            {
                string segment = pathSegments[index];

                if (segment == ".")
                {
                    continue;
                }

                if (segment == "..")
                {
                    if (segments.Count > 0)
                    {
                        segments.RemoveAt(segments.Count - 1);
                    }

                    continue;
                }

                segments.Add(segment);
            }
        }

        private static string BuildRemotePath(List<string> segments)
        {
            if (segments.Count == 0)
            {
                return "/";
            }

            return "/" + string.Join("/", segments);
        }

        private static string CombineRemotePath(string basePath, string childName)
        {
            List<string> segments = new List<string>();
            AddSegments(segments, basePath);
            AddSegments(segments, childName);
            return BuildRemotePath(segments);
        }

        private static string GetDisplayRemotePath(string path)
        {
            return string.IsNullOrWhiteSpace(path) ? "/" : path;
        }

        private static string FormatNullableDateTime(DateTime? value)
        {
            return value.HasValue ? value.Value.ToString("u") : "(none)";
        }

        private static string DisplayOrBlank(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "(blank)" : value;
        }

        private static bool ContainsWildcard(string value)
        {
            return value.Contains('*') || value.Contains('?');
        }

        private static int ParsePort(string value)
        {
            return ParsePositiveInt(value, 1, 65535);
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
            List<string> tokens = new List<string>();
            StringBuilder current = new StringBuilder();
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

        private static string FormatClientFailure(OpenCifsClientException exception)
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

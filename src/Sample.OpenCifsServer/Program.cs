namespace Sample.OpenCifsServer
{
    using System;
    using System.IO;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using System.Threading;
    using OpenCIFS.Server;

    /// <summary>
    /// Entry point for the bootstrap sample server utility.
    /// </summary>
    public static class Program
    {
        /// <summary>
        /// Run the sample configuration utility.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <returns>Process exit code.</returns>
        public static int Main(string[] args)
        {
            try
            {
                return Run(args);
            }
            catch (OperationCanceledException)
            {
                return 0;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("[sample-server] " + FormatExceptionForConsole(exception));
                return 1;
            }
        }

        private static int Run(string[] args)
        {
            SampleServerCommandLineOptions commandLineOptions = SampleServerCommandLineParser.Parse(args);
            string configurationPath = Path.GetFullPath(commandLineOptions.ConfigurationPath);

            if (commandLineOptions.WriteDefaultConfiguration)
            {
                WriteDefaultConfiguration(configurationPath);
                Console.WriteLine("Wrote sample configuration to " + configurationPath + ".");
                return 0;
            }

            SampleServerConfiguration configuration = LoadConfiguration(configurationPath).ApplyCommandLineOptions(commandLineOptions);
            OpenCifsServerOptions options = configuration.ToServerOptions(configurationPath);

            if (commandLineOptions.PrintConfiguration)
            {
                Console.WriteLine(SampleServerConsoleFormatter.CreateConfigurationReport(configurationPath, configuration, options));
                return 0;
            }

            if (commandLineOptions.ValidateConfiguration)
            {
                Console.WriteLine(SampleServerConsoleFormatter.CreateValidationReport(configurationPath, configuration, options));
                return 0;
            }

            Console.WriteLine(SampleServerConsoleFormatter.CreateStartupBanner(configurationPath, configuration, options));

            using CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellationTokenSource.Cancel();
            };

            Console.CancelKeyPress += cancelHandler;

            try
            {
                OpenCifsServerBuilder builder = CreateServerBuilder(options, configuration.ToServerAccount());
                OpenCifsServer serverDefinition = builder.Build();
                OpenCifsServerApplication server = serverDefinition.BuildApplication(
                    exception => Console.Error.WriteLine("[sample-server] " + FormatExceptionForConsole(exception)));
                server.RunAsync(cancellationTokenSource.Token).GetAwaiter().GetResult();
                return 0;
            }
            finally
            {
                Console.CancelKeyPress -= cancelHandler;
            }
        }

        private static SampleServerConfiguration LoadConfiguration(string configurationPath)
        {
            if (!File.Exists(configurationPath))
            {
                return new SampleServerConfiguration();
            }

            string json = File.ReadAllText(configurationPath);
            JsonSerializerOptions serializerOptions = CreateSerializerOptions();
            SampleServerConfiguration? configuration = JsonSerializer.Deserialize<SampleServerConfiguration>(json, serializerOptions);
            return configuration ?? new SampleServerConfiguration();
        }

        private static void WriteDefaultConfiguration(string configurationPath)
        {
            SampleServerConfiguration configuration = new SampleServerConfiguration();
            JsonSerializerOptions serializerOptions = CreateSerializerOptions();
            string json = JsonSerializer.Serialize(configuration, serializerOptions);
            string? configurationDirectory = Path.GetDirectoryName(Path.GetFullPath(configurationPath));

            if (!String.IsNullOrEmpty(configurationDirectory))
            {
                Directory.CreateDirectory(configurationDirectory);
            }

            File.WriteAllText(configurationPath, json);
        }

        private static OpenCifsServerBuilder CreateServerBuilder(OpenCifsServerOptions options, OpenCifsServerAccount account)
        {
            options.DiagnosticLogger = message =>
            {
                Console.Error.WriteLine("[sample-server] " + message);
                Console.Error.Flush();
            };
            OpenCifsServerBuilder builder = new OpenCifsServerBuilder(options);
            builder.AddFileSystemShare(options.ShareName, options.SharePath, createRootIfMissing: true);
            builder.AddAccount(account);
            return builder;
        }

        private static JsonSerializerOptions CreateSerializerOptions()
        {
            JsonSerializerOptions serializerOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true
            };
            serializerOptions.Converters.Add(new JsonStringEnumConverter());

            return serializerOptions;
        }

        private static string FormatExceptionForConsole(Exception exception)
        {
            string message = exception.GetType().Name + ": " + exception.Message;

            if (exception.InnerException != null)
            {
                message += " | Inner: " + exception.InnerException.GetType().Name + ": " + exception.InnerException.Message;
            }

            return message;
        }
    }
}

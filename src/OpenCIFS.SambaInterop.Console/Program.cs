namespace OpenCIFS.SambaInterop.Console
{
    using System;
    using System.IO;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;

    internal static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            try
            {
                SambaInteropOptions options = SambaInteropArgumentParser.ParseArguments(args);
                SambaInteropSmokeResult result = await SambaInteropSmokeRunner.RunAsync(options).ConfigureAwait(false);
                JsonSerializerOptions serializerOptions = new JsonSerializerOptions
                {
                    WriteIndented = true
                };
                string json = JsonSerializer.Serialize(result, serializerOptions);

                if (!string.IsNullOrWhiteSpace(options.OutputPath))
                {
                    string? outputDirectory = Path.GetDirectoryName(options.OutputPath);

                    if (!string.IsNullOrWhiteSpace(outputDirectory))
                    {
                        Directory.CreateDirectory(outputDirectory);
                    }

                    await File.WriteAllTextAsync(options.OutputPath, json, Encoding.UTF8).ConfigureAwait(false);
                }

                System.Console.WriteLine(json);
                return 0;
            }
            catch (Exception exception)
            {
                System.Console.Error.WriteLine(exception);
                return 1;
            }
        }
    }
}

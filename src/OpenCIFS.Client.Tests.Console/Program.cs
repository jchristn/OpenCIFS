namespace OpenCIFS.Client.Tests.Console
{
    using System;
    using System.Threading.Tasks;
    using OpenCIFS.Client.Tests.Shared;
    using Touchstone.Cli;

    /// <summary>
    /// Console runner for client Touchstone suites.
    /// </summary>
    public static class Program
    {
        /// <summary>
        /// Execute the client Touchstone suites.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <returns>Process exit code.</returns>
        public static Task<int> Main(string[] args)
        {
            string? resultsPath = null;

            for (int index = 0; index < args.Length - 1; index++)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(args[index], "--results"))
                {
                    resultsPath = args[index + 1];
                    break;
                }
            }

            return ConsoleRunner.RunAsync(ClientTestSuites.All, resultsPath: resultsPath);
        }
    }
}

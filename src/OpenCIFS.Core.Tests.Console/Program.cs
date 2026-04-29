namespace OpenCIFS.Core.Tests.Console
{
    using System;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using Touchstone.Cli;

    /// <summary>
    /// Console runner for core Touchstone suites.
    /// </summary>
    public static class Program
    {
        /// <summary>
        /// Execute the core Touchstone suites.
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

            return ConsoleRunner.RunAsync(CoreTestSuites.All, resultsPath: resultsPath);
        }
    }
}

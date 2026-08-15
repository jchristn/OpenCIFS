namespace OpenCIFS.Test.Automated
{
    using System;
    using System.Threading.Tasks;
    using OpenCIFS.Test.Shared;
    using Touchstone.Cli;

    /// <summary>
    /// Touchstone command-line runner that executes every OpenCIFS shared suite and
    /// reports pass/fail through the process exit code. Pass <c>--results &lt;path&gt;</c>
    /// to emit a machine-readable JSON result file.
    /// </summary>
    public static class Program
    {
        /// <summary>
        /// Execute the aggregate OpenCIFS Touchstone suites.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <returns>Process exit code; zero when every suite passes.</returns>
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

            return ConsoleRunner.RunAsync(AllSuites.All, resultsPath: resultsPath);
        }
    }
}

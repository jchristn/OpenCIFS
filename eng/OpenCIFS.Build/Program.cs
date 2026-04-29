namespace OpenCIFS.Build
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Entry point for OpenCIFS build validation utilities.
    /// </summary>
    internal static class Program
    {
        /// <summary>
        /// Execute a build validation command.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <returns>Process exit code.</returns>
        private static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.Error.WriteLine("Usage: OpenCIFS.Build validate-coverage <coverage-matrix-path>");
                Console.Error.WriteLine("   or: OpenCIFS.Build validate-package-graph <source-root-path>");
                Console.Error.WriteLine("   or: OpenCIFS.Build validate-interop <interop-matrix-path>");
                return 1;
            }

            IReadOnlyList<string> errors;
            string successMessage;

            if (StringComparer.OrdinalIgnoreCase.Equals(args[0], "validate-coverage"))
            {
                errors = CoverageMatrixValidator.Validate(args[1]);
                successMessage = "Coverage matrix validation passed.";
            }
            else if (StringComparer.OrdinalIgnoreCase.Equals(args[0], "validate-package-graph"))
            {
                errors = PackageGraphValidator.Validate(args[1]);
                successMessage = "Package graph validation passed.";
            }
            else if (StringComparer.OrdinalIgnoreCase.Equals(args[0], "validate-interop"))
            {
                errors = InteropMatrixValidator.Validate(args[1]);
                successMessage = "Interop matrix validation passed.";
            }
            else
            {
                Console.Error.WriteLine("Usage: OpenCIFS.Build validate-coverage <coverage-matrix-path>");
                Console.Error.WriteLine("   or: OpenCIFS.Build validate-package-graph <source-root-path>");
                Console.Error.WriteLine("   or: OpenCIFS.Build validate-interop <interop-matrix-path>");
                return 1;
            }

            if (errors.Count == 0)
            {
                Console.WriteLine(successMessage);
                return 0;
            }

            for (int index = 0; index < errors.Count; index++)
            {
                Console.Error.WriteLine(errors[index]);
            }

            return 1;
        }
    }
}

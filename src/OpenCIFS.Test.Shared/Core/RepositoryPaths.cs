namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.IO;

    /// <summary>
    /// Repository path helpers for test suites.
    /// </summary>
    public static class RepositoryPaths
    {
        /// <summary>
        /// Resolve the repository root directory.
        /// </summary>
        /// <returns>Absolute repository root path.</returns>
        /// <exception cref="DirectoryNotFoundException">Thrown when the repository root cannot be located.</exception>
        public static string GetRepositoryRoot()
        {
            DirectoryInfo? current = new DirectoryInfo(AppContext.BaseDirectory);

            while (current != null)
            {
                string solutionPath = Path.Combine(current.FullName, "src", "OpenCIFS.sln");
                string gitPath = Path.Combine(current.FullName, ".git");

                if (File.Exists(solutionPath) && (Directory.Exists(gitPath) || File.Exists(gitPath)))
                {
                    return current.FullName;
                }

                current = current.Parent;
            }

            throw new DirectoryNotFoundException("Unable to locate the OpenCIFS repository root from " + AppContext.BaseDirectory + ".");
        }

        /// <summary>
        /// Build an absolute path from the repository root.
        /// </summary>
        /// <param name="relativePath">Relative path under the repository root.</param>
        /// <returns>Absolute path.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="relativePath" /> is null or whitespace.</exception>
        public static string FromRoot(string relativePath)
        {
            if (String.IsNullOrWhiteSpace(relativePath))
            {
                throw new ArgumentNullException(nameof(relativePath), "Relative path cannot be null or whitespace.");
            }

            return Path.Combine(GetRepositoryRoot(), relativePath);
        }
    }
}

namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.IO;

    /// <summary>
    /// Shared temporary-path and cleanup helpers for OpenCIFS test suites.
    /// </summary>
    public static class TestPathUtilities
    {
        /// <summary>
        /// Create a unique temporary directory and return its absolute path.
        /// </summary>
        /// <param name="prefix">Directory-name prefix.</param>
        /// <returns>Created directory path.</returns>
        public static string CreateUniqueDirectory(string prefix)
        {
            if (String.IsNullOrWhiteSpace(prefix))
            {
                throw new ArgumentNullException(nameof(prefix), "Directory prefix cannot be null or whitespace.");
            }

            string path = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return path;
        }

        /// <summary>
        /// Forcefully delete a directory tree, clearing file attributes first.
        /// </summary>
        /// <param name="rootPath">Directory tree to delete.</param>
        public static void DeleteDirectoryForcefully(string rootPath)
        {
            if (String.IsNullOrWhiteSpace(rootPath))
            {
                throw new ArgumentNullException(nameof(rootPath), "Root path cannot be null or whitespace.");
            }

            if (!Directory.Exists(rootPath))
            {
                return;
            }

            foreach (string filePath in Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(filePath, FileAttributes.Normal);
            }

            foreach (string directoryPath in Directory.EnumerateDirectories(rootPath, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(directoryPath, FileAttributes.Directory);
            }

            File.SetAttributes(rootPath, FileAttributes.Directory);
            Directory.Delete(rootPath, recursive: true);
        }
    }
}

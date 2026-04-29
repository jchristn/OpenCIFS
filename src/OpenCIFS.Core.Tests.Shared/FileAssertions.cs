namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.IO;

    /// <summary>
    /// Shared file assertions for repository bootstrap tests.
    /// </summary>
    public static class FileAssertions
    {
        /// <summary>
        /// Assert that a file exists.
        /// </summary>
        /// <param name="path">Absolute file path.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="path" /> is null or whitespace.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
        public static void AssertExists(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            if (!File.Exists(path))
            {
                throw new FileNotFoundException("Expected file was not found.", path);
            }
        }

        /// <summary>
        /// Assert that a file contains the expected text.
        /// </summary>
        /// <param name="path">Absolute file path.</param>
        /// <param name="expectedText">Expected text.</param>
        /// <exception cref="ArgumentNullException">Thrown when an input is null or whitespace.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the expected text is missing.</exception>
        public static void AssertContains(string path, string expectedText)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            if (String.IsNullOrWhiteSpace(expectedText))
            {
                throw new ArgumentNullException(nameof(expectedText), "Expected text cannot be null or whitespace.");
            }

            string content = File.ReadAllText(path);

            if (!content.Contains(expectedText, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Expected text was not found in " + path + ": " + expectedText + ".");
            }
        }
    }
}

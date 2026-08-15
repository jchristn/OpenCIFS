namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text.Json;

    /// <summary>
    /// Shared loader for deterministic OpenCIFS known-answer vectors stored under <c>docs/protocol-notes</c>.
    /// </summary>
    public static class GoldenVectorStore
    {
        /// <summary>
        /// Resolve a vector payload as bytes.
        /// </summary>
        /// <param name="vectorName">Stable vector key.</param>
        /// <returns>Decoded bytes.</returns>
        public static byte[] GetBytes(string vectorName)
        {
            string value = GetString(vectorName);
            return Convert.FromHexString(value.Replace(" ", String.Empty, StringComparison.Ordinal));
        }

        /// <summary>
        /// Resolve a vector payload as its stored string value.
        /// </summary>
        /// <param name="vectorName">Stable vector key.</param>
        /// <returns>Stored string value.</returns>
        public static string GetString(string vectorName)
        {
            if (String.IsNullOrWhiteSpace(vectorName))
            {
                throw new ArgumentNullException(nameof(vectorName), "Vector name cannot be null or whitespace.");
            }

            Dictionary<string, string> vectors = LoadVectors();

            if (!vectors.TryGetValue(vectorName, out string? value) || String.IsNullOrWhiteSpace(value))
            {
                throw new KeyNotFoundException("Golden vector '" + vectorName + "' was not found.");
            }

            return value;
        }

        private static Dictionary<string, string> LoadVectors()
        {
            if (_CachedVectors != null)
            {
                return _CachedVectors;
            }

            string path = RepositoryPaths.FromRoot(Path.Combine("docs", "protocol-notes", "golden-vectors", "security-vectors.json"));
            string json = File.ReadAllText(path);
            Dictionary<string, string>? vectors = JsonSerializer.Deserialize<Dictionary<string, string>>(json);

            if (vectors == null)
            {
                throw new InvalidOperationException("The golden-vector file '" + path + "' did not deserialize to a key-value map.");
            }

            _CachedVectors = vectors;
            return vectors;
        }

        private static Dictionary<string, string>? _CachedVectors;
    }
}

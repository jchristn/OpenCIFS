namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Text.Json;

    /// <summary>
    /// Writes deterministic binary and hex packet-trace snapshots for OpenCIFS test diagnostics.
    /// </summary>
    public sealed class PacketCaptureTraceWriter
    {
        private readonly List<Dictionary<string, object>> _Entries;
        private readonly string _TraceDirectoryPath;

        /// <summary>
        /// Initialize a packet-trace writer under the specified root directory.
        /// </summary>
        /// <param name="rootDirectoryPath">Parent directory for the trace.</param>
        /// <param name="traceName">Stable trace name.</param>
        public PacketCaptureTraceWriter(string rootDirectoryPath, string traceName)
        {
            if (String.IsNullOrWhiteSpace(rootDirectoryPath))
            {
                throw new ArgumentNullException(nameof(rootDirectoryPath), "Root directory path cannot be null or whitespace.");
            }

            if (String.IsNullOrWhiteSpace(traceName))
            {
                throw new ArgumentNullException(nameof(traceName), "Trace name cannot be null or whitespace.");
            }

            RootDirectoryPath = rootDirectoryPath;
            TraceName = traceName;
            _Entries = new List<Dictionary<string, object>>();
            _TraceDirectoryPath = Path.Combine(rootDirectoryPath, SanitizeSegment(traceName));
            Directory.CreateDirectory(_TraceDirectoryPath);
        }

        /// <summary>
        /// Root directory passed to the trace writer.
        /// </summary>
        public string RootDirectoryPath { get; }

        /// <summary>
        /// Stable trace name.
        /// </summary>
        public string TraceName { get; }

        /// <summary>
        /// Capture a named payload into the trace directory.
        /// </summary>
        /// <param name="label">Logical packet label.</param>
        /// <param name="payload">Packet bytes.</param>
        /// <returns>Binary payload path.</returns>
        public string Capture(string label, ReadOnlySpan<byte> payload)
        {
            if (String.IsNullOrWhiteSpace(label))
            {
                throw new ArgumentNullException(nameof(label), "Capture label cannot be null or whitespace.");
            }

            byte[] buffer = payload.ToArray();
            string filePrefix = (_Entries.Count + 1).ToString("D3", CultureInfo.InvariantCulture) + "-" + SanitizeSegment(label);
            string binaryPath = Path.Combine(_TraceDirectoryPath, filePrefix + ".bin");
            string hexPath = Path.Combine(_TraceDirectoryPath, filePrefix + ".hex.txt");

            File.WriteAllBytes(binaryPath, buffer);
            File.WriteAllText(hexPath, Convert.ToHexString(buffer));

            _Entries.Add(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["index"] = _Entries.Count + 1,
                ["label"] = label,
                ["length"] = buffer.Length,
                ["binary_path"] = binaryPath,
                ["hex_path"] = hexPath
            });

            return binaryPath;
        }

        /// <summary>
        /// Write the trace manifest and return its path.
        /// </summary>
        /// <returns>Manifest path.</returns>
        public string WriteManifest()
        {
            string manifestPath = Path.Combine(_TraceDirectoryPath, "manifest.json");
            Dictionary<string, object> manifest = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["generated_at_utc"] = DeterministicTestClock.GetUtc("PacketCaptureTraceWriter:" + TraceName).ToString("o", CultureInfo.InvariantCulture),
                ["trace_name"] = TraceName,
                ["trace_directory"] = _TraceDirectoryPath,
                ["packet_count"] = _Entries.Count,
                ["entries"] = _Entries
            };
            string json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(manifestPath, json);
            return manifestPath;
        }

        private static string SanitizeSegment(string value)
        {
            char[] invalidCharacters = Path.GetInvalidFileNameChars();
            char[] sanitized = value.ToCharArray();

            for (int index = 0; index < sanitized.Length; index++)
            {
                for (int invalidIndex = 0; invalidIndex < invalidCharacters.Length; invalidIndex++)
                {
                    if (sanitized[index] == invalidCharacters[invalidIndex])
                    {
                        sanitized[index] = '_';
                        break;
                    }
                }
            }

            return new string(sanitized).Replace(' ', '_');
        }
    }
}

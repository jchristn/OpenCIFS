namespace OpenCIFS.Build
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    /// <summary>
    /// Validates the coverage matrix release artifact.
    /// </summary>
    internal static class CoverageMatrixValidator
    {
        private static readonly string[] _RequiredHeaders =
        {
            "dialect",
            "area",
            "command or capability",
            "server status",
            "client status",
            "advertised",
            "implemented",
            "test suite name",
            "descriptor count",
            "descriptor skipped count",
            "last samba verification date",
            "last windows verification date",
            "notes"
        };

        /// <summary>
        /// Validate the markdown coverage matrix.
        /// </summary>
        /// <param name="path">Coverage matrix path.</param>
        /// <returns>Validation errors.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="path" /> is null or whitespace.</exception>
        internal static IReadOnlyList<string> Validate(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Coverage matrix path cannot be null or whitespace.");
            }

            List<string> errors = new List<string>();

            if (!File.Exists(path))
            {
                errors.Add("Coverage matrix file was not found: " + path + ".");
                return errors;
            }

            string[] lines = File.ReadAllLines(path);
            int headerIndex = FindHeaderIndex(lines);

            if (headerIndex < 0)
            {
                errors.Add("Coverage matrix header row was not found.");
                return errors;
            }

            string[] headers = ParseColumns(lines[headerIndex]);

            for (int index = 0; index < _RequiredHeaders.Length; index++)
            {
                if (!StringComparer.OrdinalIgnoreCase.Equals(headers[index], _RequiredHeaders[index]))
                {
                    errors.Add("Coverage matrix header mismatch at column " + index + ". Expected '" + _RequiredHeaders[index] + "' but found '" + headers[index] + "'.");
                }
            }

            for (int lineIndex = headerIndex + 2; lineIndex < lines.Length; lineIndex++)
            {
                string line = lines[lineIndex];

                if (String.IsNullOrWhiteSpace(line) || !line.TrimStart().StartsWith("|", StringComparison.Ordinal))
                {
                    continue;
                }

                string[] columns = ParseColumns(line);

                if (columns.Length != _RequiredHeaders.Length)
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " does not contain " + _RequiredHeaders.Length + " columns.");
                    continue;
                }

                if (!Boolean.TryParse(columns[5], out bool advertised))
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " has an invalid advertised value '" + columns[5] + "'.");
                    continue;
                }

                if (!Boolean.TryParse(columns[6], out bool implemented))
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " has an invalid implemented value '" + columns[6] + "'.");
                    continue;
                }

                if (!Int32.TryParse(columns[8], out int descriptorCount))
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " has an invalid descriptor count '" + columns[8] + "'.");
                    continue;
                }

                if (!Int32.TryParse(columns[9], out int descriptorSkippedCount))
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " has an invalid descriptor skipped count '" + columns[9] + "'.");
                    continue;
                }

                if (descriptorCount < 0)
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " has a negative descriptor count.");
                }

                if (descriptorSkippedCount < 0)
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " has a negative descriptor skipped count.");
                }

                if (!implemented && advertised)
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " advertises a capability that is not implemented.");
                }

                if (implemented && descriptorSkippedCount != 0)
                {
                    errors.Add("Coverage matrix row " + (lineIndex + 1) + " is marked implemented while descriptor skipped count is non-zero.");
                }
            }

            return errors;
        }

        private static int FindHeaderIndex(string[] lines)
        {
            for (int index = 0; index < lines.Length; index++)
            {
                if (lines[index].Contains("| dialect | area | command or capability |", StringComparison.Ordinal))
                {
                    return index;
                }
            }

            return -1;
        }

        private static string[] ParseColumns(string line)
        {
            string trimmed = line.Trim();

            if (trimmed.StartsWith("|", StringComparison.Ordinal))
            {
                trimmed = trimmed.Substring(1);
            }

            if (trimmed.EndsWith("|", StringComparison.Ordinal))
            {
                trimmed = trimmed.Substring(0, trimmed.Length - 1);
            }

            string[] rawColumns = trimmed.Split('|', StringSplitOptions.None);
            string[] columns = new string[rawColumns.Length];

            for (int index = 0; index < rawColumns.Length; index++)
            {
                columns[index] = rawColumns[index].Trim();
            }

            return columns;
        }
    }
}

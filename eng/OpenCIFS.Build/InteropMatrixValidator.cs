namespace OpenCIFS.Build
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;

    /// <summary>
    /// Validates the interop matrix release artifact.
    /// </summary>
    internal static class InteropMatrixValidator
    {
        private static readonly string[] _RequiredHeaders =
        {
            "role",
            "peer",
            "target environment",
            "dialect scope",
            "smoke status",
            "deep status",
            "last verified date",
            "evidence",
            "notes"
        };

        /// <summary>
        /// Validate the markdown interop matrix.
        /// </summary>
        /// <param name="path">Interop matrix path.</param>
        /// <returns>Validation errors.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="path" /> is null or whitespace.</exception>
        internal static IReadOnlyList<string> Validate(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Interop matrix path cannot be null or whitespace.");
            }

            List<string> errors = new List<string>();

            if (!File.Exists(path))
            {
                errors.Add("Interop matrix file was not found: " + path + ".");
                return errors;
            }

            string[] lines = File.ReadAllLines(path);
            int headerIndex = FindHeaderIndex(lines);

            if (headerIndex < 0)
            {
                errors.Add("Interop matrix header row was not found.");
                return errors;
            }

            string[] headers = ParseColumns(lines[headerIndex]);

            for (int index = 0; index < _RequiredHeaders.Length; index++)
            {
                if (!StringComparer.OrdinalIgnoreCase.Equals(headers[index], _RequiredHeaders[index]))
                {
                    errors.Add("Interop matrix header mismatch at column " + index + ". Expected '" + _RequiredHeaders[index] + "' but found '" + headers[index] + "'.");
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
                    errors.Add("Interop matrix row " + (lineIndex + 1) + " does not contain " + _RequiredHeaders.Length + " columns.");
                    continue;
                }

                if (!IsValidStatus(columns[4]))
                {
                    errors.Add("Interop matrix row " + (lineIndex + 1) + " has an invalid smoke status '" + columns[4] + "'.");
                }

                if (!IsValidStatus(columns[5]))
                {
                    errors.Add("Interop matrix row " + (lineIndex + 1) + " has an invalid deep status '" + columns[5] + "'.");
                }

                bool smokePassed = StringComparer.OrdinalIgnoreCase.Equals(columns[4], "pass");
                bool deepPassed = StringComparer.OrdinalIgnoreCase.Equals(columns[5], "pass");
                bool smokeNotRun = StringComparer.OrdinalIgnoreCase.Equals(columns[4], "not run");
                bool deepNotRun = StringComparer.OrdinalIgnoreCase.Equals(columns[5], "not run");
                string lastVerifiedDate = columns[6];
                string evidence = columns[7];

                if (!StringComparer.OrdinalIgnoreCase.Equals(lastVerifiedDate, "n/a") &&
                    !DateTime.TryParseExact(lastVerifiedDate, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
                {
                    errors.Add("Interop matrix row " + (lineIndex + 1) + " has an invalid last verified date '" + lastVerifiedDate + "'.");
                }

                if ((smokePassed || deepPassed) && StringComparer.OrdinalIgnoreCase.Equals(lastVerifiedDate, "n/a"))
                {
                    errors.Add("Interop matrix row " + (lineIndex + 1) + " is marked pass but does not record a last verified date.");
                }

                if ((smokePassed || deepPassed) && StringComparer.OrdinalIgnoreCase.Equals(evidence, "n/a"))
                {
                    errors.Add("Interop matrix row " + (lineIndex + 1) + " is marked pass but does not list any evidence.");
                }

                if (smokeNotRun && deepNotRun)
                {
                    if (!StringComparer.OrdinalIgnoreCase.Equals(lastVerifiedDate, "n/a"))
                    {
                        errors.Add("Interop matrix row " + (lineIndex + 1) + " is marked not run but records a concrete last verified date.");
                    }

                    if (!StringComparer.OrdinalIgnoreCase.Equals(evidence, "n/a"))
                    {
                        errors.Add("Interop matrix row " + (lineIndex + 1) + " is marked not run but lists concrete evidence.");
                    }
                }

                if (!StringComparer.OrdinalIgnoreCase.Equals(evidence, "n/a"))
                {
                    string[] evidenceEntries = evidence.Split(',', StringSplitOptions.RemoveEmptyEntries);

                    if (evidenceEntries.Length == 0)
                    {
                        errors.Add("Interop matrix row " + (lineIndex + 1) + " lists evidence but no paths could be parsed.");
                    }

                    for (int evidenceIndex = 0; evidenceIndex < evidenceEntries.Length; evidenceIndex++)
                    {
                        string evidenceEntry = evidenceEntries[evidenceIndex].Trim().Trim('`');

                        if (String.IsNullOrWhiteSpace(evidenceEntry))
                        {
                            errors.Add("Interop matrix row " + (lineIndex + 1) + " contains an empty evidence entry.");
                        }
                    }
                }
            }

            return errors;
        }

        private static int FindHeaderIndex(string[] lines)
        {
            for (int index = 0; index < lines.Length; index++)
            {
                if (lines[index].Contains("| role | peer | target environment |", StringComparison.Ordinal))
                {
                    return index;
                }
            }

            return -1;
        }

        private static bool IsValidStatus(string value)
        {
            return
                StringComparer.OrdinalIgnoreCase.Equals(value, "pass") ||
                StringComparer.OrdinalIgnoreCase.Equals(value, "fail") ||
                StringComparer.OrdinalIgnoreCase.Equals(value, "not run");
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

namespace OpenCIFS.Build
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    /// <summary>
    /// Validates the repository for forbidden placeholder and TODO-based release claims.
    /// </summary>
    internal static class SourceAuditValidator
    {
        private static readonly string[] _AuditRoots =
        {
            "eng",
            "docs\\samples",
            "src\\OpenCIFS.Protocol",
            "src\\OpenCIFS.Transport",
            "src\\OpenCIFS.Security",
            "src\\OpenCIFS.Server",
            "src\\OpenCIFS.Client",
            "src\\Sample.OpenCifsServer",
        };

        private static readonly string[] _ReleaseFacingFiles =
        {
            "README.md",
            "src\\OpenCIFS.Protocol\\PackageReadme.md",
            "src\\OpenCIFS.Security\\PackageReadme.md",
            "src\\OpenCIFS.Transport\\PackageReadme.md",
            "src\\OpenCIFS.Server\\PackageReadme.md",
            "src\\OpenCIFS.Client\\PackageReadme.md",
        };

        /// <summary>
        /// Validate the repository source audit rules.
        /// </summary>
        /// <param name="repositoryRoot">Repository root path.</param>
        /// <returns>Validation errors.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="repositoryRoot" /> is null or whitespace.</exception>
        internal static IReadOnlyList<string> Validate(string repositoryRoot)
        {
            if (String.IsNullOrWhiteSpace(repositoryRoot))
            {
                throw new ArgumentNullException(nameof(repositoryRoot), "Repository root path cannot be null or whitespace.");
            }

            List<string> errors = new List<string>();

            if (!Directory.Exists(repositoryRoot))
            {
                errors.Add("Repository root directory was not found: " + repositoryRoot + ".");
                return errors;
            }

            ValidateAuditRoots(repositoryRoot, errors);
            ValidateReleaseFacingFiles(repositoryRoot, errors);

            return errors;
        }

        private static void ValidateAuditRoots(string repositoryRoot, List<string> errors)
        {
            for (int rootIndex = 0; rootIndex < _AuditRoots.Length; rootIndex++)
            {
                string relativeRoot = _AuditRoots[rootIndex];
                string fullRoot = Path.Combine(repositoryRoot, relativeRoot);

                if (!Directory.Exists(fullRoot))
                {
                    continue;
                }

                foreach (string filePath in Directory.EnumerateFiles(fullRoot, "*", SearchOption.AllDirectories))
                {
                    if (ShouldSkipFile(filePath))
                    {
                        continue;
                    }

                    ValidateFile(
                        filePath,
                        requireNoNotImplementedException: IsProductSourceFile(filePath),
                        requireNoPlaceholderLanguage: ShouldEnforcePlaceholderLanguage(filePath),
                        errors: errors);
                }
            }
        }

        private static void ValidateReleaseFacingFiles(string repositoryRoot, List<string> errors)
        {
            for (int fileIndex = 0; fileIndex < _ReleaseFacingFiles.Length; fileIndex++)
            {
                string relativePath = _ReleaseFacingFiles[fileIndex];
                string fullPath = Path.Combine(repositoryRoot, relativePath);

                if (!File.Exists(fullPath))
                {
                    errors.Add("Release-facing file was not found: " + fullPath + ".");
                    continue;
                }

                ValidateFile(
                    fullPath,
                    requireNoNotImplementedException: false,
                    requireNoPlaceholderLanguage: true,
                    errors: errors);
            }
        }

        private static void ValidateFile(string filePath, bool requireNoNotImplementedException, bool requireNoPlaceholderLanguage, List<string> errors)
        {
            string[] lines = File.ReadAllLines(filePath);

            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                string line = lines[lineIndex];

                if (ContainsToken(line, "TODO"))
                {
                    errors.Add("Forbidden TODO token found at " + filePath + ":" + (lineIndex + 1) + ".");
                }

                if (requireNoNotImplementedException && line.IndexOf("NotImplementedException", StringComparison.Ordinal) >= 0)
                {
                    errors.Add("Forbidden NotImplementedException reference found at " + filePath + ":" + (lineIndex + 1) + ".");
                }

                if (requireNoPlaceholderLanguage)
                {
                    if (ContainsToken(line, "placeholder"))
                    {
                        errors.Add("Forbidden placeholder token found at " + filePath + ":" + (lineIndex + 1) + ".");
                    }

                    if (ContainsToken(line, "stub"))
                    {
                        errors.Add("Forbidden stub token found at " + filePath + ":" + (lineIndex + 1) + ".");
                    }
                }
            }
        }

        private static bool ContainsToken(string text, string token)
        {
            int searchIndex = 0;

            while (searchIndex < text.Length)
            {
                int index = text.IndexOf(token, searchIndex, StringComparison.OrdinalIgnoreCase);

                if (index < 0)
                {
                    return false;
                }

                bool validStart = index == 0 || !Char.IsLetterOrDigit(text[index - 1]);
                int endIndex = index + token.Length;
                bool validEnd = endIndex >= text.Length || !Char.IsLetterOrDigit(text[endIndex]);

                if (validStart && validEnd)
                {
                    return true;
                }

                searchIndex = index + token.Length;
            }

            return false;
        }

        private static bool IsProductSourceFile(string filePath)
        {
            return filePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase);
        }

        private static bool ShouldEnforcePlaceholderLanguage(string filePath)
        {
            string normalizedPath = filePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

            return
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "src" + Path.DirectorySeparatorChar + "OpenCIFS.Protocol" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "src" + Path.DirectorySeparatorChar + "OpenCIFS.Transport" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "src" + Path.DirectorySeparatorChar + "OpenCIFS.Security" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "src" + Path.DirectorySeparatorChar + "OpenCIFS.Server" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "src" + Path.DirectorySeparatorChar + "OpenCIFS.Client" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "src" + Path.DirectorySeparatorChar + "Sample.OpenCifsServer" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool ShouldSkipFile(string filePath)
        {
            string normalizedPath = filePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

            if (normalizedPath.IndexOf(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalizedPath.IndexOf(Path.DirectorySeparatorChar + "eng" + Path.DirectorySeparatorChar + "OpenCIFS.Build" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            string extension = Path.GetExtension(filePath);

            return
                !StringComparer.OrdinalIgnoreCase.Equals(extension, ".cs") &&
                !StringComparer.OrdinalIgnoreCase.Equals(extension, ".csproj") &&
                !StringComparer.OrdinalIgnoreCase.Equals(extension, ".md") &&
                !StringComparer.OrdinalIgnoreCase.Equals(extension, ".props") &&
                !StringComparer.OrdinalIgnoreCase.Equals(extension, ".ps1") &&
                !StringComparer.OrdinalIgnoreCase.Equals(extension, ".py") &&
                !StringComparer.OrdinalIgnoreCase.Equals(extension, ".targets");
        }
    }
}

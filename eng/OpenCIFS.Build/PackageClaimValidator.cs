namespace OpenCIFS.Build
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Xml.Linq;

    /// <summary>
    /// Validates that packable package-facing metadata and readmes do not over-claim unsupported features.
    /// </summary>
    internal static class PackageClaimValidator
    {
        private static readonly string[] _DisclaimerMarkers =
        {
            "backlog",
            "not claimed",
            "is not claimed",
            "remain backlog",
            "remains backlog",
            "not a standalone",
            "advanced dependency package",
        };

        private static readonly PackageRule[] _Rules =
        {
            new PackageRule(
                packageId: "OpenCIFS.Protocol",
                relativeProjectPath: Path.Combine("src", "OpenCIFS.Protocol", "OpenCIFS.Protocol.csproj"),
                expectedDescription: "Shared OpenCIFS SMB/CIFS protocol models, codecs, and wire-format foundations.",
                requiredTagTokens: new[] { "smb", "cifs", "protocol", "wire-format", "dotnet" },
                requiredReadmePhrases: new[]
                {
                    "`OpenCIFS.Protocol` is not a standalone SMB client or server.",
                    "SMB 3.x and SMB1/CIFS compatibility work beyond the current bounded scope remains backlog.",
                },
                unsupportedReadmeTopics: new[]
                {
                    "SMB 3.x",
                    "SMB 3",
                    "Kerberos",
                    "DFS",
                    "named pipe",
                    "named pipes",
                }),
            new PackageRule(
                packageId: "OpenCIFS.Security",
                relativeProjectPath: Path.Combine("src", "OpenCIFS.Security", "OpenCIFS.Security.csproj"),
                expectedDescription: "Shared OpenCIFS NTLMv2, SPNEGO, signing, encryption, and key-derivation helpers.",
                requiredTagTokens: new[] { "smb", "cifs", "security", "ntlm", "spnego" },
                requiredReadmePhrases: new[]
                {
                    "`OpenCIFS.Security` is an advanced dependency package.",
                    "Native Kerberos and broader SMB 3.x behavior such as SMB 3.1.1 signing or encryption negotiation remain backlog.",
                },
                unsupportedReadmeTopics: new[]
                {
                    "Kerberos",
                    "durable-handle v2",
                }),
            new PackageRule(
                packageId: "OpenCIFS.Transport",
                relativeProjectPath: Path.Combine("src", "OpenCIFS.Transport", "OpenCIFS.Transport.csproj"),
                expectedDescription: "Shared OpenCIFS direct-TCP, NetBIOS session-service, and framing helpers.",
                requiredTagTokens: new[] { "smb", "cifs", "transport", "direct-tcp", "netbios" },
                requiredReadmePhrases: new[]
                {
                    "`OpenCIFS.Transport` is an advanced dependency package.",
                    "The verified scope currently covers the transport paths exercised by the managed SMB 2.0.2 and SMB 2.1 client and server flows in this repository.",
                },
                unsupportedReadmeTopics: Array.Empty<string>()),
            new PackageRule(
                packageId: "OpenCIFS.Client",
                relativeProjectPath: Path.Combine("src", "OpenCIFS.Client", "OpenCIFS.Client.csproj"),
                expectedDescription: "Managed OpenCIFS direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 client library.",
                requiredTagTokens: new[] { "smb", "cifs", "client", "fileshare", "dotnet" },
                requiredReadmePhrases: new[]
                {
                    "Managed direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 client surface for OpenCIFS.",
                    "bounded remote share browsing and share inspection over `IPC$` and `srvsvc`, plus bounded generic named-pipe transceive over `IPC$`, when the target server exposes those paths",
                    "bounded SMB 3.0 / SMB 3.0.2 secure-negotiate validation",
                    "SMB 3.1.1, Kerberos, and broader Windows-server interop remain backlog.",
                },
                unsupportedReadmeTopics: new[]
                {
                    "Kerberos",
                    "Windows-server interop",
                    "DFS",
                }),
            new PackageRule(
                packageId: "OpenCIFS.Server",
                relativeProjectPath: Path.Combine("src", "OpenCIFS.Server", "OpenCIFS.Server.csproj"),
                expectedDescription: "Managed OpenCIFS direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 server library.",
                requiredTagTokens: new[] { "smb", "cifs", "server", "fileserver", "dotnet" },
                requiredReadmePhrases: new[]
                {
                    "Managed direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 server surface for OpenCIFS.",
                    "bounded local `IPC$` / named-pipe hosting with the built-in `srvsvc` share-enumeration/share-info endpoint, the built-in UTF-8 echo endpoint, plus host-provided named-pipe endpoints",
                    "bounded SMB 3.0 / SMB 3.0.2 negotiate, secure-negotiate validation, AES-CMAC signing, and SMB 3.0.2 AES-128-CCM session encryption",
                    "Continuous availability, persistent clustered handles, SMB 3.1.1, SMB1/CIFS, DFS, broader named-pipe semantics, and Kerberos remain backlog.",
                },
                unsupportedReadmeTopics: new[]
                {
                    "SMB1/CIFS",
                    "DFS",
                    "Kerberos",
                }),
        };

        /// <summary>
        /// Validate package-facing metadata and readmes for all packable OpenCIFS packages.
        /// </summary>
        /// <param name="repositoryRoot">Repository root path.</param>
        /// <returns>Validation errors.</returns>
        internal static IReadOnlyList<string> Validate(string repositoryRoot)
        {
            if (String.IsNullOrWhiteSpace(repositoryRoot))
            {
                throw new ArgumentNullException(nameof(repositoryRoot), "Repository root path cannot be null or whitespace.");
            }

            List<string> errors = new List<string>();
            string fullRepositoryRoot = Path.GetFullPath(repositoryRoot);

            if (!Directory.Exists(fullRepositoryRoot))
            {
                errors.Add("Repository root directory was not found: " + fullRepositoryRoot + ".");
                return errors;
            }

            for (int ruleIndex = 0; ruleIndex < _Rules.Length; ruleIndex++)
            {
                ValidatePackageRule(fullRepositoryRoot, _Rules[ruleIndex], errors);
            }

            return errors;
        }

        private static void ValidatePackageRule(string repositoryRoot, PackageRule rule, List<string> errors)
        {
            string projectPath = Path.Combine(repositoryRoot, rule.RelativeProjectPath);

            if (!File.Exists(projectPath))
            {
                errors.Add("Packable project was not found for package '" + rule.PackageId + "': " + projectPath + ".");
                return;
            }

            XDocument projectDocument = XDocument.Load(projectPath, LoadOptions.PreserveWhitespace);
            XElement? projectElement = projectDocument.Root;

            if (projectElement == null)
            {
                errors.Add("Packable project could not be read for package '" + rule.PackageId + "': " + projectPath + ".");
                return;
            }

            XNamespace projectNamespace = projectElement.Name.Namespace;
            string? isPackable = GetSinglePropertyValue(projectElement, projectNamespace, "IsPackable");

            if (!StringComparer.OrdinalIgnoreCase.Equals(isPackable, Boolean.TrueString))
            {
                errors.Add("Package-claim validation expected packable project '" + rule.PackageId + "' to set IsPackable=true.");
            }

            string? description = GetSinglePropertyValue(projectElement, projectNamespace, "Description");
            if (!StringComparer.Ordinal.Equals(description, rule.ExpectedDescription))
            {
                errors.Add(
                    "Package '" + rule.PackageId + "' description does not match the validated bounded claim text. " +
                    "Expected '" + rule.ExpectedDescription + "' but found '" + description + "'.");
            }

            string? packageTags = GetSinglePropertyValue(projectElement, projectNamespace, "PackageTags");
            if (String.IsNullOrWhiteSpace(packageTags))
            {
                errors.Add("Package '" + rule.PackageId + "' is missing PackageTags metadata.");
            }
            else
            {
                ValidateRequiredTagTokens(rule, packageTags, errors);
            }

            string? packageReadmeFile = GetSinglePropertyValue(projectElement, projectNamespace, "PackageReadmeFile");
            if (!StringComparer.Ordinal.Equals(packageReadmeFile, "PackageReadme.md"))
            {
                errors.Add("Package '" + rule.PackageId + "' must emit PackageReadme.md as the validated package readme.");
                return;
            }

            string readmePath = Path.Combine(Path.GetDirectoryName(projectPath)!, packageReadmeFile);
            if (!File.Exists(readmePath))
            {
                errors.Add("Package readme was not found for package '" + rule.PackageId + "': " + readmePath + ".");
                return;
            }

            string[] readmeLines = File.ReadAllLines(readmePath);
            string readmeText = String.Join(Environment.NewLine, readmeLines);

            for (int phraseIndex = 0; phraseIndex < rule.RequiredReadmePhrases.Length; phraseIndex++)
            {
                string requiredPhrase = rule.RequiredReadmePhrases[phraseIndex];
                if (readmeText.IndexOf(requiredPhrase, StringComparison.Ordinal) < 0)
                {
                    errors.Add("Package readme for '" + rule.PackageId + "' is missing the required bounded-claim phrase '" + requiredPhrase + "'.");
                }
            }

            if (rule.UnsupportedReadmeTopics.Length == 0)
            {
                return;
            }

            for (int lineIndex = 0; lineIndex < readmeLines.Length; lineIndex++)
            {
                string line = readmeLines[lineIndex];

                for (int topicIndex = 0; topicIndex < rule.UnsupportedReadmeTopics.Length; topicIndex++)
                {
                    string topic = rule.UnsupportedReadmeTopics[topicIndex];

                    if (line.IndexOf(topic, StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        continue;
                    }

                    if (!ContainsAnyDisclaimerMarker(line))
                    {
                        errors.Add(
                            "Package readme for '" + rule.PackageId + "' mentions unsupported topic '" + topic +
                            "' without a backlog or non-claim disclaimer at " + readmePath + ":" + (lineIndex + 1) + ".");
                    }
                }
            }
        }

        private static void ValidateRequiredTagTokens(PackageRule rule, string packageTags, List<string> errors)
        {
            string[] tagTokens = packageTags
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            for (int tagIndex = 0; tagIndex < rule.RequiredTagTokens.Length; tagIndex++)
            {
                string requiredTagToken = rule.RequiredTagTokens[tagIndex];

                if (!tagTokens.Any(tag => StringComparer.OrdinalIgnoreCase.Equals(tag, requiredTagToken)))
                {
                    errors.Add("Package '" + rule.PackageId + "' is missing required tag token '" + requiredTagToken + "'.");
                }
            }
        }

        private static string? GetSinglePropertyValue(XElement projectElement, XNamespace projectNamespace, string propertyName)
        {
            return projectElement
                .Descendants(projectNamespace + propertyName)
                .Select(static element => element.Value.Trim())
                .FirstOrDefault(value => !String.IsNullOrWhiteSpace(value));
        }

        private static bool ContainsAnyDisclaimerMarker(string line)
        {
            for (int markerIndex = 0; markerIndex < _DisclaimerMarkers.Length; markerIndex++)
            {
                if (line.IndexOf(_DisclaimerMarkers[markerIndex], StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private sealed class PackageRule
        {
            internal PackageRule(
                string packageId,
                string relativeProjectPath,
                string expectedDescription,
                string[] requiredTagTokens,
                string[] requiredReadmePhrases,
                string[] unsupportedReadmeTopics)
            {
                PackageId = packageId;
                RelativeProjectPath = relativeProjectPath;
                ExpectedDescription = expectedDescription;
                RequiredTagTokens = requiredTagTokens;
                RequiredReadmePhrases = requiredReadmePhrases;
                UnsupportedReadmeTopics = unsupportedReadmeTopics;
            }

            internal string PackageId { get; }

            internal string RelativeProjectPath { get; }

            internal string ExpectedDescription { get; }

            internal string[] RequiredTagTokens { get; }

            internal string[] RequiredReadmePhrases { get; }

            internal string[] UnsupportedReadmeTopics { get; }
        }
    }
}

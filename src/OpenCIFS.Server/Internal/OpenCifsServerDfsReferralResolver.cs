namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerDfsReferralResolver
    {
        private readonly Dictionary<string, List<OpenCifsServerDfsReferral>> _DfsReferralsByShare;

        public OpenCifsServerDfsReferralResolver(Dictionary<string, List<OpenCifsServerDfsReferral>> dfsReferralsByShare)
        {
            _DfsReferralsByShare = dfsReferralsByShare ?? throw new ArgumentNullException(nameof(dfsReferralsByShare));
        }

        public bool HasReferrals()
        {
            return _DfsReferralsByShare.Count != 0;
        }

        public bool TryMatchReferral(string shareName, string relativePath, out OpenCifsServerDfsReferral[] referrals, out string matchedNamespacePath)
        {
            referrals = Array.Empty<OpenCifsServerDfsReferral>();
            matchedNamespacePath = string.Empty;

            if (!_DfsReferralsByShare.TryGetValue(shareName, out List<OpenCifsServerDfsReferral>? configuredReferrals) || configuredReferrals == null || configuredReferrals.Count == 0)
            {
                return false;
            }

            string normalizedRelativePath = NormalizeRelativePath(relativePath);
            string? bestNamespacePath = null;
            int bestMatchLength = -1;

            for (int index = 0; index < configuredReferrals.Count; index++)
            {
                string candidateNamespacePath = NormalizeRelativePath(configuredReferrals[index].NamespacePath);

                if (!PathFallsUnderNamespace(candidateNamespacePath, normalizedRelativePath))
                {
                    continue;
                }

                if (candidateNamespacePath.Length > bestMatchLength)
                {
                    bestMatchLength = candidateNamespacePath.Length;
                    bestNamespacePath = candidateNamespacePath;
                }
            }

            if (bestNamespacePath == null)
            {
                return false;
            }

            List<OpenCifsServerDfsReferral> matches = configuredReferrals.FindAll(
                referral => StringComparer.OrdinalIgnoreCase.Equals(NormalizeRelativePath(referral.NamespacePath), bestNamespacePath));

            if (matches.Count == 0)
            {
                return false;
            }

            referrals = matches.ToArray();
            matchedNamespacePath = bestNamespacePath;
            return true;
        }

        public bool TryMatchReferralByRequestPath(string requestPath, out DfsReferralMatch? match)
        {
            match = null;
            string normalizedRequestPath = NormalizeRequestPath(requestPath);
            string[] parts = normalizedRequestPath.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2)
            {
                return false;
            }

            string serverName = parts[0];
            string shareName = parts[1];
            string relativePath = parts.Length <= 2 ? string.Empty : string.Join("\\", parts, 2, parts.Length - 2);

            if (!TryMatchReferral(shareName, relativePath, out OpenCifsServerDfsReferral[] referrals, out string matchedNamespacePath))
            {
                return false;
            }

            match = new DfsReferralMatch
            {
                ServerName = serverName,
                ShareName = shareName,
                NamespacePath = matchedNamespacePath,
                Referrals = referrals
            };
            return true;
        }

        public static string ExtractShareName(string path)
        {
            string trimmedPath = path.Trim();

            if (!trimmedPath.StartsWith("\\\\", StringComparison.Ordinal))
            {
                return trimmedPath.Trim('\\');
            }

            string[] parts = trimmedPath.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2)
            {
                return string.Empty;
            }

            return parts[1];
        }

        public static string NormalizeRelativePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path == "/" || path == "\\")
            {
                return string.Empty;
            }

            return path.Trim().Replace('/', '\\').Trim('\\');
        }

        public static string BuildRequestPath(string serverName, string shareName, string? relativePath = null)
        {
            if (string.IsNullOrWhiteSpace(serverName))
            {
                throw new ArgumentNullException(nameof(serverName), "ServerName cannot be null or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            string normalizedServerName = serverName.Trim().Trim('\\');
            string normalizedShareName = shareName.Trim().Trim('\\');
            string normalizedRelativePath = NormalizeRelativePath(relativePath ?? string.Empty);
            return string.IsNullOrEmpty(normalizedRelativePath)
                ? "\\" + normalizedServerName + "\\" + normalizedShareName
                : "\\" + normalizedServerName + "\\" + normalizedShareName + "\\" + normalizedRelativePath;
        }

        private static bool PathFallsUnderNamespace(string namespacePath, string relativePath)
        {
            if (string.IsNullOrEmpty(namespacePath))
            {
                return true;
            }

            if (string.Equals(namespacePath, relativePath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return relativePath.StartsWith(namespacePath + "\\", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeRequestPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ProtocolEncodingException("The DFS request path cannot be empty.");
            }

            string normalizedPath = path.Trim().Replace('/', '\\');

            while (normalizedPath.StartsWith("\\\\", StringComparison.Ordinal))
            {
                normalizedPath = normalizedPath.Substring(1);
            }

            normalizedPath = "\\" + normalizedPath.Trim('\\');

            while (normalizedPath.Contains("\\\\", StringComparison.Ordinal))
            {
                normalizedPath = normalizedPath.Replace("\\\\", "\\", StringComparison.Ordinal);
            }

            return normalizedPath;
        }
    }
}

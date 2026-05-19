namespace OpenCIFS.TestClient
{
    using System;
    using System.Collections.Generic;

    internal static class TestClientPathUtilities
    {
        internal static string NormalizeRemotePath(string currentRemotePath, string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return currentRemotePath;
            }

            string candidatePath = path.Replace('\\', '/');
            bool isAbsolute = candidatePath.StartsWith("/", StringComparison.Ordinal);
            List<string> segments = new List<string>();

            if (!isAbsolute)
            {
                AddSegments(segments, currentRemotePath);
            }

            AddSegments(segments, candidatePath);
            return BuildRemotePath(segments);
        }

        internal static string CombineRemotePath(string basePath, string childName)
        {
            List<string> segments = new List<string>();
            AddSegments(segments, basePath);
            AddSegments(segments, childName);
            return BuildRemotePath(segments);
        }

        internal static string GetDisplayRemotePath(string path)
        {
            return string.IsNullOrWhiteSpace(path) ? "/" : path;
        }

        internal static bool ContainsWildcard(string value)
        {
            return value.Contains('*') || value.Contains('?');
        }

        private static void AddSegments(List<string> segments, string path)
        {
            string[] pathSegments = path.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            for (int index = 0; index < pathSegments.Length; index++)
            {
                string segment = pathSegments[index];

                if (segment == ".")
                {
                    continue;
                }

                if (segment == "..")
                {
                    if (segments.Count > 0)
                    {
                        segments.RemoveAt(segments.Count - 1);
                    }

                    continue;
                }

                segments.Add(segment);
            }
        }

        private static string BuildRemotePath(List<string> segments)
        {
            if (segments.Count == 0)
            {
                return "/";
            }

            return "/" + string.Join("/", segments);
        }
    }
}

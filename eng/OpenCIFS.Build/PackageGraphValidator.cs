namespace OpenCIFS.Build
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Xml.Linq;

    /// <summary>
    /// Validates that packable projects do not depend on non-packable project references.
    /// </summary>
    internal static class PackageGraphValidator
    {
        /// <summary>
        /// Validate the packable project-reference graph rooted at the provided source directory.
        /// </summary>
        /// <param name="sourceRootPath">Source-root path that contains the project files.</param>
        /// <returns>Validation errors.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="sourceRootPath" /> is null or whitespace.</exception>
        internal static IReadOnlyList<string> Validate(string sourceRootPath)
        {
            if (String.IsNullOrWhiteSpace(sourceRootPath))
            {
                throw new ArgumentNullException(nameof(sourceRootPath), "Source root path cannot be null or whitespace.");
            }

            List<string> errors = new List<string>();
            string fullSourceRootPath = Path.GetFullPath(sourceRootPath);

            if (!Directory.Exists(fullSourceRootPath))
            {
                errors.Add("Source root directory was not found: " + fullSourceRootPath + ".");
                return errors;
            }

            string[] projectPaths = Directory.GetFiles(fullSourceRootPath, "*.csproj", SearchOption.AllDirectories);
            Dictionary<string, ProjectMetadata> projectMetadataByPath = new Dictionary<string, ProjectMetadata>(StringComparer.OrdinalIgnoreCase);

            for (int projectIndex = 0; projectIndex < projectPaths.Length; projectIndex++)
            {
                string projectPath = Path.GetFullPath(projectPaths[projectIndex]);
                projectMetadataByPath[projectPath] = LoadProjectMetadata(projectPath);
            }

            foreach (ProjectMetadata projectMetadata in projectMetadataByPath.Values.Where(static metadata => metadata.IsPackable))
            {
                for (int referenceIndex = 0; referenceIndex < projectMetadata.ProjectReferencePaths.Count; referenceIndex++)
                {
                    string projectReferencePath = projectMetadata.ProjectReferencePaths[referenceIndex];

                    if (!projectMetadataByPath.TryGetValue(projectReferencePath, out ProjectMetadata? referencedProjectMetadata))
                    {
                        errors.Add(
                            "Packable project '" + projectMetadata.ProjectName + "' references a project that was not found: " +
                            projectReferencePath + ".");
                        continue;
                    }

                    if (!referencedProjectMetadata.IsPackable)
                    {
                        errors.Add(
                            "Packable project '" + projectMetadata.ProjectName + "' references non-packable project '" +
                            referencedProjectMetadata.ProjectName + "'.");
                    }
                }
            }

            return errors;
        }

        private static ProjectMetadata LoadProjectMetadata(string projectPath)
        {
            XDocument projectDocument = XDocument.Load(projectPath, LoadOptions.PreserveWhitespace);
            XElement? projectElement = projectDocument.Root;

            if (projectElement == null)
            {
                return new ProjectMetadata(Path.GetFileNameWithoutExtension(projectPath), projectPath, isPackable: false, Array.Empty<string>());
            }

            XNamespace projectNamespace = projectElement.Name.Namespace;
            bool isPackable = projectElement
                .Descendants(projectNamespace + "IsPackable")
                .Select(static element => element.Value.Trim())
                .Any(static value => StringComparer.OrdinalIgnoreCase.Equals(value, Boolean.TrueString));

            List<string> projectReferencePaths = new List<string>();
            IEnumerable<XElement> projectReferenceElements = projectElement.Descendants(projectNamespace + "ProjectReference");

            foreach (XElement projectReferenceElement in projectReferenceElements)
            {
                XAttribute? includeAttribute = projectReferenceElement.Attribute("Include");

                if (includeAttribute == null || String.IsNullOrWhiteSpace(includeAttribute.Value))
                {
                    continue;
                }

                string referencedProjectPath = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(projectPath)!, includeAttribute.Value));
                projectReferencePaths.Add(referencedProjectPath);
            }

            return new ProjectMetadata(Path.GetFileNameWithoutExtension(projectPath), projectPath, isPackable, projectReferencePaths);
        }

        private sealed class ProjectMetadata
        {
            internal ProjectMetadata(string projectName, string projectPath, bool isPackable, IReadOnlyList<string> projectReferencePaths)
            {
                ProjectName = projectName;
                ProjectPath = projectPath;
                IsPackable = isPackable;
                ProjectReferencePaths = projectReferencePaths;
            }

            internal string ProjectName { get; }

            internal string ProjectPath { get; }

            internal bool IsPackable { get; }

            internal IReadOnlyList<string> ProjectReferencePaths { get; }
        }
    }
}

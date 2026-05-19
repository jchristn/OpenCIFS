namespace OpenCIFS.Client
{
    using System;

    internal sealed class OpenCifsResolvedTreeAcquisition
    {
        public OpenCifsResolvedTreeAcquisition(OpenCifsClientTreeHandle treeHandle, bool ownsTree)
        {
            TreeHandle = treeHandle ?? throw new ArgumentNullException(nameof(treeHandle));
            OwnsTree = ownsTree;
        }

        public OpenCifsClientTreeHandle TreeHandle { get; }

        public bool OwnsTree { get; }
    }
}

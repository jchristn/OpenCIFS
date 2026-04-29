namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Marks a bounded public surface as preview-only until the broader client capability matrix is complete.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Interface | AttributeTargets.Method | AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
    public sealed class OpenCifsPreviewAttribute : Attribute
    {
        /// <summary>
        /// Initialize the preview marker.
        /// </summary>
        /// <param name="message">Preview guidance for consumers.</param>
        public OpenCifsPreviewAttribute(string message)
        {
            if (String.IsNullOrWhiteSpace(message))
            {
                throw new ArgumentException("Preview message cannot be null or whitespace.", nameof(message));
            }

            Message = message;
        }

        /// <summary>
        /// Preview guidance for consumers.
        /// </summary>
        public string Message { get; }
    }
}

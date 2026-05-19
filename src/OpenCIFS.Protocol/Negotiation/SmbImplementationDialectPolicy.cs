namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Shared policy for the highest currently implemented SMB dialect surface.
    /// </summary>
    internal static class SmbImplementationDialectPolicy
    {
        /// <summary>
        /// Get the effective highest implemented dialect for the current preview posture.
        /// </summary>
        /// <param name="enableSmb311Preview">Whether the bounded SMB 3.1.1 preview is enabled.</param>
        /// <returns>Highest implemented dialect.</returns>
        internal static SmbDialect GetMaximumImplementedDialect(bool enableSmb311Preview)
        {
            return enableSmb311Preview ? SmbDialect.Smb311 : SmbDialect.Smb302;
        }

        /// <summary>
        /// Validate that the configured minimum dialect does not exceed the implemented ceiling for the current preview posture.
        /// </summary>
        /// <param name="minimumDialect">Configured minimum dialect.</param>
        /// <param name="enableSmb311Preview">Whether the bounded SMB 3.1.1 preview is enabled.</param>
        /// <param name="parameterName">Parameter name to report on failure.</param>
        internal static void ValidatePreviewDialectFloor(SmbDialect minimumDialect, bool enableSmb311Preview, string parameterName)
        {
            if (minimumDialect > GetMaximumImplementedDialect(enableSmb311Preview))
            {
                throw new ArgumentException("MinimumDialect cannot exceed SMB 3.0.2 when EnableSmb311Preview is false.", parameterName);
            }
        }
    }
}

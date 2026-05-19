namespace OpenCIFS.Server.Tests.Shared
{
    using System;

    internal sealed class SampleProgramExecutionResult
    {
        public SampleProgramExecutionResult(int exitCode, string standardOutput, string standardError)
        {
            ExitCode = exitCode;
            StandardOutput = standardOutput ?? throw new ArgumentNullException(nameof(standardOutput));
            StandardError = standardError ?? throw new ArgumentNullException(nameof(standardError));
        }

        public int ExitCode { get; }

        public string StandardOutput { get; }

        public string StandardError { get; }
    }
}

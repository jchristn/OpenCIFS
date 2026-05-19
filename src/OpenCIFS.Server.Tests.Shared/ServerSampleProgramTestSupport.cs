namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.IO;
    using Sample.OpenCifsServer;

    internal static class ServerSampleProgramTestSupport
    {
        private static readonly object ConsoleCaptureLock = new object();

        internal static SampleProgramExecutionResult RunSampleProgram(params string[] args)
        {
            lock (ConsoleCaptureLock)
            {
                TextWriter originalOut = Console.Out;
                TextWriter originalError = Console.Error;
                using StringWriter capturedOut = new StringWriter();
                using StringWriter capturedError = new StringWriter();

                try
                {
                    Console.SetOut(capturedOut);
                    Console.SetError(capturedError);
                    int exitCode = Program.Main(args);
                    return new SampleProgramExecutionResult(exitCode, capturedOut.ToString(), capturedError.ToString());
                }
                finally
                {
                    Console.SetOut(originalOut);
                    Console.SetError(originalError);
                }
            }
        }
    }
}

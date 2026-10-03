namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Threading;

    /// <summary>
    /// Cross-process, non-thread-affine binary lock used to serialize direct-TCP test port reservation across test hosts.
    /// </summary>
    /// <remarks>
    /// Windows uses a named <see cref="Semaphore" />. Named semaphores are not supported on Linux or macOS, so other
    /// platforms hold an exclusive lock file in the temporary directory instead. Both forms may be released from a
    /// different thread than the one that acquired them, which the reservation flow requires because it spans awaits.
    /// </remarks>
    internal sealed class CrossProcessTestLock : IDisposable
    {
        internal CrossProcessTestLock(string name)
        {
            if (String.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentNullException(nameof(name), "Lock name cannot be null or whitespace.");
            }

            if (OperatingSystem.IsWindows())
            {
                _Semaphore = new Semaphore(initialCount: 1, maximumCount: 1, name: name);
            }
            else
            {
                _LockFilePath = Path.Combine(Path.GetTempPath(), name + ".lock");
            }
        }

        internal bool WaitOne(TimeSpan timeout)
        {
            if (_Semaphore != null)
            {
                return _Semaphore.WaitOne(timeout);
            }

            Stopwatch stopwatch = Stopwatch.StartNew();

            while (true)
            {
                try
                {
                    _LockFile = new FileStream(_LockFilePath!, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                    return true;
                }
                catch (IOException) when (stopwatch.Elapsed < timeout)
                {
                    Thread.Sleep(25);
                }
                catch (IOException)
                {
                    return false;
                }
            }
        }

        internal void Release()
        {
            if (_Semaphore != null)
            {
                _Semaphore.Release();
                return;
            }

            FileStream? lockFile = _LockFile;
            _LockFile = null;
            lockFile?.Dispose();
        }

        public void Dispose()
        {
            _Semaphore?.Dispose();
            _LockFile?.Dispose();
            _LockFile = null;
        }

        private readonly Semaphore? _Semaphore;
        private readonly string? _LockFilePath;
        private FileStream? _LockFile;
    }
}

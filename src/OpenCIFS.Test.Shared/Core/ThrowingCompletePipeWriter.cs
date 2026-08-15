namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.IO;
    using System.IO.Pipelines;
    using System.Threading;
    using System.Threading.Tasks;

    internal sealed class ThrowingCompletePipeWriter : PipeWriter
    {
        private readonly PipeWriter _InnerWriter;

        public ThrowingCompletePipeWriter(PipeWriter innerWriter)
        {
            _InnerWriter = innerWriter ?? throw new ArgumentNullException(nameof(innerWriter));
        }

        public override void Advance(int bytes)
        {
            _InnerWriter.Advance(bytes);
        }

        public override void CancelPendingFlush()
        {
            _InnerWriter.CancelPendingFlush();
        }

        public override void Complete(Exception? exception = null)
        {
            throw new IOException("Simulated writer completion fault during expected cancellation.");
        }

        public override ValueTask CompleteAsync(Exception? exception = null)
        {
            return ValueTask.FromException(new IOException("Simulated writer completion fault during expected cancellation."));
        }

        public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
        {
            return _InnerWriter.FlushAsync(cancellationToken);
        }

        public override Memory<byte> GetMemory(int sizeHint = 0)
        {
            return _InnerWriter.GetMemory(sizeHint);
        }

        public override Span<byte> GetSpan(int sizeHint = 0)
        {
            return _InnerWriter.GetSpan(sizeHint);
        }
    }
}
namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.IO;
    using System.IO.Pipelines;
    using System.Threading;
    using System.Threading.Tasks;

    internal sealed class ThrowingCompletePipeReader : PipeReader
    {
        private readonly PipeReader _InnerReader;

        public ThrowingCompletePipeReader(PipeReader innerReader)
        {
            _InnerReader = innerReader ?? throw new ArgumentNullException(nameof(innerReader));
        }

        public override void AdvanceTo(SequencePosition consumed)
        {
            _InnerReader.AdvanceTo(consumed);
        }

        public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
        {
            _InnerReader.AdvanceTo(consumed, examined);
        }

        public override void CancelPendingRead()
        {
            _InnerReader.CancelPendingRead();
        }

        public override void Complete(Exception? exception = null)
        {
            throw new IOException("Simulated reader completion fault during expected cancellation.");
        }

        public override ValueTask CompleteAsync(Exception? exception = null)
        {
            return ValueTask.FromException(new IOException("Simulated reader completion fault during expected cancellation."));
        }

        public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
        {
            return _InnerReader.ReadAsync(cancellationToken);
        }

        public override bool TryRead(out ReadResult result)
        {
            return _InnerReader.TryRead(out result);
        }
    }
}
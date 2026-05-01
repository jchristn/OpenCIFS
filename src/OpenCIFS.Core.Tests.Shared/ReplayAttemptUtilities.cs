namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Deterministic helpers for building bounded SMB request replay attempts.
    /// </summary>
    /// <remarks>
    /// SMB2 replay defense is implicit: each accepted request consumes a one-shot message identifier from the
    /// negotiated credit window, so re-sending the exact same signed bytes must surface as an out-of-window
    /// message-id rejection on the server. These helpers preserve a captured signed request and return replay
    /// copies suitable for verifying that rejection in shared-suite tests.
    /// </remarks>
    public static class ReplayAttemptUtilities
    {
        /// <summary>
        /// Capture a signed-request payload and return a deterministic replay copy.
        /// </summary>
        /// <param name="signedRequestBytes">Bytes of the signed SMB2 request to replay.</param>
        /// <returns>Replay-attempt copy of the signed request bytes.</returns>
        public static byte[] CreateReplayCopy(byte[] signedRequestBytes)
        {
            if (signedRequestBytes == null)
            {
                throw new ArgumentNullException(nameof(signedRequestBytes), "SignedRequestBytes cannot be null.");
            }

            byte[] replayCopy = new byte[signedRequestBytes.Length];
            Buffer.BlockCopy(signedRequestBytes, 0, replayCopy, 0, signedRequestBytes.Length);
            return replayCopy;
        }

        /// <summary>
        /// Build a deterministic burst of replay copies for the same signed request.
        /// </summary>
        /// <param name="signedRequestBytes">Bytes of the signed SMB2 request to replay.</param>
        /// <param name="replayCount">Number of replay copies to produce.</param>
        /// <returns>Replay-attempt corpus.</returns>
        public static IReadOnlyList<byte[]> CreateReplayBurst(byte[] signedRequestBytes, int replayCount)
        {
            if (replayCount <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(replayCount), "ReplayCount must be positive.");
            }

            byte[][] burst = new byte[replayCount][];

            for (int index = 0; index < replayCount; index++)
            {
                burst[index] = CreateReplayCopy(signedRequestBytes);
            }

            return burst;
        }
    }
}

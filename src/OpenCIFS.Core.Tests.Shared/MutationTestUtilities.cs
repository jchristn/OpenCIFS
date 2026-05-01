namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Shared deterministic mutation helpers for malformed-input and parser-robustness coverage.
    /// </summary>
    public static class MutationTestUtilities
    {
        /// <summary>
        /// Build a deterministic mutation corpus from a valid baseline payload.
        /// </summary>
        /// <param name="baseline">Baseline bytes.</param>
        /// <param name="randomSeed">Deterministic random seed.</param>
        /// <param name="randomCount">Number of random mutations to append after the fixed corpus.</param>
        /// <returns>Unique mutated payloads.</returns>
        public static IReadOnlyList<byte[]> CreateDeterministicMutationCorpus(
            ReadOnlySpan<byte> baseline,
            int randomSeed = 0x43494653,
            int randomCount = 64)
        {
            if (baseline.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(baseline), "A mutation baseline must not be empty.");
            }

            if (randomCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(randomCount), "Random mutation count must be non-negative.");
            }

            List<byte[]> mutations = new List<byte[]>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            byte[] baselineArray = baseline.ToArray();

            void AddCandidate(byte[] candidate)
            {
                if (candidate.AsSpan().SequenceEqual(baselineArray))
                {
                    return;
                }

                string key = Convert.ToHexString(candidate);

                if (seen.Add(key))
                {
                    mutations.Add(candidate);
                }
            }

            int[] representativeIndices = GetRepresentativeIndices(baseline.Length);

            for (int length = 0; length < Math.Min(baseline.Length, 8); length++)
            {
                AddCandidate(baseline.Slice(0, length).ToArray());
            }

            if (baseline.Length > 1)
            {
                AddCandidate(baseline.Slice(0, baseline.Length - 1).ToArray());
                AddCandidate(baseline.Slice(0, Math.Max(1, baseline.Length / 2)).ToArray());
            }

            byte[] xorMasks = new byte[] { 0x01, 0x7F, 0x80, 0xFF };

            for (int index = 0; index < representativeIndices.Length; index++)
            {
                int representativeIndex = representativeIndices[index];

                for (int maskIndex = 0; maskIndex < xorMasks.Length; maskIndex++)
                {
                    byte[] mutated = (byte[])baselineArray.Clone();
                    mutated[representativeIndex] ^= xorMasks[maskIndex];
                    AddCandidate(mutated);
                }

                byte[] zeroed = (byte[])baselineArray.Clone();
                zeroed[representativeIndex] = 0;
                AddCandidate(zeroed);

                if (representativeIndex + 1 < zeroed.Length)
                {
                    byte[] runZeroed = (byte[])baselineArray.Clone();
                    runZeroed[representativeIndex] = 0;
                    runZeroed[representativeIndex + 1] = 0;
                    AddCandidate(runZeroed);
                }
            }

            Random random = new Random(unchecked(randomSeed ^ baseline.Length));
            int maximumRandomLength = Math.Max(1, Math.Min(256, baseline.Length + 8));

            for (int iteration = 0; iteration < randomCount; iteration++)
            {
                byte[] mutated = (byte[])baselineArray.Clone();
                int flipCount = 1 + random.Next(4);

                for (int flipIndex = 0; flipIndex < flipCount; flipIndex++)
                {
                    int targetIndex = random.Next(mutated.Length);
                    mutated[targetIndex] = (byte)random.Next(256);
                }

                AddCandidate(mutated);

                int randomLength = random.Next(maximumRandomLength);
                byte[] randomPayload = new byte[randomLength];
                random.NextBytes(randomPayload);
                AddCandidate(randomPayload);
            }

            return mutations;
        }

        /// <summary>
        /// Execute a mutation corpus against a parser or validator action and require that only expected malformed-input exceptions escape.
        /// </summary>
        /// <param name="corpusName">Corpus name for diagnostics.</param>
        /// <param name="mutations">Mutated payloads.</param>
        /// <param name="action">Mutation action.</param>
        /// <param name="isExpectedException">Expected exception predicate.</param>
        /// <returns>Outcome summary.</returns>
        public static MutationOutcomeSummary ExecuteMutationCorpus(
            string corpusName,
            IReadOnlyList<byte[]> mutations,
            Action<byte[]> action,
            Func<Exception, bool> isExpectedException)
        {
            if (String.IsNullOrWhiteSpace(corpusName))
            {
                throw new ArgumentNullException(nameof(corpusName), "Corpus name cannot be null or whitespace.");
            }

            if (mutations == null)
            {
                throw new ArgumentNullException(nameof(mutations), "Mutations cannot be null.");
            }

            if (action == null)
            {
                throw new ArgumentNullException(nameof(action), "Action cannot be null.");
            }

            if (isExpectedException == null)
            {
                throw new ArgumentNullException(nameof(isExpectedException), "Expected-exception predicate cannot be null.");
            }

            int acceptedCount = 0;
            int rejectedCount = 0;

            for (int index = 0; index < mutations.Count; index++)
            {
                byte[] mutation = mutations[index];

                try
                {
                    action(mutation);
                    acceptedCount++;
                }
                catch (Exception exception) when (isExpectedException(exception))
                {
                    rejectedCount++;
                }
                catch (Exception exception)
                {
                    throw new InvalidOperationException(
                        "Mutation corpus '" + corpusName + "' produced an unexpected " + exception.GetType().FullName +
                        " at mutation index " + index + " with payload length " + mutation.Length + ".",
                        exception);
                }
            }

            return new MutationOutcomeSummary(corpusName, mutations.Count, acceptedCount, rejectedCount);
        }

        /// <summary>
        /// Determine whether an exception is an expected malformed-input failure for bounded protocol mutation coverage.
        /// </summary>
        /// <param name="exception">Exception to classify.</param>
        /// <returns><c>true</c> when the exception is expected.</returns>
        public static bool IsExpectedMalformedInputException(Exception exception)
        {
            return exception is ProtocolEncodingException ||
                   exception is ProtocolValidationException ||
                   exception is ArgumentException ||
                   exception is InvalidOperationException ||
                   exception is FormatException ||
                   exception is OverflowException ||
                   exception is NotSupportedException;
        }

        private static int[] GetRepresentativeIndices(int length)
        {
            HashSet<int> indices = new HashSet<int>();

            void AddIndex(int index)
            {
                if (index >= 0 && index < length)
                {
                    indices.Add(index);
                }
            }

            AddIndex(0);
            AddIndex(1);
            AddIndex(2);
            AddIndex(length / 4);
            AddIndex(length / 2);
            AddIndex((length * 3) / 4);
            AddIndex(length - 2);
            AddIndex(length - 1);

            int[] representativeIndices = new int[indices.Count];
            indices.CopyTo(representativeIndices);
            Array.Sort(representativeIndices);
            return representativeIndices;
        }
    }

    /// <summary>
    /// Summary of a bounded mutation-corpus execution.
    /// </summary>
    public readonly struct MutationOutcomeSummary
    {
        /// <summary>
        /// Initialize the summary.
        /// </summary>
        /// <param name="corpusName">Corpus name.</param>
        /// <param name="totalCount">Total mutation count.</param>
        /// <param name="acceptedCount">Accepted mutation count.</param>
        /// <param name="rejectedCount">Rejected mutation count.</param>
        public MutationOutcomeSummary(string corpusName, int totalCount, int acceptedCount, int rejectedCount)
        {
            CorpusName = corpusName ?? throw new ArgumentNullException(nameof(corpusName), "Corpus name cannot be null.");
            TotalCount = totalCount;
            AcceptedCount = acceptedCount;
            RejectedCount = rejectedCount;
        }

        /// <summary>
        /// Corpus name.
        /// </summary>
        public string CorpusName { get; }

        /// <summary>
        /// Total executed mutations.
        /// </summary>
        public int TotalCount { get; }

        /// <summary>
        /// Accepted mutation count.
        /// </summary>
        public int AcceptedCount { get; }

        /// <summary>
        /// Expected rejection count.
        /// </summary>
        public int RejectedCount { get; }
    }
}

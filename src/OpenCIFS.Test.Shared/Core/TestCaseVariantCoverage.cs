namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using Touchstone.Core;

    /// <summary>
    /// Audits shared Touchstone suites for balanced positive and negative coverage.
    /// </summary>
    public static class TestCaseVariantCoverage
    {
        /// <summary>
        /// Assert that every suite exposes at least one positive and one negative case,
        /// and that every case can be classified into a variant.
        /// </summary>
        /// <param name="suites">Suites to audit.</param>
        /// <param name="owner">Owning test assembly label for diagnostics.</param>
        public static void AssertBalancedVariants(IReadOnlyList<TestSuiteDescriptor> suites, string owner)
        {
            if (suites == null)
            {
                throw new ArgumentNullException(nameof(suites), "Suites cannot be null.");
            }

            if (String.IsNullOrWhiteSpace(owner))
            {
                throw new ArgumentNullException(nameof(owner), "Owner cannot be null or whitespace.");
            }

            for (int suiteIndex = 0; suiteIndex < suites.Count; suiteIndex++)
            {
                TestSuiteDescriptor suite = suites[suiteIndex];
                bool hasPositive = false;
                bool hasNegative = false;

                if (suite.Cases.Count == 0)
                {
                    throw new InvalidOperationException(owner + " suite " + suite.SuiteId + " must not be empty.");
                }

                for (int caseIndex = 0; caseIndex < suite.Cases.Count; caseIndex++)
                {
                    TestCaseDescriptor descriptor = suite.Cases[caseIndex];
                    TestCaseVariantKind variant = Classify(descriptor);

                    if (variant == TestCaseVariantKind.None)
                    {
                        throw new InvalidOperationException(
                            owner + " test case " + descriptor.TestId + " is missing an explicit positive or negative variant signal.");
                    }

                    hasPositive |= (variant & TestCaseVariantKind.Positive) != 0;
                    hasNegative |= (variant & TestCaseVariantKind.Negative) != 0;
                }

                if (!hasPositive || !hasNegative)
                {
                    throw new InvalidOperationException(
                        owner + " suite " + suite.SuiteId + " must expose both positive and negative variants.");
                }
            }
        }

        private static TestCaseVariantKind Classify(TestCaseDescriptor descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor), "Descriptor cannot be null.");
            }

            if (_Overrides.TryGetValue(descriptor.CaseId, out TestCaseVariantKind variant))
            {
                return variant;
            }

            return ClassifyText(descriptor.CaseId) | ClassifyText(descriptor.DisplayName);
        }

        private static TestCaseVariantKind ClassifyText(string text)
        {
            if (String.IsNullOrWhiteSpace(text))
            {
                return TestCaseVariantKind.None;
            }

            TestCaseVariantKind variant = TestCaseVariantKind.None;

            if (ContainsAny(text, _PositiveTokens))
            {
                variant |= TestCaseVariantKind.Positive;
            }

            if (ContainsAny(text, _NegativeTokens))
            {
                variant |= TestCaseVariantKind.Negative;
            }

            return variant;
        }

        private static bool ContainsAny(string value, IReadOnlyList<string> tokens)
        {
            for (int index = 0; index < tokens.Count; index++)
            {
                if (value.Contains(tokens[index], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static readonly IReadOnlyList<string> _PositiveTokens = new[]
        {
            "Accept",
            "Advertis",
            "Allow",
            "Appl",
            "Authenticat",
            "Bind",
            "Build",
            "Clamp",
            "Complete",
            "Connect",
            "Create",
            "Default",
            "Encod",
            "Enumerat",
            "Exist",
            "Expose",
            "Parse",
            "Follow",
            "Grant",
            "Handle",
            "Honor",
            "Include",
            "Lifecycle",
            "Maintain",
            "Match",
            "Mutat",
            "Negotiat",
            "Preserve",
            "Present",
            "Queri",
            "Query",
            "Read",
            "Remain",
            "Rename",
            "Report",
            "Resolve",
            "Respect",
            "Return",
            "RoundTrip",
            "Supersede",
            "Secure",
            "Stable",
            "Track",
            "Transfer",
            "Transceive",
            "Overwrite"
        };

        private static readonly IReadOnlyList<string> _NegativeTokens = new[]
        {
            "Block",
            "Cancel",
            "Cancelled",
            "Cannot",
            "Closed",
            "Collision",
            "Conflict",
            "DeletePending",
            "Denied",
            "DoesNot",
            "Escape",
            "Fail",
            "Invalid",
            "Malformed",
            "Mismatch",
            "Missing",
            "NoSuch",
            "NotClaim",
            "Null",
            "Overflow",
            "Reject",
            "Stale",
            "Tampering",
            "Truncated",
            "Unexpected",
            "Unknown",
            "Unsupported",
            "Wrong"
        };

        private static readonly IReadOnlyDictionary<string, TestCaseVariantKind> _Overrides =
            new Dictionary<string, TestCaseVariantKind>(StringComparer.Ordinal)
            {
                { "ClientCreatesCancelHeadersWithoutConsumingCredits", TestCaseVariantKind.Positive },
                { "ServerReturnsInterimPendingAndCancelsAsyncChangeNotifyRequests", TestCaseVariantKind.Positive | TestCaseVariantKind.Negative }
            };
    }

    /// <summary>
    /// Variant flags for shared Touchstone cases.
    /// </summary>
    [Flags]
    public enum TestCaseVariantKind
    {
        /// <summary>
        /// No variant classification.
        /// </summary>
        None = 0,

        /// <summary>
        /// Positive success-path coverage.
        /// </summary>
        Positive = 1,

        /// <summary>
        /// Negative rejection or failure-path coverage.
        /// </summary>
        Negative = 2
    }
}

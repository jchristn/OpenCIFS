namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    /// <summary>
    /// Minimal assertion helpers shared across Touchstone test assemblies.
    /// </summary>
    public static class TestAssertions
    {
        /// <summary>
        /// Assert that a condition is true.
        /// </summary>
        /// <param name="condition">Condition to evaluate.</param>
        /// <param name="message">Failure message.</param>
        public static void True(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        /// <summary>
        /// Assert that a condition is false.
        /// </summary>
        /// <param name="condition">Condition to evaluate.</param>
        /// <param name="message">Failure message.</param>
        public static void False(bool condition, string message)
        {
            True(!condition, message);
        }

        /// <summary>
        /// Assert that two values are equal.
        /// </summary>
        /// <typeparam name="T">Value type.</typeparam>
        /// <param name="expected">Expected value.</param>
        /// <param name="actual">Actual value.</param>
        /// <param name="message">Failure message.</param>
        public static void Equal<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(message + " Expected: " + expected + ". Actual: " + actual + ".");
            }
        }

        /// <summary>
        /// Assert that two byte sequences are equal.
        /// </summary>
        /// <param name="expected">Expected bytes.</param>
        /// <param name="actual">Actual bytes.</param>
        /// <param name="message">Failure message.</param>
        public static void SequenceEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string message)
        {
            if (!expected.SequenceEqual(actual))
            {
                throw new InvalidOperationException(message);
            }
        }

        /// <summary>
        /// Assert that an action throws the expected exception type.
        /// </summary>
        /// <typeparam name="TException">Expected exception type.</typeparam>
        /// <param name="action">Action to execute.</param>
        /// <param name="message">Failure message.</param>
        public static void Throws<TException>(Action action, string message)
            where TException : Exception
        {
            try
            {
                action();
            }
            catch (TException)
            {
                return;
            }

            throw new InvalidOperationException(message + " Expected exception: " + typeof(TException).FullName + ".");
        }

        /// <summary>
        /// Assert that an asynchronous action throws the expected exception type.
        /// </summary>
        /// <typeparam name="TException">Expected exception type.</typeparam>
        /// <param name="action">Asynchronous action to execute.</param>
        /// <param name="message">Failure message.</param>
        /// <returns>A task that completes when the assertion finishes.</returns>
        public static async Task ThrowsAsync<TException>(Func<Task> action, string message)
            where TException : Exception
        {
            try
            {
                await action().ConfigureAwait(false);
            }
            catch (TException)
            {
                return;
            }

            throw new InvalidOperationException(message + " Expected exception: " + typeof(TException).FullName + ".");
        }
    }
}

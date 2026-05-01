namespace OpenCIFS.Client
{
    using System;
    using System.Threading.Tasks;

    internal static class OpenCifsClientResultFactory
    {
        internal static async Task<OpenCifsClientResult> TryAsync(Func<Task> action)
        {
            try
            {
                await action().ConfigureAwait(false);
                return OpenCifsClientResult.Success();
            }
            catch (ObjectDisposedException exception)
            {
                return OpenCifsClientResult.Failure(new OpenCifsClientStateException(exception.Message, exception));
            }
            catch (OpenCifsClientException exception)
            {
                return OpenCifsClientResult.Failure(exception);
            }
        }

        internal static async Task<OpenCifsClientResult<T>> TryAsync<T>(Func<Task<T>> action)
        {
            try
            {
                T value = await action().ConfigureAwait(false);
                return OpenCifsClientResult<T>.Success(value);
            }
            catch (ObjectDisposedException exception)
            {
                return OpenCifsClientResult<T>.Failure(new OpenCifsClientStateException(exception.Message, exception));
            }
            catch (OpenCifsClientException exception)
            {
                return OpenCifsClientResult<T>.Failure(exception);
            }
        }
    }
}

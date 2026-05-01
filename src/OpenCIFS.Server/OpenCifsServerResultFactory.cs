namespace OpenCIFS.Server
{
    using System;
    using System.Threading.Tasks;

    internal static class OpenCifsServerResultFactory
    {
        internal static async Task<OpenCifsServerResult> TryAsync(Func<Task> action)
        {
            try
            {
                await action().ConfigureAwait(false);
                return OpenCifsServerResult.Success();
            }
            catch (ObjectDisposedException exception)
            {
                return OpenCifsServerResult.Failure(new OpenCifsServerStateException(exception.Message, exception));
            }
            catch (OpenCifsServerException exception)
            {
                return OpenCifsServerResult.Failure(exception);
            }
        }
    }
}

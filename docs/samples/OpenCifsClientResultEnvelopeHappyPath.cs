using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OpenCIFS.Client;
using OpenCIFS.Protocol;

internal static class OpenCifsClientResultEnvelopeSample
{
    public static async Task RunAsync(CancellationToken cancellationToken = default)
    {
        OpenCifsClientCredential credential = new OpenCifsClientCredential
        {
            UserName = "alice",
            UserDomain = "CONTOSO",
            Password = "Password123!"
        };

        await using OpenCifsClient client = new OpenCifsClientBuilder()
            .WithServer("fileserver.contoso.local", 445)
            .Build();

        OpenCifsClientResult connectResult = await client.TryConnectAsync(credential, cancellationToken).ConfigureAwait(false);
        connectResult.EnsureSuccess();

        OpenCifsClientResult<OpenCifsShareSession> shareResult = await client.TryOpenShareAsync("share", cancellationToken).ConfigureAwait(false);
        await using OpenCifsShareSession share = shareResult.GetValueOrThrow();

        OpenCifsClientResult createResult = await share.Directories.TryCreateAsync("/docs", cancellationToken).ConfigureAwait(false);
        createResult.EnsureSuccess();

        OpenCifsClientResult writeResult = await share.Files.TryWriteAllBytesAsync(
            "/docs/hello.txt",
            Encoding.UTF8.GetBytes("hello from OpenCIFS"),
            cancellationToken).ConfigureAwait(false);
        writeResult.EnsureSuccess();

        OpenCifsClientResult<byte[]> readResult = await share.Files.TryReadAllBytesAsync("/docs/hello.txt", cancellationToken).ConfigureAwait(false);
        if (readResult.IsSuccess)
        {
            Console.WriteLine(Encoding.UTF8.GetString(readResult.GetValueOrThrow()));
        }
        else if (readResult.Status == NtStatus.ObjectNameNotFound)
        {
            Console.WriteLine("The file does not exist.");
        }
        else
        {
            readResult.EnsureSuccess();
        }

        await client.TryDisconnectAsync(cancellationToken).ConfigureAwait(false);
    }
}

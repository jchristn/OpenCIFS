using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OpenCIFS.Client;

internal static class OpenCifsClientHappyPathSample
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
        await client.ConnectAsync(credential, cancellationToken).ConfigureAwait(false);

        await using OpenCifsShareSession share = await client.OpenShareAsync("share", cancellationToken).ConfigureAwait(false);
        await share.Directories.CreateAsync("/docs", cancellationToken).ConfigureAwait(false);
        await share.Files.WriteAllBytesAsync("/docs/hello.txt", Encoding.UTF8.GetBytes("hello from OpenCIFS"), cancellationToken).ConfigureAwait(false);

        byte[] fileBytes = await share.Files.ReadAllBytesAsync("/docs/hello.txt", cancellationToken).ConfigureAwait(false);
        OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("/docs/hello.txt", cancellationToken).ConfigureAwait(false);
        OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync("/docs", cancellationToken: cancellationToken).ConfigureAwait(false);

        Console.WriteLine(Encoding.UTF8.GetString(fileBytes));
        Console.WriteLine($"{metadata.Path}: {metadata.EndOfFile} bytes");
        Console.WriteLine($"Enumerated {entries.Length} entries.");

        try
        {
            await share.Directories.DeleteAsync("/docs", cancellationToken).ConfigureAwait(false);
        }
        catch (OpenCifsStatusException exception) when (exception.Category == OpenCifsErrorCategory.Conflict)
        {
            Console.WriteLine($"{exception.Command} failed with {exception.Status} ({exception.Category}).");
        }

        await share.Files.RenameAsync("/docs/hello.txt", "/docs/hello-renamed.txt", cancellationToken).ConfigureAwait(false);
        await share.Files.DeleteAsync("/docs/hello-renamed.txt", cancellationToken).ConfigureAwait(false);
        await share.Directories.DeleteAsync("/docs", cancellationToken).ConfigureAwait(false);
        await client.DisconnectAsync(cancellationToken).ConfigureAwait(false);
    }
}

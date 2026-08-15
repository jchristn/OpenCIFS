namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;
    internal static class ClientDefaultsSuiteBuilder
    {
        /// <summary>
        /// Build the client defaults suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Defaults",
                displayName: "Client bootstrap defaults",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "DefaultConnectionSettings",
                        displayName: "Client defaults target modern signed sessions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientOptions options = new OpenCifsClientOptions();

                            if (!StringComparer.Ordinal.Equals(options.ServerName, "127.0.0.1"))
                            {
                                throw new InvalidOperationException("Expected default server name 127.0.0.1.");
                            }

                            if (options.ServerPort != 445)
                            {
                                throw new InvalidOperationException("Expected default server port 445.");
                            }

                            if (options.ConnectTimeoutMs != 30000)
                            {
                                throw new InvalidOperationException("Expected default timeout 30000ms.");
                            }

                            if (options.DfsReferralCacheCapacity != 128)
                            {
                                throw new InvalidOperationException("Expected default DFS referral cache capacity 128.");
                            }

                            if (options.DfsSiteName.Length != 0)
                            {
                                throw new InvalidOperationException("Expected default DFS site name to be empty.");
                            }

                            if (!options.RequireSigning)
                            {
                                throw new InvalidOperationException("Signing should be required by default.");
                            }

                            if (!options.PreferEncryption)
                            {
                                throw new InvalidOperationException("Encryption should be preferred by default.");
                            }

                            options.Validate();
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "InvalidDialectRangeRejected",
                        displayName: "Client options reject an invalid dialect range",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientOptions options = new OpenCifsClientOptions
                            {
                                MinimumDialect = SmbDialect.Smb311,
                                MaximumDialect = SmbDialect.Smb2002
                            };

                            try
                            {
                                options.Validate();
                            }
                            catch (ArgumentException)
                            {
                                return Task.CompletedTask;
                            }

                            throw new InvalidOperationException("Expected Validate to reject a reversed dialect range.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "Smb311MinimumRejectedWhenPreviewDisabled",
                        displayName: "Client options reject SMB 3.1.1 minimum dialect when preview is disabled",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientOptions options = new OpenCifsClientOptions
                            {
                                MinimumDialect = SmbDialect.Smb311,
                                MaximumDialect = SmbDialect.Smb311,
                                EnableSmb311Preview = false
                            };

                            try
                            {
                                options.Validate();
                            }
                            catch (ArgumentException)
                            {
                                return Task.CompletedTask;
                            }

                            throw new InvalidOperationException("Expected Validate to reject SMB 3.1.1 minimum dialect when preview is disabled.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "ClientStatusExceptionsReturnNormalizedCategoriesForRepresentativeNtStatusValues",
                        displayName: "Client status exceptions return normalized categories for representative NTSTATUS values",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Equal(OpenCifsErrorCategory.NotFound, new OpenCifsStatusException(Smb2Command.Create, NtStatus.ObjectNameNotFound).Category, "Expected STATUS_OBJECT_NAME_NOT_FOUND to normalize to NotFound.");
                            TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, new OpenCifsStatusException(Smb2Command.SetInfo, NtStatus.AccessDenied).Category, "Expected STATUS_ACCESS_DENIED to normalize to AccessDenied.");
                            TestAssertions.Equal(OpenCifsErrorCategory.Conflict, new OpenCifsStatusException(Smb2Command.Create, NtStatus.SharingViolation).Category, "Expected STATUS_SHARING_VIOLATION to normalize to Conflict.");
                            TestAssertions.Equal(OpenCifsErrorCategory.Unsupported, new OpenCifsStatusException(Smb2Command.Ioctl, NtStatus.NotSupported).Category, "Expected STATUS_NOT_SUPPORTED to normalize to Unsupported.");
                            TestAssertions.Equal(OpenCifsErrorCategory.ProtocolError, new OpenCifsStatusException(Smb2Command.QueryInfo, NtStatus.BufferTooSmall).Category, "Expected STATUS_BUFFER_TOO_SMALL to normalize to ProtocolError.");
                            TestAssertions.Equal(OpenCifsErrorCategory.IoError, new OpenCifsStatusException(Smb2Command.Close, NtStatus.FileClosed).Category, "Expected STATUS_FILE_CLOSED to normalize to IoError.");
                            TestAssertions.Equal(OpenCifsErrorCategory.Cancelled, new OpenCifsStatusException(Smb2Command.ChangeNotify, NtStatus.Cancelled).Category, "Expected STATUS_CANCELLED to normalize to Cancelled.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "ClientPublicSurfaceExposesTypedExceptionsForRepresentativeStateAndProtocolFailures",
                        displayName: "Client public surface exposes typed exceptions for representative state and protocol failures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsStatusException statusException = new OpenCifsStatusException(Smb2Command.Create, NtStatus.ObjectNameNotFound);
                            TestAssertions.True(statusException is OpenCifsClientException, "Expected SMB status failures to derive from the typed client exception hierarchy.");

                            OpenCifsClientConnection disconnectedConnection = new OpenCifsClientConnection(new OpenCifsClientOptions());
                            TestAssertions.Throws<OpenCifsClientStateException>(
                                () => disconnectedConnection.TreeConnectAsync("public", token).GetAwaiter().GetResult(),
                                "Expected tree connect before authentication to raise a typed client-state exception.");

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ApplyResponseHeader(CreateResponseHeader(requestHeader, flags: Smb2HeaderFlags.None)),
                                "Expected malformed response headers on the advanced session surface to raise a typed client-protocol exception.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Defaults",
                        caseId: "ClientSuitesExposePositiveAndNegativeVariants",
                        displayName: "Client shared suites expose positive and negative variants",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            TestCaseVariantCoverage.AssertBalancedVariants(ClientTestSuites.All, "Client");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}

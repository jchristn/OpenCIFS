namespace OpenCIFS.Server
{
    using System;
    using System.Globalization;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerChangeNotifyService
    {
        private readonly Func<ulong> _AllocateAsyncId;
        private readonly Func<ulong> _AllocateSequenceId;
        private readonly Func<Smb2Header, NtStatus, ulong, uint, Smb2Header> _CreateResponseHeader;
        private readonly Func<ushort, ushort> _DetermineCreditsToGrant;
        private readonly Action<OpenCifsServerAsyncResponse> _EnqueueAsyncResponse;
        private readonly Func<IEnumerable<OpenCifsServerHost>> _EnumerateHosts;
        private readonly Func<ulong, RequestState> _GetPendingRequest;
        private readonly Action<ushort> _GrantCredits;
        private readonly Dictionary<ulong, PendingChangeNotifySubscription> _PendingChangeNotifySubscriptions;
        private readonly Dictionary<ulong, RequestState> _PendingRequests;

        public OpenCifsServerChangeNotifyService(
            Dictionary<ulong, PendingChangeNotifySubscription> pendingChangeNotifySubscriptions,
            Dictionary<ulong, RequestState> pendingRequests,
            Func<ulong, RequestState> getPendingRequest,
            Func<ushort, ushort> determineCreditsToGrant,
            Action<ushort> grantCredits,
            Func<ulong> allocateAsyncId,
            Func<ulong> allocateSequenceId,
            Func<Smb2Header, NtStatus, ulong, uint, Smb2Header> createResponseHeader,
            Action<OpenCifsServerAsyncResponse> enqueueAsyncResponse,
            Func<IEnumerable<OpenCifsServerHost>> enumerateHosts)
        {
            _PendingChangeNotifySubscriptions = pendingChangeNotifySubscriptions ?? throw new ArgumentNullException(nameof(pendingChangeNotifySubscriptions), "PendingChangeNotifySubscriptions cannot be null.");
            _PendingRequests = pendingRequests ?? throw new ArgumentNullException(nameof(pendingRequests), "PendingRequests cannot be null.");
            _GetPendingRequest = getPendingRequest ?? throw new ArgumentNullException(nameof(getPendingRequest), "GetPendingRequest cannot be null.");
            _DetermineCreditsToGrant = determineCreditsToGrant ?? throw new ArgumentNullException(nameof(determineCreditsToGrant), "DetermineCreditsToGrant cannot be null.");
            _GrantCredits = grantCredits ?? throw new ArgumentNullException(nameof(grantCredits), "GrantCredits cannot be null.");
            _AllocateAsyncId = allocateAsyncId ?? throw new ArgumentNullException(nameof(allocateAsyncId), "AllocateAsyncId cannot be null.");
            _AllocateSequenceId = allocateSequenceId ?? throw new ArgumentNullException(nameof(allocateSequenceId), "AllocateSequenceId cannot be null.");
            _CreateResponseHeader = createResponseHeader ?? throw new ArgumentNullException(nameof(createResponseHeader), "CreateResponseHeader cannot be null.");
            _EnqueueAsyncResponse = enqueueAsyncResponse ?? throw new ArgumentNullException(nameof(enqueueAsyncResponse), "EnqueueAsyncResponse cannot be null.");
            _EnumerateHosts = enumerateHosts ?? throw new ArgumentNullException(nameof(enumerateHosts), "EnumerateHosts cannot be null.");
        }

        public IEnumerable<PendingChangeNotifySubscription> EnumeratePendingSubscriptions()
        {
            return _PendingChangeNotifySubscriptions.Values;
        }

        public OpenCifsServerAsyncResponse CreateErrorResponse(Smb2Header requestHeader, NtStatus status, ulong sessionId, uint treeId)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            Smb2ErrorResponse errorResponse = new Smb2ErrorResponse();
            Smb2ErrorResponseValidator.Validate(errorResponse);
            return new OpenCifsServerAsyncResponse
            {
                Header = _CreateResponseHeader(requestHeader, status, sessionId, treeId),
                Payload = errorResponse.ToByteArray()
            };
        }

        public OpenCifsServerAsyncResponse CreatePendingResponse(Smb2Header requestHeader, Smb2ChangeNotifyRequest request, ServerOpenRecord openRecord)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (openRecord == null)
            {
                throw new ArgumentNullException(nameof(openRecord), "OpenRecord cannot be null.");
            }

            Smb2Header interimHeader = CreateInterimAsyncResponseHeader(requestHeader);
            _PendingChangeNotifySubscriptions[requestHeader.MessageId] = new PendingChangeNotifySubscription
            {
                SequenceId = _AllocateSequenceId(),
                MessageId = requestHeader.MessageId,
                SessionId = requestHeader.SessionId,
                TreeId = requestHeader.TreeId,
                PersistentFileId = request.PersistentFileId,
                VolatileFileId = request.VolatileFileId,
                DirectoryFullPath = openRecord.FullPath,
                WatchTree = (request.Flags & Smb2ChangeNotifyFlags.WatchTree) != 0,
                CompletionFilter = request.CompletionFilter,
                OutputBufferLength = request.OutputBufferLength
            };

            Smb2ErrorResponse interimErrorResponse = new Smb2ErrorResponse();
            Smb2ErrorResponseValidator.Validate(interimErrorResponse);
            return new OpenCifsServerAsyncResponse
            {
                Header = interimHeader,
                Payload = interimErrorResponse.ToByteArray()
            };
        }

        public void TryQueueResponse(PendingChangeNotifySubscription subscription, IReadOnlyList<ChangeNotifyEvent> events)
        {
            if (subscription == null)
            {
                throw new ArgumentNullException(nameof(subscription), "Subscription cannot be null.");
            }

            if (events == null)
            {
                throw new ArgumentNullException(nameof(events), "Events cannot be null.");
            }

            if (!_PendingRequests.TryGetValue(subscription.MessageId, out RequestState? requestState) || requestState == null || requestState.Header == null)
            {
                _PendingChangeNotifySubscriptions.Remove(subscription.MessageId);
                return;
            }

            List<FileNotifyInformation> entries = new List<FileNotifyInformation>();

            for (int index = 0; index < events.Count; index++)
            {
                ChangeNotifyEvent changeEvent = events[index];

                if ((subscription.CompletionFilter & changeEvent.Filter) == 0)
                {
                    continue;
                }

                if (!TryGetRelativePath(subscription, changeEvent.FullPath, out string? relativePath) || relativePath == null)
                {
                    continue;
                }

                entries.Add(new FileNotifyInformation
                {
                    Action = changeEvent.Action,
                    FileName = relativePath
                });
            }

            if (entries.Count == 0)
            {
                return;
            }

            _PendingChangeNotifySubscriptions.Remove(subscription.MessageId);
            byte[] encodedEntries = FileNotifyInformation.EncodeEntries(entries);
            Smb2ChangeNotifyResponse response = new Smb2ChangeNotifyResponse();
            NtStatus status;

            if (subscription.OutputBufferLength == 0 || encodedEntries.Length > subscription.OutputBufferLength)
            {
                status = NtStatus.NotifyEnumDir;
                response.OutputBuffer = Array.Empty<byte>();
            }
            else
            {
                status = NtStatus.Success;
                response.OutputBuffer = encodedEntries;
            }

            Smb2ChangeNotifyResponseValidator.Validate(response);
            _EnqueueAsyncResponse(new OpenCifsServerAsyncResponse
            {
                Header = _CreateResponseHeader(requestState.Header, status, requestState.Header.SessionId, requestState.Header.TreeId),
                Payload = response.ToByteArray()
            });
        }

        public void PublishNameChangeNotification(string fullPath, bool isDirectory, FileNotifyAction action)
        {
            PublishChangeNotifyEvents(new ChangeNotifyEvent
            {
                FullPath = fullPath,
                Action = action,
                Filter = ((!isDirectory) ? FileNotifyChangeFilter.FileName : FileNotifyChangeFilter.DirName)
            });
        }

        public void PublishModifiedNotification(string fullPath, FileNotifyChangeFilter filter)
        {
            if (filter != FileNotifyChangeFilter.None)
            {
                PublishChangeNotifyEvents(new ChangeNotifyEvent
                {
                    FullPath = fullPath,
                    Action = FileNotifyAction.Modified,
                    Filter = filter
                });
            }
        }

        public void PublishRenameNotification(string oldFullPath, string newFullPath, bool isDirectory)
        {
            FileNotifyChangeFilter filter = ((!isDirectory) ? FileNotifyChangeFilter.FileName : FileNotifyChangeFilter.DirName);
            string? oldParent = Path.GetDirectoryName(oldFullPath);
            string? newParent = Path.GetDirectoryName(newFullPath);

            if (string.Equals(oldParent, newParent, StringComparison.OrdinalIgnoreCase))
            {
                PublishChangeNotifyEvents(new ChangeNotifyEvent
                {
                    FullPath = oldFullPath,
                    Action = FileNotifyAction.RenamedOldName,
                    Filter = filter
                }, new ChangeNotifyEvent
                {
                    FullPath = newFullPath,
                    Action = FileNotifyAction.RenamedNewName,
                    Filter = filter
                });
            }
            else
            {
                PublishChangeNotifyEvents(new ChangeNotifyEvent
                {
                    FullPath = oldFullPath,
                    Action = FileNotifyAction.Removed,
                    Filter = filter
                }, new ChangeNotifyEvent
                {
                    FullPath = newFullPath,
                    Action = FileNotifyAction.Added,
                    Filter = filter
                });
            }
        }

        public void QueueCancelledResponsesForOpen(ulong volatileFileId)
        {
            List<ulong> messageIds = new List<ulong>();

            foreach (KeyValuePair<ulong, PendingChangeNotifySubscription> entry in _PendingChangeNotifySubscriptions)
            {
                if (entry.Value.VolatileFileId == volatileFileId)
                {
                    messageIds.Add(entry.Key);
                }
            }

            for (int index = 0; index < messageIds.Count; index++)
            {
                ulong messageId = messageIds[index];
                _PendingChangeNotifySubscriptions.Remove(messageId);

                if (!_PendingRequests.TryGetValue(messageId, out RequestState? requestState) || requestState == null || requestState.Header == null)
                {
                    continue;
                }

                requestState.Cancel();
                Smb2ErrorResponse cancelledErrorResponse = new Smb2ErrorResponse();
                Smb2ErrorResponseValidator.Validate(cancelledErrorResponse);
                _EnqueueAsyncResponse(new OpenCifsServerAsyncResponse
                {
                    Header = _CreateResponseHeader(requestState.Header, NtStatus.Cancelled, requestState.Header.SessionId, requestState.Header.TreeId),
                    Payload = cancelledErrorResponse.ToByteArray()
                });
            }
        }

        private Smb2Header CreateInterimAsyncResponseHeader(Smb2Header requestHeader)
        {
            RequestState requestState = _GetPendingRequest(requestHeader.MessageId);

            if (requestState.Command != requestHeader.Command)
            {
                throw new ProtocolValidationException("The accepted SMB2 request does not match the interim async response command.", nameof(requestHeader));
            }

            ushort creditsGranted = _DetermineCreditsToGrant(requestHeader.CreditRequest);
            _GrantCredits(creditsGranted);

            ulong asyncId = _AllocateAsyncId();
            requestState.MarkAsync(asyncId);

            Smb2Header responseHeader = new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Pending,
                Command = requestHeader.Command,
                CreditRequest = creditsGranted,
                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand | (requestHeader.Flags & Smb2HeaderFlags.Signed),
                NextCommand = 0,
                MessageId = requestHeader.MessageId,
                AsyncId = asyncId,
                SessionId = requestHeader.SessionId,
                Signature = new byte[16]
            };

            Smb2HeaderValidator.Validate(responseHeader);
            return responseHeader;
        }

        private void PublishChangeNotifyEvents(params ChangeNotifyEvent[] events)
        {
            if (events == null || events.Length == 0)
            {
                return;
            }

            List<PendingChangeNotifyDispatchTarget> dispatchableSubscriptions = GetDispatchableChangeNotifySubscriptions();

            for (int index = 0; index < dispatchableSubscriptions.Count; index++)
            {
                PendingChangeNotifyDispatchTarget dispatchTarget = dispatchableSubscriptions[index];
                dispatchTarget.OwnerHost.TryQueuePublishedChangeNotifyResponse(dispatchTarget.Subscription, events);
            }
        }

        private List<PendingChangeNotifyDispatchTarget> GetDispatchableChangeNotifySubscriptions()
        {
            Dictionary<string, PendingChangeNotifyDispatchTarget> firstByOpen = new Dictionary<string, PendingChangeNotifyDispatchTarget>(StringComparer.Ordinal);

            foreach (OpenCifsServerHost host in _EnumerateHosts())
            {
                foreach (PendingChangeNotifySubscription subscription in host.EnumeratePendingChangeNotifySubscriptions())
                {
                    string key = host.HostId.ToString("N") + ":" + subscription.VolatileFileId.ToString(CultureInfo.InvariantCulture);

                    if (!firstByOpen.TryGetValue(key, out PendingChangeNotifyDispatchTarget? existingTarget) || subscription.SequenceId < existingTarget.Subscription.SequenceId)
                    {
                        firstByOpen[key] = new PendingChangeNotifyDispatchTarget
                        {
                            OwnerHost = host,
                            Subscription = subscription
                        };
                    }
                }
            }

            List<PendingChangeNotifyDispatchTarget> subscriptions = new List<PendingChangeNotifyDispatchTarget>(firstByOpen.Values);
            subscriptions.Sort((PendingChangeNotifyDispatchTarget left, PendingChangeNotifyDispatchTarget right) => left.Subscription.SequenceId.CompareTo(right.Subscription.SequenceId));
            return subscriptions;
        }

        private static bool TryGetRelativePath(PendingChangeNotifySubscription subscription, string fullPath, out string? relativePath)
        {
            relativePath = null;

            if (string.IsNullOrEmpty(fullPath) || string.IsNullOrEmpty(subscription.DirectoryFullPath))
            {
                return false;
            }

            if (subscription.WatchTree)
            {
                string directoryPrefix = subscription.DirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                    ? subscription.DirectoryFullPath
                    : subscription.DirectoryFullPath + Path.DirectorySeparatorChar;

                if (!fullPath.StartsWith(directoryPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                relativePath = fullPath.Substring(directoryPrefix.Length);
                return relativePath.Length != 0;
            }

            string? parentDirectory = Path.GetDirectoryName(fullPath);

            if (!string.Equals(parentDirectory, subscription.DirectoryFullPath, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            relativePath = Path.GetFileName(fullPath);
            return !string.IsNullOrEmpty(relativePath);
        }
    }
}

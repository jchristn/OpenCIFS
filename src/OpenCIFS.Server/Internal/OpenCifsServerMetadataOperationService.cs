#nullable enable annotations
#nullable disable warnings

namespace OpenCIFS.Server;

using System;
using System.Collections.Generic;
using System.IO;
using OpenCIFS.Protocol;

internal sealed class OpenCifsServerMetadataOperationService
{
	private readonly OpenCifsServerDirectoryEnumerationService _DirectoryEnumerationService;

	private readonly IDictionary<ulong, ServerSessionRecord> _Sessions;

	private readonly OpenCifsServerOpenCleanupService _OpenCleanupService;

	private readonly OpenCifsServerOptions _Options;

	private readonly OpenCifsServerQueryInfoService _QueryInfoService;

	private readonly OpenCifsServerSessionOpenStateService _SessionOpenStateService;

	private readonly OpenCifsServerSetInfoMutationService _SetInfoMutationService;

	private readonly Action<string> _WriteDiagnostic;

	public OpenCifsServerMetadataOperationService(
		OpenCifsServerOptions options,
		IDictionary<ulong, ServerSessionRecord> sessions,
		OpenCifsServerSessionOpenStateService sessionOpenStateService,
		OpenCifsServerDirectoryEnumerationService directoryEnumerationService,
		OpenCifsServerQueryInfoService queryInfoService,
		OpenCifsServerSetInfoMutationService setInfoMutationService,
		OpenCifsServerOpenCleanupService openCleanupService,
		Action<string> writeDiagnostic)
	{
		_Options = options ?? throw new ArgumentNullException("options", "Options cannot be null.");
		_Sessions = sessions ?? throw new ArgumentNullException("sessions", "Sessions cannot be null.");
		_SessionOpenStateService = sessionOpenStateService ?? throw new ArgumentNullException("sessionOpenStateService", "SessionOpenStateService cannot be null.");
		_DirectoryEnumerationService = directoryEnumerationService ?? throw new ArgumentNullException("directoryEnumerationService", "DirectoryEnumerationService cannot be null.");
		_QueryInfoService = queryInfoService ?? throw new ArgumentNullException("queryInfoService", "QueryInfoService cannot be null.");
		_SetInfoMutationService = setInfoMutationService ?? throw new ArgumentNullException("setInfoMutationService", "SetInfoMutationService cannot be null.");
		_OpenCleanupService = openCleanupService ?? throw new ArgumentNullException("openCleanupService", "OpenCleanupService cannot be null.");
		_WriteDiagnostic = writeDiagnostic ?? throw new ArgumentNullException("writeDiagnostic", "WriteDiagnostic cannot be null.");
	}

	public OpenCifsServerOperationResult<Smb2QueryInfoResponse> ExecuteQueryInfo(ulong sessionId, uint treeId, Smb2QueryInfoRequest request)
	{
		Smb2QueryInfoRequestValidator.Validate(request);
		if (!_SessionOpenStateService.TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord sessionRecord) || sessionRecord == null)
		{
			return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryInfoResponse());
		}
		if (!_SessionOpenStateService.TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord openRecord) || openRecord == null)
		{
			return CreateOperationResult(NtStatus.FileClosed, new Smb2QueryInfoResponse());
		}
		if (openRecord.IsNamedPipeEndpoint)
		{
			return CreateOperationResult(NtStatus.NotSupported, new Smb2QueryInfoResponse());
		}
		byte[] outputBuffer;
		NtStatus queryStatus = _QueryInfoService.TryBuildOutputBuffer(openRecord, request, out outputBuffer);
		if (queryStatus != NtStatus.Success)
		{
			return CreateOperationResult(queryStatus, new Smb2QueryInfoResponse());
		}
		if (request.OutputBufferLength < outputBuffer.Length)
		{
			return CreateOperationResult(NtStatus.BufferTooSmall, new Smb2QueryInfoResponse());
		}
		Smb2QueryInfoResponse response = new Smb2QueryInfoResponse
		{
			OutputBuffer = outputBuffer
		};
		Smb2QueryInfoResponseValidator.Validate(response);
		return CreateOperationResult(NtStatus.Success, response);
	}

	public OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> ExecuteQueryDirectory(ulong sessionId, uint treeId, Smb2QueryDirectoryRequest request)
	{
		_WriteDiagnostic("Query-directory request received for session " + sessionId + ", tree " + treeId + ", info class " + request.FileInfoClass.ToString() + " (0x" + ((byte)request.FileInfoClass).ToString("X2") + "), pattern '" + request.FileNamePattern + "'.");
		Smb2QueryDirectoryRequestValidator.Validate(request);
		if (!_SessionOpenStateService.TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord sessionRecord) || sessionRecord == null)
		{
			return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryDirectoryResponse());
		}
		if (!_SessionOpenStateService.TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord openRecord) || openRecord == null)
		{
			return CreateOperationResult(NtStatus.FileClosed, new Smb2QueryDirectoryResponse());
		}
		if (openRecord.IsNamedPipeEndpoint)
		{
			return CreateOperationResult(NtStatus.NotSupported, new Smb2QueryDirectoryResponse());
		}
		if (_Options.RequestCallbacks?.QueryDirectoryCallback != null)
		{
			NtStatus? callbackStatus = _Options.RequestCallbacks.QueryDirectoryCallback(new OpenCifsServerQueryDirectoryContext
			{
				SessionId = sessionId,
				TreeId = treeId,
				ShareName = openRecord.ShareName,
				FullPath = openRecord.FullPath,
				Request = request
			});
			if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
			{
				return CreateOperationResult(callbackStatus.Value, new Smb2QueryDirectoryResponse());
			}
		}
		if (!openRecord.IsDirectory)
		{
			return CreateOperationResult(NtStatus.InvalidParameter, new Smb2QueryDirectoryResponse());
		}
		if (!OpenCifsServerFilePolicy.CanListDirectory(openRecord.DesiredAccess))
		{
			return CreateOperationResult(NtStatus.AccessDenied, new Smb2QueryDirectoryResponse());
		}
		if (!IsSupportedQueryDirectoryInformationClass(request.FileInfoClass))
		{
			return CreateOperationResult(NtStatus.InvalidInfoClass, new Smb2QueryDirectoryResponse());
		}

		bool restartScan = (request.Flags & (Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.Reopen)) != 0;
		bool hadExistingEnumeration = !string.IsNullOrEmpty(openRecord.DirectoryEnumerationPattern);
		string pattern = GetEffectiveDirectoryEnumerationPattern(openRecord, request, restartScan, hadExistingEnumeration);
		List<FileSystemInfo> matchingEntries = _DirectoryEnumerationService.EnumerateMatchingEntries(openRecord.Backend, openRecord.FullPath, pattern);
		bool firstPassForPattern = restartScan || !hadExistingEnumeration;
		if (matchingEntries.Count == 0)
		{
			return CreateOperationResult(firstPassForPattern ? NtStatus.NoSuchFile : NtStatus.NoMoreFiles, new Smb2QueryDirectoryResponse());
		}
		int startIndex = firstPassForPattern ? 0 : openRecord.DirectoryEnumerationIndex;
		if (startIndex >= matchingEntries.Count)
		{
			return CreateOperationResult(NtStatus.NoMoreFiles, new Smb2QueryDirectoryResponse());
		}
		bool returnSingleEntry = (request.Flags & Smb2QueryDirectoryFlags.ReturnSingleEntry) != 0;
		byte[] outputBuffer;
		int returnedEntryCount;
		NtStatus bufferStatus = _DirectoryEnumerationService.TryBuildEnumerationBuffer(openRecord.Backend, request.FileInfoClass, matchingEntries, startIndex, request.OutputBufferLength, returnSingleEntry, out outputBuffer, out returnedEntryCount);
		if (bufferStatus != NtStatus.Success)
		{
			return CreateOperationResult(bufferStatus, new Smb2QueryDirectoryResponse());
		}
		openRecord.DirectoryEnumerationIndex = startIndex + returnedEntryCount;
		Smb2QueryDirectoryResponse response = new Smb2QueryDirectoryResponse
		{
			OutputBuffer = outputBuffer
		};
		Smb2QueryDirectoryResponseValidator.Validate(response);
		return CreateOperationResult(NtStatus.Success, response);
	}

	public OpenCifsServerOperationResult<Smb2SetInfoResponse> ExecuteSetInfo(ulong sessionId, uint treeId, Smb2SetInfoRequest request)
	{
		Smb2SetInfoRequestValidator.Validate(request);
		if (!_SessionOpenStateService.TryGetAuthenticatedTree(sessionId, treeId, out ServerSessionRecord sessionRecord) || sessionRecord == null)
		{
			return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
		}
		if (!_SessionOpenStateService.TryGetOpen(sessionRecord, treeId, request.PersistentFileId, request.VolatileFileId, out ServerOpenRecord openRecord) || openRecord == null)
		{
			return CreateOperationResult(NtStatus.FileClosed, new Smb2SetInfoResponse());
		}
		if (openRecord.IsNamedPipeEndpoint)
		{
			return CreateOperationResult(NtStatus.NotSupported, new Smb2SetInfoResponse());
		}
		if (_Options.RequestCallbacks?.SetInfoCallback != null)
		{
			NtStatus? callbackStatus = _Options.RequestCallbacks.SetInfoCallback(new OpenCifsServerSetInfoContext
			{
				SessionId = sessionId,
				TreeId = treeId,
				ShareName = openRecord.ShareName,
				FullPath = openRecord.FullPath,
				Request = request
			});
			if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
			{
				return CreateOperationResult(callbackStatus.Value, new Smb2SetInfoResponse());
			}
		}
		try
		{
			switch (request.FileInfoClass)
			{
				case FileInformationClass.BasicInformation:
				{
					if (!OpenCifsServerFilePolicy.CanWriteAttributes(openRecord.DesiredAccess))
					{
						return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
					}
					FileBasicInformation basicInformation = FileBasicInformation.ReadFrom(request.Buffer);
					NtStatus basicInformationStatus = _SetInfoMutationService.ApplyFileBasicInformation(openRecord, basicInformation);
					if (basicInformationStatus != NtStatus.Success)
					{
						return CreateOperationResult(basicInformationStatus, new Smb2SetInfoResponse());
					}
					break;
				}
				case FileInformationClass.AllocationInformation:
					if (!OpenCifsServerFilePolicy.CanWriteData(openRecord.DesiredAccess))
					{
						return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
					}
					if (openRecord.IsDirectory || openRecord.Stream == null)
					{
						return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
					}
					_SetInfoMutationService.ApplyFileAllocationInformation(openRecord, FileAllocationInformation.ReadFrom(request.Buffer));
					break;
				case FileInformationClass.EndOfFileInformation:
					if (!OpenCifsServerFilePolicy.CanWriteData(openRecord.DesiredAccess))
					{
						return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
					}
					if (openRecord.IsDirectory || openRecord.Stream == null)
					{
						return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
					}
					_SetInfoMutationService.ApplyFileEndOfFileInformation(openRecord, FileEndOfFileInformation.ReadFrom(request.Buffer));
					break;
				case FileInformationClass.DispositionInformation:
				{
					if (!OpenCifsServerFilePolicy.CanDelete(openRecord.DesiredAccess))
					{
						return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
					}
					FileDispositionInformation dispositionInformation = FileDispositionInformation.ReadFrom(request.Buffer);
					NtStatus dispositionStatus = _SetInfoMutationService.ApplyDeletePendingState(openRecord, dispositionInformation.DeletePending);
					if (dispositionStatus != NtStatus.Success)
					{
						return CreateOperationResult(dispositionStatus, new Smb2SetInfoResponse());
					}
					break;
				}
				case FileInformationClass.RenameInformation:
				{
					if (!OpenCifsServerFilePolicy.CanDelete(openRecord.DesiredAccess))
					{
						return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
					}
					NtStatus renameStatus = _SetInfoMutationService.ApplyRenameInformation(openRecord, FileRenameInformationType2.ReadFrom(request.Buffer));
					if (renameStatus != NtStatus.Success)
					{
						return CreateOperationResult(renameStatus, new Smb2SetInfoResponse());
					}
					break;
				}
				default:
					return CreateOperationResult(NtStatus.NotSupported, new Smb2SetInfoResponse());
			}
		}
		catch (ProtocolEncodingException)
		{
			return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
		}
		catch (ArgumentOutOfRangeException)
		{
			return CreateOperationResult(NtStatus.InvalidParameter, new Smb2SetInfoResponse());
		}
		catch (UnauthorizedAccessException)
		{
			return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
		}
		catch (IOException)
		{
			return CreateOperationResult(NtStatus.AccessDenied, new Smb2SetInfoResponse());
		}
		Smb2SetInfoResponse response = new Smb2SetInfoResponse();
		Smb2SetInfoResponseValidator.Validate(response);
		return CreateOperationResult(NtStatus.Success, response);
	}

	public OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> ExecuteTreeDisconnect(ulong sessionId, uint treeId, Smb2TreeDisconnectRequest request)
	{
		Smb2TreeDisconnectRequestValidator.Validate(request);
		if (!_Sessions.TryGetValue(sessionId, out ServerSessionRecord sessionRecord) || !sessionRecord.State.IsAuthenticated)
		{
			return CreateOperationResult(NtStatus.AccessDenied, new Smb2TreeDisconnectResponse());
		}
		if (!sessionRecord.Trees.TryGetValue(treeId, out ServerTreeRecord treeRecord) || treeRecord == null)
		{
			return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2TreeDisconnectResponse());
		}
		_OpenCleanupService.CleanupTreeOpenRecords(sessionRecord, treeId);
		treeRecord.State.Disconnect();
		treeRecord.State.Dispose();
		sessionRecord.Trees.Remove(treeId);
		Smb2TreeDisconnectResponse response = new Smb2TreeDisconnectResponse();
		Smb2TreeDisconnectResponseValidator.Validate(response);
		return CreateOperationResult(NtStatus.Success, response);
	}

	private static OpenCifsServerOperationResult<TResponse> CreateOperationResult<TResponse>(NtStatus status, TResponse response) where TResponse : class
	{
		return new OpenCifsServerOperationResult<TResponse>
		{
			Status = status,
			Response = response
		};
	}

	private static string GetEffectiveDirectoryEnumerationPattern(
		ServerOpenRecord openRecord,
		Smb2QueryDirectoryRequest request,
		bool restartScan,
		bool hadExistingEnumeration)
	{
		string pattern;
		if (restartScan)
		{
			pattern = request.FileNamePattern.Length != 0 ? request.FileNamePattern : (hadExistingEnumeration ? openRecord.DirectoryEnumerationPattern : "*");
			openRecord.DirectoryEnumerationPattern = pattern;
			openRecord.DirectoryEnumerationIndex = 0;
			return pattern;
		}
		if (hadExistingEnumeration)
		{
			return openRecord.DirectoryEnumerationPattern;
		}
		pattern = request.FileNamePattern.Length != 0 ? request.FileNamePattern : "*";
		openRecord.DirectoryEnumerationPattern = pattern;
		openRecord.DirectoryEnumerationIndex = 0;
		return pattern;
	}

	private static bool IsSupportedQueryDirectoryInformationClass(FileInformationClass informationClass)
	{
		switch (informationClass)
		{
			case FileInformationClass.DirectoryInformation:
			case FileInformationClass.FullDirectoryInformation:
			case FileInformationClass.BothDirectoryInformation:
			case FileInformationClass.IdBothDirectoryInformation:
			case FileInformationClass.IdFullDirectoryInformation:
				return true;
			default:
				return false;
		}
	}
}

param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [string]$Server = "127.0.0.1",
    [int]$Port = 5445,
    [string]$Share = "share",
    [string]$UserName = "alice",
    [string]$Password = "Password123!",
    [string]$Domain = "WORKGROUP",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

function Invoke-TaskResult {
    param([Parameter(Mandatory = $true)][System.Threading.Tasks.Task]$Task)

    return $Task.GetAwaiter().GetResult()
}

function Load-OpenCifsAssembly {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ProjectName,
        [Parameter(Mandatory = $true)][string]$Configuration,
        [Parameter(Mandatory = $true)][string]$Framework
    )

    $assemblyPath = Join-Path $RepositoryRoot ("src\" + $ProjectName + "\bin\" + $Configuration + "\" + $Framework + "\" + $ProjectName + ".dll")
    [void][System.Reflection.Assembly]::LoadFrom($assemblyPath)
}

function Resolve-OpenCifsType {
    param([Parameter(Mandatory = $true)][string]$TypeName)

    foreach ($assembly in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
        $resolvedType = $assembly.GetType($TypeName, $false)

        if ($null -ne $resolvedType) {
            return $resolvedType
        }
    }

    throw "Unable to resolve type '$TypeName' from the currently loaded OpenCIFS assemblies."
}

function Close-TrackedOpen {
    param(
        [Parameter(Mandatory = $true)][Object]$Client,
        [Object]$OpenHandle
    )

    if ($null -eq $OpenHandle -or $OpenHandle.IsClosed) {
        return
    }

    try {
        Invoke-TaskResult ($Client.CloseAsync($OpenHandle, $false, [System.Threading.CancellationToken]::None))
    }
    catch {
    }
}

function Disconnect-TrackedTree {
    param(
        [Parameter(Mandatory = $true)][Object]$Client,
        [Object]$TreeHandle
    )

    if ($null -eq $TreeHandle -or $TreeHandle.IsDisconnected) {
        return
    }

    try {
        Invoke-TaskResult ($Client.TreeDisconnectAsync($TreeHandle, [System.Threading.CancellationToken]::None))
    }
    catch {
    }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Load-OpenCifsAssembly -RepositoryRoot $repositoryRoot -ProjectName "OpenCIFS.Protocol" -Configuration $Configuration -Framework $Framework
Load-OpenCifsAssembly -RepositoryRoot $repositoryRoot -ProjectName "OpenCIFS.Transport" -Configuration $Configuration -Framework $Framework
Load-OpenCifsAssembly -RepositoryRoot $repositoryRoot -ProjectName "OpenCIFS.Security" -Configuration $Configuration -Framework $Framework
Load-OpenCifsAssembly -RepositoryRoot $repositoryRoot -ProjectName "OpenCIFS.Client" -Configuration $Configuration -Framework $Framework

$clientOptionsType = Resolve-OpenCifsType "OpenCIFS.Client.OpenCifsClientOptions"
$clientCredentialType = Resolve-OpenCifsType "OpenCIFS.Client.OpenCifsClientCredential"
$clientConnectionType = Resolve-OpenCifsType "OpenCIFS.Client.OpenCifsClientConnection"
$smbDialectType = Resolve-OpenCifsType "OpenCIFS.Protocol.SmbDialect"
$fileAttributesType = Resolve-OpenCifsType "OpenCIFS.Protocol.FileAttributes"
$createDispositionType = Resolve-OpenCifsType "OpenCIFS.Protocol.Smb2CreateDisposition"
$createOptionsType = Resolve-OpenCifsType "OpenCIFS.Protocol.Smb2CreateOptions"
$fileInformationClassType = Resolve-OpenCifsType "OpenCIFS.Protocol.FileInformationClass"
$fileStandardInformationType = Resolve-OpenCifsType "OpenCIFS.Protocol.FileStandardInformation"
$lockElementType = Resolve-OpenCifsType "OpenCIFS.Protocol.Smb2LockElement"
$lockFlagsType = Resolve-OpenCifsType "OpenCIFS.Protocol.Smb2LockFlags"
$queryDirectoryFlagsType = Resolve-OpenCifsType "OpenCIFS.Protocol.Smb2QueryDirectoryFlags"
$directoryEntryType = Resolve-OpenCifsType "OpenCIFS.Protocol.FileFullDirectoryInformationEntry"

$cancellationToken = [System.Threading.CancellationToken]::None
$genericReadAccess = [uint32]2147483648
$genericWriteAccess = [uint32]1073741824
$deleteAccessMask = [uint32]65536
$shareAccess = [uint32]7
$payloadText = "hello from opencifs client"
$payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadText)
$truncatedLength = [uint64]6
$directoryName = "opencifs-samba-smoke"
$fileName = "smoke.txt"
$renamedFileName = "renamed-smoke.txt"
$relativeFilePath = $directoryName + "\" + $fileName
$renamedFilePath = $directoryName + "\" + $renamedFileName

$options = $clientOptionsType::new()
$options.ServerName = $Server
$options.ServerPort = $Port
$options.RequireSigning = $false
$options.MinimumDialect = $smbDialectType::Smb2002
$options.MaximumDialect = $smbDialectType::Smb2002

$credential = $clientCredentialType::new()
$credential.UserName = $UserName
$credential.UserDomain = $Domain
$credential.Password = $Password

$firstClient = $clientConnectionType::new($options)
$secondClient = $clientConnectionType::new($options)
$firstTree = $null
$secondTree = $null
$directoryHandle = $null
$firstFileHandle = $null
$renameHandle = $null
$queryHandle = $null
$deleteFileHandle = $null
$deleteDirectoryHandle = $null
$secondFileHandle = $null
$lockConflictRejected = $false

try {
    Invoke-TaskResult ($firstClient.ConnectAndAuthenticateAsync($credential, $cancellationToken))
    Invoke-TaskResult ($secondClient.ConnectAndAuthenticateAsync($credential, $cancellationToken))

    $firstTree = Invoke-TaskResult ($firstClient.TreeConnectAsync($Share, $cancellationToken))
    $secondTree = Invoke-TaskResult ($secondClient.TreeConnectAsync($Share, $cancellationToken))

    $directoryHandle = Invoke-TaskResult ($firstClient.OpenAsync(
        $firstTree,
        $directoryName,
        $genericReadAccess,
        $fileAttributesType::Directory,
        $shareAccess,
        $createDispositionType::OpenIf,
        $createOptionsType::DirectoryFile,
        $cancellationToken))
    Invoke-TaskResult ($firstClient.CloseAsync($directoryHandle, $false, $cancellationToken))

    $firstFileHandle = Invoke-TaskResult ($firstClient.OpenAsync(
        $firstTree,
        $relativeFilePath,
        [uint32]($genericReadAccess -bor $genericWriteAccess),
        $fileAttributesType::Normal,
        $shareAccess,
        $createDispositionType::OverwriteIf,
        $createOptionsType::NonDirectoryFile,
        $cancellationToken))

    $writtenCount = Invoke-TaskResult ($firstClient.WriteAsync($firstFileHandle, $payloadBytes, [uint64]0, $cancellationToken))
    Invoke-TaskResult ($firstClient.FlushAsync($firstFileHandle, $cancellationToken))
    $roundTripBytes = Invoke-TaskResult ($firstClient.ReadAsync($firstFileHandle, [uint32]$payloadBytes.Length, [uint64]0, [uint32]0, $cancellationToken))
    $standardInfoBytes = Invoke-TaskResult ($firstClient.QueryInfoAsync($firstFileHandle, $fileInformationClassType::StandardInformation, [uint32]4096, $cancellationToken))
    $standardInfo = $fileStandardInformationType::ReadFrom($standardInfoBytes)

    $exclusiveLock = $lockElementType::new()
    $exclusiveLock.Offset = [uint64]0
    $exclusiveLock.Length = [uint64]8
    $exclusiveLock.Flags = $lockFlagsType::ExclusiveLock -bor $lockFlagsType::FailImmediately
    Invoke-TaskResult ($firstClient.LockAsync($firstFileHandle, @($exclusiveLock), $cancellationToken))

    $secondFileHandle = Invoke-TaskResult ($secondClient.OpenAsync(
        $secondTree,
        $relativeFilePath,
        [uint32]($genericReadAccess -bor $genericWriteAccess),
        $fileAttributesType::Normal,
        $shareAccess,
        $createDispositionType::Open,
        $createOptionsType::NonDirectoryFile,
        $cancellationToken))

    try {
        Invoke-TaskResult ($secondClient.LockAsync($secondFileHandle, @($exclusiveLock), $cancellationToken))
        throw "Expected Samba to reject the conflicting byte-range lock request."
    }
    catch [System.InvalidOperationException] {
        $lockConflictRejected = $true
    }

    $unlock = $lockElementType::new()
    $unlock.Offset = [uint64]0
    $unlock.Length = [uint64]8
    $unlock.Flags = $lockFlagsType::Unlock
    Invoke-TaskResult ($firstClient.LockAsync($firstFileHandle, @($unlock), $cancellationToken))

    Invoke-TaskResult ($firstClient.SetEndOfFileAsync($firstFileHandle, $truncatedLength, $cancellationToken))
    Invoke-TaskResult ($firstClient.CloseAsync($firstFileHandle, $false, $cancellationToken))
    Invoke-TaskResult ($secondClient.CloseAsync($secondFileHandle, $false, $cancellationToken))

    $renameHandle = Invoke-TaskResult ($firstClient.OpenExistingPathAsync(
        $firstTree,
        $relativeFilePath,
        [uint32]($genericReadAccess -bor $deleteAccessMask),
        $cancellationToken))
    Invoke-TaskResult ($firstClient.SetRenameAsync($renameHandle, $renamedFilePath, $false, $cancellationToken))
    Invoke-TaskResult ($firstClient.CloseAsync($renameHandle, $false, $cancellationToken))

    $queryHandle = Invoke-TaskResult ($firstClient.OpenAsync(
        $firstTree,
        $directoryName,
        $genericReadAccess,
        $fileAttributesType::Directory,
        $shareAccess,
        $createDispositionType::Open,
        $createOptionsType::DirectoryFile,
        $cancellationToken))
    $queryDirectoryBytes = Invoke-TaskResult ($firstClient.QueryDirectoryAsync(
        $queryHandle,
        $fileInformationClassType::FullDirectoryInformation,
        [uint32]4096,
        "*",
        $queryDirectoryFlagsType::RestartScans,
        $cancellationToken))
    $directoryEntries = $directoryEntryType::DecodeEntries($queryDirectoryBytes)
    $directoryEntryNames = @($directoryEntries | ForEach-Object { $_.FileName })
    Invoke-TaskResult ($firstClient.CloseAsync($queryHandle, $false, $cancellationToken))

    $deleteFileHandle = Invoke-TaskResult ($firstClient.OpenExistingPathAsync(
        $firstTree,
        $renamedFilePath,
        [uint32]($deleteAccessMask),
        $cancellationToken))
    Invoke-TaskResult ($firstClient.SetDeletePendingAsync($deleteFileHandle, $true, $cancellationToken))
    Invoke-TaskResult ($firstClient.CloseAsync($deleteFileHandle, $false, $cancellationToken))

    $deleteDirectoryHandle = Invoke-TaskResult ($firstClient.OpenExistingPathAsync(
        $firstTree,
        $directoryName,
        [uint32]($deleteAccessMask),
        $cancellationToken))
    Invoke-TaskResult ($firstClient.SetDeletePendingAsync($deleteDirectoryHandle, $true, $cancellationToken))
    Invoke-TaskResult ($firstClient.CloseAsync($deleteDirectoryHandle, $false, $cancellationToken))

    if ($writtenCount -ne $payloadBytes.Length) {
        throw "The OpenCIFS client wrote an unexpected byte count."
    }

    if ([System.Text.Encoding]::UTF8.GetString($roundTripBytes) -ne $payloadText) {
        throw "The OpenCIFS client read back unexpected file contents from Samba."
    }

    if ([uint64]$standardInfo.EndOfFile -ne [uint64]$payloadBytes.Length) {
        throw "The OpenCIFS client metadata query returned an unexpected end-of-file size from Samba."
    }

    if (-not $lockConflictRejected) {
        throw "The OpenCIFS client did not observe the expected conflicting lock rejection from Samba."
    }

    if (-not ($directoryEntryNames -contains $renamedFileName)) {
        throw "The OpenCIFS client directory enumeration did not return the renamed Samba file."
    }

    $summary = [ordered]@{
        server = $Server
        port = $Port
        share = $Share
        dialect = $firstClient.Session.NegotiatedDialect.ToString()
        directory = $directoryName
        file = $fileName
        renamed_file = $renamedFileName
        bytes_written = $writtenCount
        initial_end_of_file = [uint64]$standardInfo.EndOfFile
        directory_entries_after_rename = $directoryEntryNames
        conflicting_lock_rejected = $lockConflictRejected
        signing_required = $firstClient.Session.IsSigningRequired
    }

    $json = $summary | ConvertTo-Json -Depth 5

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        Set-Content -Path $OutputPath -Value $json
    }

    Write-Output $json
}
finally {
    Close-TrackedOpen -Client $firstClient -OpenHandle $deleteDirectoryHandle
    Close-TrackedOpen -Client $firstClient -OpenHandle $deleteFileHandle
    Close-TrackedOpen -Client $firstClient -OpenHandle $queryHandle
    Close-TrackedOpen -Client $firstClient -OpenHandle $renameHandle
    Close-TrackedOpen -Client $secondClient -OpenHandle $secondFileHandle
    Close-TrackedOpen -Client $firstClient -OpenHandle $firstFileHandle
    Close-TrackedOpen -Client $firstClient -OpenHandle $directoryHandle
    Disconnect-TrackedTree -Client $secondClient -TreeHandle $secondTree
    Disconnect-TrackedTree -Client $firstClient -TreeHandle $firstTree

    try {
        $firstClient.Dispose()
    }
    catch {
    }

    try {
        $secondClient.Dispose()
    }
    catch {
    }
}

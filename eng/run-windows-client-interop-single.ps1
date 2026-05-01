param(
    [string]$Configuration = "Debug",
    [string]$Framework = "net8.0",
    [int]$Port = 0,
    [string]$DriveLetter = "Z:",
    [string]$Dialect = "Smb21",
    [string]$ArtifactSubdirectory = "",
    [string]$RemoteHost = "localhost",
    [string]$ShareName = "share",
    [int]$LargePayloadLength = 200000
)

$ErrorActionPreference = "Stop"

if ($LargePayloadLength -lt 65536) {
    throw "LargePayloadLength must be at least 65536 bytes so the deeper Windows interop path exercises bounded large-I/O behavior."
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $repositoryRoot "artifacts\windows-client-interop"

if (-not [string]::IsNullOrWhiteSpace($ArtifactSubdirectory)) {
    $artifactRoot = Join-Path $artifactRoot $ArtifactSubdirectory
}
$shareRoot = Join-Path $artifactRoot "share"
$printedConfigurationPath = Join-Path $artifactRoot "sample-server.config.txt"
$environmentPath = Join-Path $artifactRoot "windows-client-environment.json"
$serverLogPath = Join-Path $artifactRoot "sample-server.log"
$serverErrorPath = Join-Path $artifactRoot "sample-server.err.log"
$workflowPath = Join-Path $artifactRoot "windows-client-smoke.json"
$projectPath = Join-Path $repositoryRoot "src\Sample.OpenCifsServer\Sample.OpenCifsServer.csproj"
$normalizedDriveLetter = $DriveLetter.TrimEnd('\')
$mappedRoot = $normalizedDriveLetter + "\"
$normalizedRemoteHost = $RemoteHost.Trim()
$normalizedShareName = $ShareName.Trim()

if ([string]::IsNullOrWhiteSpace($normalizedShareName)) {
    throw "ShareName cannot be empty."
}

$remoteSharePath = "\\{0}\{1}" -f $normalizedRemoteHost, $normalizedShareName
$sampleDirectoryPath = $mappedRoot + "native-dir"
$sampleNestedDirectoryPath = $sampleDirectoryPath + "\nested"
$sampleFilePath = $sampleDirectoryPath + "\native.txt"
$sampleNestedWatcherFilePath = $sampleNestedDirectoryPath + "\watch-created.txt"
$sampleRenamedFilePath = $sampleDirectoryPath + "\native-renamed.txt"
$sampleLargeFilePath = $sampleDirectoryPath + "\large.bin"
$sampleRenamedDirectoryPath = $mappedRoot + "native-dir-renamed"
$sampleRenamedNestedDirectoryPath = $sampleRenamedDirectoryPath + "\nested"
$sampleRenamedFileInRenamedDirectoryPath = $sampleRenamedDirectoryPath + "\native-renamed.txt"
$samplePayload = "native-windows-smoke"
$truncatedPayload = $samplePayload.Substring(0, 6)
$largePayloadBytes = New-Object byte[] $LargePayloadLength
for ($index = 0; $index -lt $largePayloadBytes.Length; $index++) {
    $largePayloadBytes[$index] = [byte](65 + ($index % 23))
}
$largePayloadHasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $largePayloadHash = [System.BitConverter]::ToString($largePayloadHasher.ComputeHash($largePayloadBytes)).Replace("-", "")
}
finally {
    $largePayloadHasher.Dispose()
}
$requestedPort = $Port

switch ($Dialect) {
    "Smb2002" {
        $dialectId = "smb2002"
        $dialectLabel = "SMB 2.0.2"
        $requirePrivacy = $false
    }
    "Smb21" {
        $dialectId = "smb21"
        $dialectLabel = "SMB 2.1"
        $requirePrivacy = $false
    }
    "Smb302" {
        $dialectId = "smb302"
        $dialectLabel = "SMB 3.0.2"
        $requirePrivacy = $true
    }
    default {
        throw "Unsupported dialect '$Dialect'."
    }
}

function Resolve-AvailableTcpPort {
    param(
        [int]$PreferredPort,
        [int]$MaximumAttempts = 32
    )

    if ($PreferredPort -le 0) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)

        try {
            $listener.Start()
            return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        }
        finally {
            $listener.Stop()
        }
    }

    for ($offset = 0; $offset -lt $MaximumAttempts; $offset++) {
        $candidatePort = $PreferredPort + $offset
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $candidatePort)

        try {
            $listener.Start()
            return $candidatePort
        }
        catch [System.Net.Sockets.SocketException] {
        }
        finally {
            if ($null -ne $listener.Server) {
                $listener.Stop()
            }
        }
    }

    throw "Could not find an available loopback TCP port after trying $MaximumAttempts port(s) starting at $PreferredPort."
}

function Assert-LastExitCode {
    param([string]$Message)

    if ($LASTEXITCODE -ne 0) {
        throw $Message
    }
}

function Remove-TestMapping {
    Remove-SmbMapping -LocalPath $normalizedDriveLetter -Force -UpdateProfile -ErrorAction SilentlyContinue
}

function Remove-RemoteShareConnection {
    param([string]$RemotePath)

    try {
        Remove-SmbMapping -RemotePath $RemotePath -Force -UpdateProfile -ErrorAction SilentlyContinue
    }
    catch {
    }

    cmd /c ("net use `"{0}`" /delete /y >nul 2>nul" -f $RemotePath) | Out-Null
}

function Stop-StaleSampleServerProcesses {
    param(
        [string]$ProjectPath,
        [int[]]$ExcludeProcessIds = @()
    )

    $staleProcesses = Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -eq "dotnet.exe" -and
            $null -ne $_.CommandLine -and
            $_.CommandLine -like ("*" + $ProjectPath + "*") -and
            $ExcludeProcessIds -notcontains [int]$_.ProcessId
        } |
        Select-Object -ExpandProperty ProcessId

    foreach ($processId in $staleProcesses) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $processId -ErrorAction SilentlyContinue
    }
}

function New-TestMapping {
    param(
        [string]$LocalPath,
        [string]$RemotePath,
        [int]$TcpPort,
        [string]$UserName,
        [string]$Password,
        [bool]$RequirePrivacy,
        [int]$MaximumAttempts = 45
    )

    $lastErrorMessage = $null

    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        try {
            Remove-SmbMapping -LocalPath $LocalPath -Force -UpdateProfile -ErrorAction SilentlyContinue

            return New-SmbMapping `
                -LocalPath $LocalPath `
                -RemotePath $RemotePath `
                -TransportType TCP `
                -TcpPort $TcpPort `
                -UserName $UserName `
                -Password $Password `
                -RequirePrivacy $RequirePrivacy `
                -ErrorAction Stop
        }
        catch {
            $lastErrorMessage = $_.Exception.Message
            Start-Sleep -Milliseconds 1000
        }
    }

    throw $lastErrorMessage
}

function Wait-ServerReady {
    param(
        [System.Diagnostics.Process]$Process,
        [int]$TcpPort
    )

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        Start-Sleep -Milliseconds 500

        if ($Process.HasExited) {
            throw "Sample.OpenCifsServer exited before the port opened. See $serverLogPath and $serverErrorPath."
        }

        $tcpClient = [System.Net.Sockets.TcpClient]::new()

        try {
            $tcpClient.Connect("127.0.0.1", $TcpPort)
            return
        }
        catch {
        }
        finally {
            $tcpClient.Dispose()
        }
    }

    throw "Timed out waiting for Sample.OpenCifsServer to open 127.0.0.1:$TcpPort."
}

function Invoke-CmdStep {
    param(
        [int]$Index,
        [string]$Name,
        [string]$Command,
        [int]$TimeoutSeconds = 30
    )

    $stdoutPath = Join-Path $artifactRoot ("step-{0:D2}.out.txt" -f $Index)
    $stderrPath = Join-Path $artifactRoot ("step-{0:D2}.err.txt" -f $Index)

    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.FileName = "cmd.exe"
    $processStartInfo.Arguments = "/c $Command"
    $processStartInfo.UseShellExecute = $false
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.RedirectStandardError = $true
    $processStartInfo.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $null = $process.Start()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)

    if ($timedOut) {
        try {
            $process.Kill($true)
        }
        catch {
        }
    }

    $process.WaitForExit()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()

    Set-Content -Path $stdoutPath -Value $stdout -NoNewline
    Set-Content -Path $stderrPath -Value $stderr -NoNewline

    return [pscustomobject]@{
        index = $Index
        name = $Name
        shell = "cmd"
        command = $Command
        exit_code = $process.ExitCode
        timed_out = $timedOut
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        stdout = $stdout
        stderr = $stderr
    }
}

function Invoke-PowerShellStep {
    param(
        [int]$Index,
        [string]$Name,
        [string]$Command,
        [int]$TimeoutSeconds = 30
    )

    $stdoutPath = Join-Path $artifactRoot ("step-{0:D2}.out.txt" -f $Index)
    $stderrPath = Join-Path $artifactRoot ("step-{0:D2}.err.txt" -f $Index)

    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.FileName = "powershell.exe"
    $processStartInfo.Arguments = "-NoProfile -NonInteractive -Command `$ErrorActionPreference = 'Stop'; $Command"
    $processStartInfo.UseShellExecute = $false
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.RedirectStandardError = $true
    $processStartInfo.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $null = $process.Start()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)

    if ($timedOut) {
        try {
            $process.Kill($true)
        }
        catch {
        }
    }

    $process.WaitForExit()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()

    Set-Content -Path $stdoutPath -Value $stdout -NoNewline
    Set-Content -Path $stderrPath -Value $stderr -NoNewline

    return [pscustomobject]@{
        index = $Index
        name = $Name
        shell = "powershell"
        command = $Command
        exit_code = $process.ExitCode
        timed_out = $timedOut
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        stdout = $stdout
        stderr = $stderr
    }
}

function Invoke-FileSystemWatcherStep {
    param(
        [int]$Index,
        [string]$Name,
        [string]$WatchPath,
        [string]$EventName,
        [scriptblock]$Action,
        [bool]$IncludeSubdirectories = $false,
        [string[]]$NotifyFilters = @("FileName"),
        [int]$TimeoutSeconds = 5,
        [bool]$RequireEvent = $true
    )

    $stdoutPath = Join-Path $artifactRoot ("step-{0:D2}.out.txt" -f $Index)
    $stderrPath = Join-Path $artifactRoot ("step-{0:D2}.err.txt" -f $Index)
    $stdoutBuilder = [System.Text.StringBuilder]::new()
    $stderrBuilder = [System.Text.StringBuilder]::new()
    $sourceIdentifier = "OpenCifsWatcher_{0}_{1}" -f $Index, ([Guid]::NewGuid().ToString("N"))
    $watcher = $null
    $watcherJob = $null
    $eventRecord = $null
    $exitCode = 0

    try {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $WatchPath
        $watcher.Filter = "*"
        $watcher.IncludeSubdirectories = $IncludeSubdirectories

        if ($NotifyFilters.Count -gt 0) {
            $notifyFilter = [System.IO.NotifyFilters]0

            foreach ($notifyFilterName in $NotifyFilters) {
                $notifyFilter = $notifyFilter -bor [System.IO.NotifyFilters]::$notifyFilterName
            }

            $watcher.NotifyFilter = $notifyFilter
        }

        $watcher.EnableRaisingEvents = $true

        switch ($EventName) {
            "Created" {
                $watcherJob = Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier $sourceIdentifier
            }
            "Deleted" {
                $watcherJob = Register-ObjectEvent -InputObject $watcher -EventName Deleted -SourceIdentifier $sourceIdentifier
            }
            "Changed" {
                $watcherJob = Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier $sourceIdentifier
            }
            "Renamed" {
                $watcherJob = Register-ObjectEvent -InputObject $watcher -EventName Renamed -SourceIdentifier $sourceIdentifier
            }
            default {
                throw "Unsupported watcher event name '$EventName'."
            }
        }

        Start-Sleep -Milliseconds 200
        & $Action
        $eventRecord = Wait-Event -SourceIdentifier $sourceIdentifier -Timeout $TimeoutSeconds

        if ($null -eq $eventRecord) {
            $stdoutBuilder.AppendLine("TimedOut=True") | Out-Null

            if ($RequireEvent) {
                $stderrBuilder.Append("Timed out waiting for watcher event '$EventName'.") | Out-Null
                $exitCode = 1
            }
        }
        else {
            $stdoutBuilder.AppendLine("TimedOut=False") | Out-Null
            $eventArgs = $eventRecord.SourceEventArgs

            if ($eventArgs -is [System.IO.RenamedEventArgs]) {
                $stdoutBuilder.AppendLine("ChangeType=" + $eventArgs.ChangeType.ToString()) | Out-Null
                $stdoutBuilder.AppendLine("OldName=" + $eventArgs.OldName) | Out-Null
                $stdoutBuilder.AppendLine("Name=" + $eventArgs.Name) | Out-Null
            }
            elseif ($eventArgs -is [System.IO.FileSystemEventArgs]) {
                $stdoutBuilder.AppendLine("ChangeType=" + $eventArgs.ChangeType.ToString()) | Out-Null
                $stdoutBuilder.AppendLine("Name=" + $eventArgs.Name) | Out-Null
            }
            else {
                $stdoutBuilder.AppendLine("EventArgsType=" + $eventArgs.GetType().FullName) | Out-Null
            }

            if (-not $RequireEvent) {
                $stderrBuilder.Append("Received an unexpected watcher event '$EventName'.") | Out-Null
                $exitCode = 1
            }
        }
    }
    catch {
        $stderrBuilder.Append($_.Exception.ToString()) | Out-Null
        $exitCode = 1
    }
    finally {
        if ($null -ne $eventRecord) {
            Remove-Event -EventIdentifier $eventRecord.EventIdentifier -ErrorAction SilentlyContinue
        }

        if ($null -ne $watcherJob) {
            Unregister-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue
            Remove-Job -Id $watcherJob.Id -Force -ErrorAction SilentlyContinue
        }

        if ($null -ne $watcher) {
            $watcher.Dispose()
        }
    }

    $stdout = $stdoutBuilder.ToString()
    $stderr = $stderrBuilder.ToString()
    Set-Content -Path $stdoutPath -Value $stdout -NoNewline
    Set-Content -Path $stderrPath -Value $stderr -NoNewline

    return [pscustomobject]@{
        index = $Index
        name = $Name
        shell = "watcher"
        command = ("WatchPath={0}; EventName={1}; IncludeSubdirectories={2}; NotifyFilters={3}" -f $WatchPath, $EventName, $IncludeSubdirectories, ($NotifyFilters -join ","))
        exit_code = $exitCode
        timed_out = $false
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        stdout = $stdout
        stderr = $stderr
    }
}

function Test-PathSafe {
    param([string]$Path)

    try {
        $result = @(Test-Path -LiteralPath $Path -ErrorAction Stop)

        if ($result.Count -eq 0) {
            return $false
        }

        return [bool]$result[$result.Count - 1]
    }
    catch {
        return $false
    }
}

function Assert-StepSucceeded {
    param(
        [pscustomobject]$StepResult,
        [string]$ExpectedSubstring
    )

    if ($StepResult.timed_out) {
        throw "Timed out running Windows client step '$($StepResult.name)'."
    }

    if ($StepResult.exit_code -ne 0) {
        throw "Windows client step '$($StepResult.name)' failed with exit code $($StepResult.exit_code). See $($StepResult.stdout_path) and $($StepResult.stderr_path)."
    }

    if ($ExpectedSubstring.Length -ne 0 -and $StepResult.stdout.IndexOf($ExpectedSubstring, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Windows client step '$($StepResult.name)' did not contain the expected output fragment '$ExpectedSubstring'."
    }
}

function Assert-StepFailed {
    param([pscustomobject]$StepResult)

    if ($StepResult.timed_out) {
        throw "Timed out running Windows client negative step '$($StepResult.name)'."
    }

    if ($StepResult.exit_code -eq 0) {
        throw "Windows client negative step '$($StepResult.name)' unexpectedly succeeded."
    }
}

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
New-Item -ItemType Directory -Force -Path $shareRoot | Out-Null

if (Test-Path $shareRoot) {
    Get-ChildItem -Path $shareRoot -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

$Port = Resolve-AvailableTcpPort -PreferredPort $requestedPort
Stop-StaleSampleServerProcesses -ProjectPath $projectPath
Get-ChildItem -Path $artifactRoot -File -ErrorAction SilentlyContinue | Remove-Item -Force

$environment = Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture, CSName
$environment | ConvertTo-Json -Depth 4 | Set-Content -Path $environmentPath

$sampleServerArguments = @(
    "--server-name", $normalizedRemoteHost,
    "--bind-address", "127.0.0.1",
    "--bind-port", $Port.ToString(),
    "--share-name", $normalizedShareName,
    "--share-path", $shareRoot,
    "--minimum-dialect", $Dialect,
    "--maximum-dialect", $Dialect,
    "--require-signing", "true",
    "--require-ntlmv2", "true",
    "--allow-anonymous", "false",
    "--enable-smb1", "false",
    "--require-encryption-for-smb3", $requirePrivacy.ToString().ToLowerInvariant(),
    "--account-username", "alice",
    "--account-domain", "WORKGROUP",
    "--account-password", "Password123!"
)

$printArguments = @(
    "run",
    "--project", $projectPath,
    "--configuration", $Configuration,
    "--framework", $Framework,
    "--no-build",
    "--",
    "--print-config"
) + $sampleServerArguments

& dotnet $printArguments | Tee-Object -FilePath $printedConfigurationPath | Out-Null
Assert-LastExitCode "Failed to print the effective Sample.OpenCifsServer configuration."

$serverArguments = @(
    "run",
    "--project", $projectPath,
    "--configuration", $Configuration,
    "--framework", $Framework,
    "--no-build",
    "--"
) + $sampleServerArguments

$serverProcess = $null
$stepResults = New-Object System.Collections.Generic.List[object]
$mappingSnapshot = $null
$failureMessage = $null

try {
    Remove-TestMapping
    Remove-RemoteShareConnection -RemotePath ("\\127.0.0.1\{0}" -f $normalizedShareName)
    Remove-RemoteShareConnection -RemotePath ("\\localhost\{0}" -f $normalizedShareName)
    Remove-RemoteShareConnection -RemotePath $remoteSharePath

    $serverProcess = Start-Process `
        -FilePath "dotnet" `
        -ArgumentList $serverArguments `
        -WorkingDirectory $repositoryRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $serverLogPath `
        -RedirectStandardError $serverErrorPath `
        -PassThru

    Wait-ServerReady -Process $serverProcess -TcpPort $Port

    $null = New-TestMapping `
        -LocalPath $normalizedDriveLetter `
        -RemotePath $remoteSharePath `
        -TcpPort $Port `
        -UserName "WORKGROUP\alice" `
        -Password "Password123!" `
        -RequirePrivacy $requirePrivacy

    $mappingSnapshot = Get-SmbMapping -LocalPath $normalizedDriveLetter |
        Select-Object LocalPath, RemotePath, Status, TransportType, TcpPort

    $steps = @(
        @{ Name = "CreateDirectory"; Shell = "cmd"; Command = "mkdir $sampleDirectoryPath" },
        @{ Name = "CreateNestedDirectory"; Shell = "cmd"; Command = "mkdir $sampleNestedDirectoryPath" },
        @{
            Name = "WatcherRejectsNestedCreateWithoutSubtree"
            Kind = "watcher"
            WatchPath = $sampleDirectoryPath
            EventName = "Created"
            IncludeSubdirectories = $false
            NotifyFilters = @("FileName", "DirectoryName")
            RequireEvent = $false
            Action = {
                New-Item -ItemType File -Path $sampleNestedWatcherFilePath -Force | Out-Null
                Start-Sleep -Milliseconds 200
                Remove-Item -LiteralPath $sampleNestedWatcherFilePath -Force -ErrorAction Stop
            }
            Expected = "TimedOut=True"
        },
        @{
            Name = "WatcherSeesNestedCreateWithSubtree"
            Kind = "watcher"
            WatchPath = $sampleDirectoryPath
            EventName = "Created"
            IncludeSubdirectories = $true
            NotifyFilters = @("FileName", "DirectoryName")
            RequireEvent = $true
            Action = {
                New-Item -ItemType File -Path $sampleNestedWatcherFilePath -Force | Out-Null
                Start-Sleep -Milliseconds 200
                Remove-Item -LiteralPath $sampleNestedWatcherFilePath -Force -ErrorAction Stop
            }
            Expected = "Name=nested\watch-created.txt"
        },
        @{ Name = "WriteFile"; Shell = "cmd"; Command = "echo $samplePayload>$sampleFilePath" },
        @{ Name = "ReadFile"; Shell = "cmd"; Command = "type $sampleFilePath"; Expected = $samplePayload },
        @{ Name = "SetHiddenAttribute"; Shell = "cmd"; Command = "attrib +h $sampleFilePath" },
        @{ Name = "QueryHiddenMetadata"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$sampleFilePath' -Force; Write-Output ('Attributes=' + `$item.Attributes); Write-Output ('Length=' + `$item.Length) }"; Expected = "Hidden" },
        @{ Name = "TruncateFile"; Shell = "powershell"; Command = "& { `$stream = [System.IO.File]::Open('$sampleFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite); try { `$stream.SetLength(6) } finally { `$stream.Dispose() }; Write-Output ('Length=' + (Get-Item -LiteralPath '$sampleFilePath' -Force).Length) }"; Expected = "Length=6" },
        @{ Name = "ReadTruncatedFile"; Shell = "cmd"; Command = "type $sampleFilePath"; Expected = $truncatedPayload },
        @{
            Name = "WriteLargeFile"
            Shell = "powershell"
            Command = "& { `$bytes = New-Object byte[] $largePayloadLength; for (`$i = 0; `$i -lt `$bytes.Length; `$i++) { `$bytes[`$i] = [byte](65 + (`$i % 23)) }; [System.IO.File]::WriteAllBytes('$sampleLargeFilePath', `$bytes); `$item = Get-Item -LiteralPath '$sampleLargeFilePath' -Force; Write-Output ('Length=' + `$item.Length) }"
            Expected = "Length=$largePayloadLength"
        },
        @{
            Name = "ReadLargeFile"
            Shell = "powershell"
            Command = "& { `$bytes = [System.IO.File]::ReadAllBytes('$sampleLargeFilePath'); `$hasher = [System.Security.Cryptography.SHA256]::Create(); try { `$hash = [System.BitConverter]::ToString(`$hasher.ComputeHash(`$bytes)).Replace('-', '') } finally { `$hasher.Dispose() }; Write-Output ('Length=' + `$bytes.Length); Write-Output ('Hash=' + `$hash) }"
            Expected = "Hash=$largePayloadHash"
        },
        @{ Name = "DeleteLargeFile"; Shell = "powershell"; Command = "& { Remove-Item -LiteralPath '$sampleLargeFilePath' -Force -ErrorAction Stop }" },
        @{
            Name = "WatcherSeesRenameFile"
            Kind = "watcher"
            WatchPath = $sampleDirectoryPath
            EventName = "Renamed"
            IncludeSubdirectories = $false
            NotifyFilters = @("FileName")
            RequireEvent = $true
            Action = {
                Rename-Item -LiteralPath $sampleFilePath -NewName "native-renamed.txt"
            }
            Expected = "Name=native-renamed.txt"
        },
        @{ Name = "DeleteNonEmptyDirectoryRejected"; Shell = "cmd"; Command = "rmdir $sampleDirectoryPath"; ShouldFail = $true },
        @{ Name = "EnumerateDirectoryBeforeDirectoryRename"; Shell = "cmd"; Command = "dir /a $sampleDirectoryPath"; Expected = "native-renamed.txt" },
        @{ Name = "SetReadOnlyAttribute"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$sampleRenamedFilePath' -Force; `$item.IsReadOnly = `$true }" },
        @{ Name = "DeleteReadOnlyFileRejected"; Shell = "powershell"; Command = "& { Remove-Item -LiteralPath '$sampleRenamedFilePath' -ErrorAction Stop }"; ShouldFail = $true },
        @{ Name = "QueryReadOnlyMetadata"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$sampleRenamedFilePath' -Force; Write-Output ('Attributes=' + `$item.Attributes); Write-Output ('Length=' + `$item.Length) }"; Expected = "ReadOnly" },
        @{ Name = "ClearReadOnlyAttribute"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$sampleRenamedFilePath' -Force; `$item.IsReadOnly = `$false }" },
        @{ Name = "ShareAccessConflictRejected"; Shell = "powershell"; Command = "& { `$first = [System.IO.File]::Open('$sampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read); try { `$rejected = `$false; try { `$second = [System.IO.File]::Open('$sampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None); `$second.Dispose() } catch [System.IO.IOException] { `$rejected = `$true }; if (-not `$rejected) { throw 'Expected a share-access conflict for the second open.' }; Write-Output 'Rejected=True' } finally { `$first.Dispose() } }"; Expected = "Rejected=True" },
        @{ Name = "ByteRangeLockConflictRejected"; Shell = "powershell"; Command = "& { `$first = [System.IO.File]::Open('$sampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite); `$second = [System.IO.File]::Open('$sampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite); try { `$first.Lock(0, 1); `$rejected = `$false; try { `$second.Lock(0, 1) } catch [System.IO.IOException] { `$rejected = `$true }; if (-not `$rejected) { throw 'Expected a byte-range lock conflict for the second lock.' }; Write-Output 'Rejected=True' } finally { try { `$second.Unlock(0, 1) } catch { }; `$second.Dispose(); try { `$first.Unlock(0, 1) } catch { }; `$first.Dispose() } }"; Expected = "Rejected=True" },
        @{ Name = "RenameDirectory"; Shell = "powershell"; Command = "& { Rename-Item -LiteralPath '$sampleDirectoryPath' -NewName 'native-dir-renamed' }" },
        @{ Name = "EnumerateRenamedDirectory"; Shell = "cmd"; Command = "dir /a $sampleRenamedDirectoryPath"; Expected = "native-renamed.txt" },
        @{ Name = "DeleteFile"; Shell = "powershell"; Command = "& { Remove-Item -LiteralPath '$sampleRenamedFileInRenamedDirectoryPath' -Force -ErrorAction Stop }" },
        @{ Name = "DeleteNestedDirectory"; Shell = "cmd"; Command = "rmdir $sampleRenamedNestedDirectoryPath" },
        @{ Name = "DeleteDirectory"; Shell = "cmd"; Command = "rmdir $sampleRenamedDirectoryPath" }
    )

    for ($index = 0; $index -lt $steps.Length; $index++) {
        $step = $steps[$index]
        $result = if ($step.Kind -eq "watcher") {
            Invoke-FileSystemWatcherStep `
                -Index $index `
                -Name $step.Name `
                -WatchPath $step.WatchPath `
                -EventName $step.EventName `
                -Action $step.Action `
                -IncludeSubdirectories ([bool]$step.IncludeSubdirectories) `
                -NotifyFilters $step.NotifyFilters `
                -TimeoutSeconds ($(if ($null -ne $step.TimeoutSeconds) { [int]$step.TimeoutSeconds } else { 5 })) `
                -RequireEvent ([bool]$step.RequireEvent)
        }
        elseif ($step.Shell -eq "powershell") {
            Invoke-PowerShellStep -Index $index -Name $step.Name -Command $step.Command
        }
        else {
            Invoke-CmdStep -Index $index -Name $step.Name -Command $step.Command
        }
        $stepResults.Add($result)

        if ($step.ShouldFail) {
            Assert-StepFailed -StepResult $result
        }
        else {
            $expectedSubstring = if ($null -ne $step.Expected) { [string]$step.Expected } else { [string]::Empty }
            Assert-StepSucceeded -StepResult $result -ExpectedSubstring $expectedSubstring
        }
    }

    if (Test-PathSafe $sampleDirectoryPath) {
        throw "The Windows client workflow completed but '$sampleDirectoryPath' still exists."
    }

    if (Test-PathSafe $sampleRenamedDirectoryPath) {
        throw "The Windows client workflow completed but '$sampleRenamedDirectoryPath' still exists."
    }

    if (Test-PathSafe (Join-Path $shareRoot "native-dir")) {
        throw "The Windows client workflow completed but the backing native-dir still exists under $shareRoot."
    }

    if (Test-PathSafe (Join-Path $shareRoot "native-dir-renamed")) {
        throw "The Windows client workflow completed but the backing native-dir-renamed still exists under $shareRoot."
    }
}
catch {
    $failureMessage = $_.Exception.Message
}
finally {
    $shareDirectoryPath = Join-Path $shareRoot "native-dir"
    try {
        [pscustomobject]@{
            dialect = $dialectLabel
            dialect_id = $dialectId
            requested_port = $requestedPort
            effective_port = $Port
            share_name = $normalizedShareName
            drive_letter = $normalizedDriveLetter
            large_payload_length = $largePayloadLength
            large_payload_hash = $largePayloadHash
            mapping = $mappingSnapshot
            environment = $environment
                        steps = $stepResults
                        final_state = [pscustomobject]@{
                mapped_directory_exists = (Test-PathSafe $sampleDirectoryPath) -or (Test-PathSafe $sampleRenamedDirectoryPath)
                mapped_file_exists = (Test-PathSafe $sampleRenamedFilePath) -or (Test-PathSafe $sampleRenamedFileInRenamedDirectoryPath)
                backing_directory_exists = (Test-PathSafe $shareDirectoryPath) -or (Test-PathSafe (Join-Path $shareRoot "native-dir-renamed"))
                failure = $failureMessage
            }
        } | ConvertTo-Json -Depth 8 | Set-Content -Path $workflowPath
    }
    catch {
        [pscustomobject]@{
            dialect = $dialectLabel
            dialect_id = $dialectId
            requested_port = $requestedPort
            effective_port = $Port
            share_name = $normalizedShareName
            drive_letter = $normalizedDriveLetter
            large_payload_length = $largePayloadLength
            large_payload_hash = $largePayloadHash
            failure = $failureMessage
            workflow_write_error = $_.Exception.ToString()
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $workflowPath
    }

    Remove-RemoteShareConnection -RemotePath ("\\127.0.0.1\{0}" -f $normalizedShareName)
    Remove-RemoteShareConnection -RemotePath ("\\localhost\{0}" -f $normalizedShareName)
    Remove-RemoteShareConnection -RemotePath $remoteSharePath
    Remove-TestMapping

    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force
        $serverProcess.WaitForExit()
    }
}

if ($failureMessage -ne $null) {
    [Console]::Error.WriteLine($failureMessage)
    exit 1
}

Write-Host "Windows SMB client interop smoke completed. Evidence:"
Write-Host "  $workflowPath"
Write-Host "  $environmentPath"
Write-Host "  $printedConfigurationPath"
Write-Host "  $serverLogPath"
Write-Host "  $serverErrorPath"

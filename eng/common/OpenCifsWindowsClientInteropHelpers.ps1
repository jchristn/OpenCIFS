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
    param([string]$LocalPath)

    Remove-SmbMapping -LocalPath $LocalPath -Force -UpdateProfile -ErrorAction SilentlyContinue
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
        [int]$TcpPort,
        [string]$ServerLogPath,
        [string]$ServerErrorPath
    )

    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        Start-Sleep -Milliseconds 500

        if ($Process.HasExited) {
            throw "Sample.OpenCifsServer exited before the port opened. See $ServerLogPath and $ServerErrorPath."
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

function Invoke-ProcessStep {
    param(
        [int]$Index,
        [string]$Name,
        [string]$ArtifactRoot,
        [string]$FileName,
        [string]$Arguments,
        [string]$Shell,
        [int]$TimeoutSeconds = 30
    )

    $stdoutPath = Join-Path $ArtifactRoot ("step-{0:D2}.out.txt" -f $Index)
    $stderrPath = Join-Path $ArtifactRoot ("step-{0:D2}.err.txt" -f $Index)
    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.FileName = $FileName
    $processStartInfo.Arguments = $Arguments
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
        shell = $Shell
        command = $Arguments
        exit_code = $process.ExitCode
        timed_out = $timedOut
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        stdout = $stdout
        stderr = $stderr
    }
}

function Invoke-CmdStep {
    param(
        [int]$Index,
        [string]$Name,
        [string]$ArtifactRoot,
        [string]$Command,
        [int]$TimeoutSeconds = 30
    )

    return Invoke-ProcessStep `
        -Index $Index `
        -Name $Name `
        -ArtifactRoot $ArtifactRoot `
        -FileName "cmd.exe" `
        -Arguments "/c $Command" `
        -Shell "cmd" `
        -TimeoutSeconds $TimeoutSeconds
}

function Invoke-PowerShellStep {
    param(
        [int]$Index,
        [string]$Name,
        [string]$ArtifactRoot,
        [string]$Command,
        [int]$TimeoutSeconds = 30
    )

    return Invoke-ProcessStep `
        -Index $Index `
        -Name $Name `
        -ArtifactRoot $ArtifactRoot `
        -FileName "powershell.exe" `
        -Arguments "-NoProfile -NonInteractive -Command `$ErrorActionPreference = 'Stop'; $Command" `
        -Shell "powershell" `
        -TimeoutSeconds $TimeoutSeconds
}

function Invoke-FileSystemWatcherStep {
    param(
        [int]$Index,
        [string]$Name,
        [string]$ArtifactRoot,
        [string]$WatchPath,
        [string]$EventName,
        [scriptblock]$Action,
        [bool]$IncludeSubdirectories = $false,
        [string[]]$NotifyFilters = @("FileName"),
        [int]$TimeoutSeconds = 5,
        [bool]$RequireEvent = $true
    )

    $stdoutPath = Join-Path $ArtifactRoot ("step-{0:D2}.out.txt" -f $Index)
    $stderrPath = Join-Path $ArtifactRoot ("step-{0:D2}.err.txt" -f $Index)
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

function Invoke-WindowsClientInteropStep {
    param(
        [int]$Index,
        [hashtable]$Step,
        [string]$ArtifactRoot
    )

    if ($Step.Kind -eq "watcher") {
        return Invoke-FileSystemWatcherStep `
            -Index $Index `
            -Name $Step.Name `
            -ArtifactRoot $ArtifactRoot `
            -WatchPath $Step.WatchPath `
            -EventName $Step.EventName `
            -Action $Step.Action `
            -IncludeSubdirectories ([bool]$Step.IncludeSubdirectories) `
            -NotifyFilters $Step.NotifyFilters `
            -TimeoutSeconds ($(if ($null -ne $Step.TimeoutSeconds) { [int]$Step.TimeoutSeconds } else { 5 })) `
            -RequireEvent ([bool]$Step.RequireEvent)
    }

    if ($Step.Shell -eq "powershell") {
        return Invoke-PowerShellStep `
            -Index $Index `
            -Name $Step.Name `
            -ArtifactRoot $ArtifactRoot `
            -Command $Step.Command `
            -TimeoutSeconds ($(if ($null -ne $Step.TimeoutSeconds) { [int]$Step.TimeoutSeconds } else { 30 }))
    }

    return Invoke-CmdStep `
        -Index $Index `
        -Name $Step.Name `
        -ArtifactRoot $ArtifactRoot `
        -Command $Step.Command `
        -TimeoutSeconds ($(if ($null -ne $Step.TimeoutSeconds) { [int]$Step.TimeoutSeconds } else { 30 }))
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

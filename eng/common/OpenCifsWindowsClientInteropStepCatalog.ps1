function New-WindowsClientInteropStepCatalog {
    param(
        [string]$SampleDirectoryPath,
        [string]$SampleNestedDirectoryPath,
        [string]$SampleFilePath,
        [string]$SampleNestedWatcherFilePath,
        [string]$SampleRenamedFilePath,
        [string]$SampleLargeFilePath,
        [string]$SampleRenamedDirectoryPath,
        [string]$SampleRenamedNestedDirectoryPath,
        [string]$SampleRenamedFileInRenamedDirectoryPath,
        [string]$SamplePayload,
        [string]$TruncatedPayload,
        [int]$LargePayloadLength,
        [string]$LargePayloadHash
    )

    $createAndDeleteNestedWatcherFile = {
        New-Item -ItemType File -Path $SampleNestedWatcherFilePath -Force | Out-Null
        Start-Sleep -Milliseconds 200
        Remove-Item -LiteralPath $SampleNestedWatcherFilePath -Force -ErrorAction Stop
    }.GetNewClosure()

    $renameFileAction = {
        Rename-Item -LiteralPath $SampleFilePath -NewName "native-renamed.txt"
    }.GetNewClosure()

    return @(
        @{ Name = "CreateDirectory"; Shell = "cmd"; Command = "mkdir $SampleDirectoryPath" },
        @{ Name = "CreateNestedDirectory"; Shell = "cmd"; Command = "mkdir $SampleNestedDirectoryPath" },
        @{
            Name = "WatcherRejectsNestedCreateWithoutSubtree"
            Kind = "watcher"
            WatchPath = $SampleDirectoryPath
            EventName = "Created"
            IncludeSubdirectories = $false
            NotifyFilters = @("FileName", "DirectoryName")
            RequireEvent = $false
            Action = $createAndDeleteNestedWatcherFile
            Expected = "TimedOut=True"
        },
        @{
            Name = "WatcherSeesNestedCreateWithSubtree"
            Kind = "watcher"
            WatchPath = $SampleDirectoryPath
            EventName = "Created"
            IncludeSubdirectories = $true
            NotifyFilters = @("FileName", "DirectoryName")
            RequireEvent = $true
            Action = $createAndDeleteNestedWatcherFile
            Expected = "Name=nested\watch-created.txt"
        },
        @{ Name = "WriteFile"; Shell = "cmd"; Command = "echo $SamplePayload>$SampleFilePath" },
        @{ Name = "ReadFile"; Shell = "cmd"; Command = "type $SampleFilePath"; Expected = $SamplePayload },
        @{ Name = "SetHiddenAttribute"; Shell = "cmd"; Command = "attrib +h $SampleFilePath" },
        @{ Name = "QueryHiddenMetadata"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$SampleFilePath' -Force; Write-Output ('Attributes=' + `$item.Attributes); Write-Output ('Length=' + `$item.Length) }"; Expected = "Hidden" },
        @{ Name = "TruncateFile"; Shell = "powershell"; Command = "& { `$stream = [System.IO.File]::Open('$SampleFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite); try { `$stream.SetLength(6) } finally { `$stream.Dispose() }; Write-Output ('Length=' + (Get-Item -LiteralPath '$SampleFilePath' -Force).Length) }"; Expected = "Length=6" },
        @{ Name = "ReadTruncatedFile"; Shell = "cmd"; Command = "type $SampleFilePath"; Expected = $TruncatedPayload },
        @{
            Name = "WriteLargeFile"
            Shell = "powershell"
            Command = "& { `$bytes = New-Object byte[] $LargePayloadLength; for (`$i = 0; `$i -lt `$bytes.Length; `$i++) { `$bytes[`$i] = [byte](65 + (`$i % 23)) }; [System.IO.File]::WriteAllBytes('$SampleLargeFilePath', `$bytes); `$item = Get-Item -LiteralPath '$SampleLargeFilePath' -Force; Write-Output ('Length=' + `$item.Length) }"
            Expected = "Length=$LargePayloadLength"
        },
        @{
            Name = "ReadLargeFile"
            Shell = "powershell"
            Command = "& { `$bytes = [System.IO.File]::ReadAllBytes('$SampleLargeFilePath'); `$hasher = [System.Security.Cryptography.SHA256]::Create(); try { `$hash = [System.BitConverter]::ToString(`$hasher.ComputeHash(`$bytes)).Replace('-', '') } finally { `$hasher.Dispose() }; Write-Output ('Length=' + `$bytes.Length); Write-Output ('Hash=' + `$hash) }"
            Expected = "Hash=$LargePayloadHash"
        },
        @{ Name = "DeleteLargeFile"; Shell = "powershell"; Command = "& { Remove-Item -LiteralPath '$SampleLargeFilePath' -Force -ErrorAction Stop }" },
        @{
            Name = "WatcherSeesRenameFile"
            Kind = "watcher"
            WatchPath = $SampleDirectoryPath
            EventName = "Renamed"
            IncludeSubdirectories = $false
            NotifyFilters = @("FileName")
            RequireEvent = $true
            Action = $renameFileAction
            Expected = "Name=native-renamed.txt"
        },
        @{ Name = "DeleteNonEmptyDirectoryRejected"; Shell = "cmd"; Command = "rmdir $SampleDirectoryPath"; ShouldFail = $true },
        @{ Name = "EnumerateDirectoryBeforeDirectoryRename"; Shell = "cmd"; Command = "dir /a $SampleDirectoryPath"; Expected = "native-renamed.txt" },
        @{ Name = "SetReadOnlyAttribute"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$SampleRenamedFilePath' -Force; `$item.IsReadOnly = `$true }" },
        @{ Name = "DeleteReadOnlyFileRejected"; Shell = "powershell"; Command = "& { Remove-Item -LiteralPath '$SampleRenamedFilePath' -ErrorAction Stop }"; ShouldFail = $true },
        @{ Name = "QueryReadOnlyMetadata"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$SampleRenamedFilePath' -Force; Write-Output ('Attributes=' + `$item.Attributes); Write-Output ('Length=' + `$item.Length) }"; Expected = "ReadOnly" },
        @{ Name = "ClearReadOnlyAttribute"; Shell = "powershell"; Command = "& { `$item = Get-Item -LiteralPath '$SampleRenamedFilePath' -Force; `$item.IsReadOnly = `$false }" },
        @{ Name = "ShareAccessConflictRejected"; Shell = "powershell"; Command = "& { `$first = [System.IO.File]::Open('$SampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read); try { `$rejected = `$false; try { `$second = [System.IO.File]::Open('$SampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None); `$second.Dispose() } catch [System.IO.IOException] { `$rejected = `$true }; if (-not `$rejected) { throw 'Expected a share-access conflict for the second open.' }; Write-Output 'Rejected=True' } finally { `$first.Dispose() } }"; Expected = "Rejected=True" },
        @{ Name = "ByteRangeLockConflictRejected"; Shell = "powershell"; Command = "& { `$first = [System.IO.File]::Open('$SampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite); `$second = [System.IO.File]::Open('$SampleRenamedFilePath', [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite); try { `$first.Lock(0, 1); `$rejected = `$false; try { `$second.Lock(0, 1) } catch [System.IO.IOException] { `$rejected = `$true }; if (-not `$rejected) { throw 'Expected a byte-range lock conflict for the second lock.' }; Write-Output 'Rejected=True' } finally { try { `$second.Unlock(0, 1) } catch { }; `$second.Dispose(); try { `$first.Unlock(0, 1) } catch { }; `$first.Dispose() } }"; Expected = "Rejected=True" },
        @{
            Name = "RenameDirectory"
            Shell = "powershell"
            Command = "& { Rename-Item -LiteralPath '$SampleDirectoryPath' -NewName 'native-dir-renamed' }"
        },
        @{ Name = "EnumerateRenamedDirectory"; Shell = "cmd"; Command = "dir /a $SampleRenamedDirectoryPath"; Expected = "native-renamed.txt" },
        @{ Name = "DeleteFile"; Shell = "powershell"; Command = "& { Remove-Item -LiteralPath '$SampleRenamedFileInRenamedDirectoryPath' -Force -ErrorAction Stop }" },
        @{ Name = "DeleteNestedDirectory"; Shell = "cmd"; Command = "rmdir $SampleRenamedNestedDirectoryPath" },
        @{ Name = "DeleteDirectory"; Shell = "cmd"; Command = "rmdir $SampleRenamedDirectoryPath" }
    )
}

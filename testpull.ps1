# Check if running with elevated privileges at the start
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isElevated) {
    # Get the current script path
    $scriptPath = $MyInvocation.MyCommand.Path
    
    # Start a new elevated process
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Wait
        exit
    }
    catch {
        Write-Error "Failed to elevate privileges: $_"
        exit 1
    }
}

# Get the script's directory (where NetFxRepairTool.exe should be)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$netFxRepairTool = Join-Path -Path $scriptDir -ChildPath "NetFxRepairTool.exe"

# Prompt user to select repair tools with explanation
Write-Host ""
Write-Host "Please select repair tools to run by entering numbers (e.g., '1', '2,3', 'all' for all tools). Leave blank to skip all."
Write-Host ""
Write-Host "1. Microsoft .NET Framework Repair Tool"
Write-Host "2. System File Checker (SFC)"
Write-Host "3. DISM (Restore Health)"
Write-Host ""
Write-Host -NoNewline "Selection: "
$choices = Read-Host

# Parse user input
$selectedOptions = @()
if ($choices -eq "all") {
    $selectedOptions = 1..3
} else {
    $choices.Split(',') | ForEach-Object {
        $trimmed = $_.Trim()
        if ($trimmed -match '^[1-3]$') {
            $selectedOptions += [int]$trimmed
        } else {
            Write-Warning "Invalid option '$trimmed' ignored. Please use 1, 2, 3, or 'all'."
        }
    }
}
$selectedOptions = $selectedOptions | Sort-Object -Unique

# Clear the screen before proceeding
Clear-Host

# Run selected tools in optimal order: DISM (3), SFC (2), .NET Repair (1)
if ($selectedOptions.Count -eq 0) {
    Write-Host "No valid repair tools selected. Proceeding with log collection..."
} else {
    # Sort options in desired execution order: 3, 2, 1
    $executionOrder = $selectedOptions | Sort-Object -Descending
    foreach ($option in $executionOrder) {
        switch ($option) {
            3 {
                Write-Host ""
                Write-Host "DISM selected."
                Write-Host ""
                Write-Host "Choose an option:"
                Write-Host "O. Online (uses Windows Update)"
                Write-Host "S. Specify a source (e.g., WIM/ESD file)"
                Write-Host ""
                Write-Host -NoNewline "Your choice (O/S): "
                $dismChoice = Read-Host
                
                if ($dismChoice -eq "S" -or $dismChoice -eq "s") {
                    Write-Host ""
                    Write-Host -NoNewline "Enter the full path to the WIM or ESD file (e.g., D:\sources\install.wim): "
                    $dismSource = Read-Host
                    if (Test-Path $dismSource) {
                        Write-Host "Running DISM with specified source: $dismSource..."
                        Start-Process -FilePath "cmd.exe" -ArgumentList "/c DISM /Online /Cleanup-Image /RestoreHealth /Source:$dismSource /LimitAccess" -Wait -NoNewWindow
                        Write-Host "DISM has completed."
                    } else {
                        Write-Warning "Invalid or inaccessible source path: $dismSource. Skipping DISM."
                    }
                } else {
                    Write-Host "Running DISM (Online Restore Health)..."
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c DISM /Online /Cleanup-Image /RestoreHealth" -Wait -NoNewWindow
                    Write-Host "DISM has completed."
                }
            }
            2 {
                Write-Host ""
                Write-Host "Running System File Checker (SFC /scannow)..."
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c sfc /scannow" -Wait -NoNewWindow
                Write-Host "System File Checker has completed."
            }
            1 {
                Write-Host ""
                if (Test-Path $netFxRepairTool) {
                    Write-Host "Running Microsoft .NET Framework Repair Tool..."
                    Start-Process -FilePath $netFxRepairTool -Wait
                    Write-Host "Microsoft .NET Framework Repair Tool has completed."
                } else {
                    Write-Warning "NetFxRepairTool.exe not found in script directory: $scriptDir"
                }
            }
        }
    }
}

# Define paths
$desktopPath = [Environment]::GetFolderPath("Desktop")
$zipFile = "$desktopPath\NetFxRepairAndLogCollector_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
$userTempPath = "$env:LOCALAPPDATA\Temp"
$eventLogPath = "C:\Windows\System32\winevt\Logs"

# Remove FixDotNet*.cab files from Desktop
$cabFiles = Get-ChildItem -Path $desktopPath -Filter "FixDotNet*.cab"
if ($cabFiles) {
    foreach ($cabFile in $cabFiles) {
        try {
            Remove-Item -Path $cabFile.FullName -Force -ErrorAction Stop
            Write-Host "Removed: $($cabFile.Name)"
        }
        catch {
            Write-Warning "Failed to remove $($cabFile.Name): $_"
        }
    }
} else {
    Write-Host "No FixDotNet*.cab files found on Desktop."
}

# Create temporary directory and subdirectories
$tempDir = "$env:TEMP\LogCollection_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$folders = @("Generated", "EventLogs", "SystemFiles", "DotNetFiles", "CrashDumps")
foreach ($folder in $folders) {
    New-Item -ItemType Directory -Path "$tempDir\$folder" -Force | Out-Null
}

# Define file patterns with categories and critical flag
$filePatterns = @(
    @{Path="C:\Windows\"; Pattern="windowsupdate.log"; Category="SystemFiles"; Critical=$true},
    @{Path="C:\Windows\logs\cbs\"; Pattern="cbs.log"; Category="SystemFiles"; Critical=$true},
    @{Path=$userTempPath; Pattern="FixDotNet.log"; Category="DotNetFiles"; Critical=$false},
    @{Path=$userTempPath; Pattern="NetFxSetupEvents.txt"; Category="DotNetFiles"; Critical=$false},
    @{Path=$userTempPath; Pattern="dd_NetFxRepairTool_decompression_log.txt"; Category="DotNetFiles"; Critical=$false},
    @{Path=$userTempPath; Pattern="dd_BackgroundDownload_*.log"; Category="DotNetFiles"; Critical=$false},
    @{Path=$userTempPath; Pattern="FixDotNet_HKCR_Installer.regdump"; Category="DotNetFiles"; Critical=$false},
    @{Path=$userTempPath; Pattern="FixDotNet_HKLM_Installer.regdump"; Category="DotNetFiles"; Critical=$false},
    @{Path="C:\Windows\Panther\"; Pattern="setupact.log"; Category="SystemFiles"; Critical=$false},  # Not always present
    @{Path="C:\Windows\Panther\"; Pattern="setuperr.log"; Category="SystemFiles"; Critical=$false},  # Not always present
    @{Path="C:\Windows\Logs\DISM\"; Pattern="dism.log"; Category="SystemFiles"; Critical=$false},     # Only after DISM runs
    @{Path="C:\Windows\inf\"; Pattern="setupapi.dev.log"; Category="SystemFiles"; Critical=$true},
    @{Path="C:\Windows\Minidump\"; Pattern="*.dmp"; Category="CrashDumps"; Critical=$false}           # Only after crashes
)

# Define event logs (including Genetec logs)
$eventLogs = @(
    @{Name="Application"; File="Application.evtx"},
    @{Name="System"; File="System.evtx"},
    @{Name="Security"; File="Security.evtx"},
    @{Name="Diagnostics-Performance"; File="Microsoft-Windows-Diagnostics-Performance%4Operational.evtx"},
    @{Name="Kernel-PnP"; File="Microsoft-Windows-Kernel-PnP%4Configuration.evtx"},
    @{Name="Kernel-WHEA"; File="Microsoft-Windows-Kernel-WHEA%4Operational.evtx"},
    @{Name="WER-SystemError"; File="Microsoft-Windows-WER-SystemErrorReporting%4Operational.evtx"}
)

# Array to store summary of fetched files
$summary = @()

try {
    # Execute Get-WindowsUpdateLog
    Write-Host "Generating Windows Update log..."
    Get-WindowsUpdateLog
    $windowsUpdateLog = "$desktopPath\WindowsUpdate.log"
    if (Test-Path $windowsUpdateLog) {
        Move-Item -Path $windowsUpdateLog -Destination "$tempDir\Generated\WindowsUpdateDecoded.log" -Force
        Write-Host "Windows Update log generated successfully"
        $summary += [PSCustomObject]@{Type="Generated"; Name="WindowsUpdateDecoded.log"; Status="Success"}
    } else {
        Write-Warning "Windows Update log was not generated"
        $summary += [PSCustomObject]@{Type="Generated"; Name="WindowsUpdateDecoded.log"; Status="Failed"}
    }

    # Copy Event Viewer logs (including Genetec logs) directly from source
    foreach ($log in $eventLogs) {
        $sourcePath = Join-Path -Path $eventLogPath -ChildPath $log.File
        $destPath = Join-Path -Path "$tempDir\EventLogs" -ChildPath $log.File
        try {
            Write-Host "Attempting to copy $($log.Name) log..."
            if (Test-Path $sourcePath) {
                Copy-Item -Path $sourcePath -Destination $destPath -Force -ErrorAction Stop
                Write-Host "Successfully copied $($log.Name) log"
                $summary += [PSCustomObject]@{Type="EventLog"; Name=$log.File; Status="Success"}
            } else {
                Write-Host "$($log.Name) log not found at $sourcePath"  # Silent reporting, no warning
                $summary += [PSCustomObject]@{Type="EventLog"; Name=$log.File; Status="Not Found"}
            }
        }
        catch {
            Write-Warning "Failed to copy $($log.Name) log: $_"
            $summary += [PSCustomObject]@{Type="EventLog"; Name=$log.File; Status="Failed: $_"}
        }
    }

    # Copy Genetec logs
    try {
        Write-Host "Checking for Genetec logs..."
        $genetecLogs = Get-ChildItem -Path $eventLogPath -Filter "*Genetec*.evtx"
        if ($genetecLogs) {
            foreach ($log in $genetecLogs) {
                $destPath = Join-Path -Path "$tempDir\EventLogs" -ChildPath $log.Name
                Write-Host "Attempting to copy Genetec log: $($log.Name)"
                Copy-Item -Path $log.FullName -Destination $destPath -Force -ErrorAction Stop
                Write-Host "Successfully copied Genetec log: $($log.Name)"
                $summary += [PSCustomObject]@{Type="EventLog"; Name=$log.Name; Status="Success"}
            }
        } else {
            Write-Host "No Genetec logs found in Event Viewer directory"
            $summary += [PSCustomObject]@{Type="EventLog"; Name="Any Genetec log"; Status="Not Found"}
        }
    }
    catch {
        Write-Warning "Error copying Genetec logs: $_"
        $summary += [PSCustomObject]@{Type="EventLog"; Name="Any Genetec log"; Status="Failed: $_"}
    }

    # Copy all specified files to temp directory using patterns
    foreach ($filePattern in $filePatterns) {
        $sourcePath = Join-Path -Path $filePattern.Path -ChildPath $filePattern.Pattern
        $destFolder = "$tempDir\$($filePattern.Category)"
        try {
            Write-Host "Searching for files matching: $sourcePath"
            $files = Get-ChildItem -Path $sourcePath -ErrorAction Stop
            if ($files) {
                foreach ($file in $files) {
                    Copy-Item -Path $file.FullName -Destination $destFolder -Force
                    Write-Host "Copied: $($file.Name) to $($filePattern.Category)"
                    $summary += [PSCustomObject]@{Type=$filePattern.Category; Name=$file.Name; Status="Success"}
                }
            } else {
                if ($filePattern.Critical) {
                    Write-Host -ForegroundColor Red "Critical file not found: $sourcePath - This may indicate system issues."
                    $summary += [PSCustomObject]@{Type=$filePattern.Category; Name=$filePattern.Pattern; Status="Not Found - Critical"}
                } else {
                    Write-Host "No files found matching: $sourcePath"  # Silent reporting for non-critical
                    $summary += [PSCustomObject]@{Type=$filePattern.Category; Name=$filePattern.Pattern; Status="Not Found"}
                }
            }
        }
        catch {
            $summary += [PSCustomObject]@{Type=$filePattern.Category; Name=$filePattern.Pattern; Status="Failed: $_"}
        }
    }

    # Create zip file
    if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
        Get-ChildItem -Path $tempDir | Compress-Archive -DestinationPath $zipFile -Force
    } else {
        Add-Type -AssemblyName "System.IO.Compression.FileSystem"
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $zipFile)
    }

    Clear-Host
    Write-Host ""
    Write-Host "Zip file created successfully at: $zipFile"

    # Display summary table
    Write-Host "`n=== Summary of Fetched Files ==="
    $summary | Format-Table -Property Type, Name, Status -AutoSize
}
catch {
    Write-Error "An error occurred: $_"
}
finally {
    # Clean up temporary directory
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    
    # Pause before exit
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

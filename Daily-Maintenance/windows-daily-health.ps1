# Daily Windows Security Health Check Script
# Author: Your Name
# Purpose: Automated daily system maintenance and security checks
# Version: 1.0

param(
    [switch]$Backup,
    [switch]$CleanOnly,
    [string]$LogPath = "$env:USERPROFILE\SecurityLogs"
)

# Create log directory if it doesn't exist
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force
}

$LogFile = "$LogPath\SecurityHealthCheck_$(Get-Date -Format 'yyyyMMdd').log"

function Write-SecurityLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main Security Health Check Function
function Start-SecurityHealthCheck {
    Write-SecurityLog "=== Daily Security Health Check Started ===" "INFO"
    
    # 1. System Health Checks
    Write-SecurityLog "Checking system health..." "INFO"
    
    # Check disk space
    $DiskInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3}
    foreach ($Disk in $DiskInfo) {
        $FreeSpacePercent = [math]::Round(($Disk.FreeSpace / $Disk.Size) * 100, 2)
        if ($FreeSpacePercent -lt 15) {
            Write-SecurityLog "WARNING: Drive $($Disk.DeviceID) only has $FreeSpacePercent% free space" "WARN"
        } else {
            Write-SecurityLog "Drive $($Disk.DeviceID) has $FreeSpacePercent% free space - OK" "INFO"
        }
    }
    
    # Check for Windows Updates
    Write-SecurityLog "Checking for Windows Updates..." "INFO"
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        if ($SearchResult.Updates.Count -gt 0) {
            Write-SecurityLog "Found $($SearchResult.Updates.Count) pending Windows updates" "WARN"
        } else {
            Write-SecurityLog "No pending Windows updates found" "INFO"
        }
    } catch {
        Write-SecurityLog "Could not check for Windows Updates: $($_.Exception.Message)" "ERROR"
    }
    
    # 2. Security Checks
    Write-SecurityLog "Performing security checks..." "INFO"
    
    # Check Windows Defender status
    try {
        $DefenderStatus = Get-MpComputerStatus
        if ($DefenderStatus.RealTimeProtectionEnabled) {
            Write-SecurityLog "Windows Defender Real-time Protection: ENABLED" "INFO"
        } else {
            Write-SecurityLog "Windows Defender Real-time Protection: DISABLED" "WARN"
        }
        
        $LastScan = $DefenderStatus.QuickScanStartTime
        $DaysSinceLastScan = (Get-Date) - $LastScan
        if ($DaysSinceLastScan.Days -gt 7) {
            Write-SecurityLog "Last virus scan was $($DaysSinceLastScan.Days) days ago - Consider running scan" "WARN"
        } else {
            Write-SecurityLog "Recent virus scan detected (within 7 days)" "INFO"
        }
    } catch {
        Write-SecurityLog "Could not check Windows Defender status: $($_.Exception.Message)" "WARN"
    }
    
    # Check for suspicious processes
    Write-SecurityLog "Checking for suspicious processes..." "INFO"
    $SuspiciousProcesses = @("powershell", "cmd", "wscript", "cscript")
    $RunningProcesses = Get-Process | Where-Object {$_.ProcessName -in $SuspiciousProcesses}
    
    foreach ($Process in $RunningProcesses) {
        Write-SecurityLog "Found process: $($Process.ProcessName) (PID: $($Process.Id)) - Path: $($Process.Path)" "INFO"
    }
    
    # 3. Cleanup Operations
    Write-SecurityLog "Starting cleanup operations..." "INFO"
    
    # Clear temporary files
    $TempFolders = @(
        $env:TEMP,
        "$env:USERPROFILE\AppData\Local\Temp",
        "C:\Windows\Temp"
    )
    
    foreach ($Folder in $TempFolders) {
        if (Test-Path $Folder) {
            try {
                # Test if we have access to the folder first
                $TestAccess = Get-ChildItem $Folder -ErrorAction Stop | Select-Object -First 1
                
                $BeforeSize = (Get-ChildItem $Folder -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
                Get-ChildItem $Folder -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-7)} | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $AfterSize = (Get-ChildItem $Folder -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
                $CleanedMB = [math]::Round($BeforeSize - $AfterSize, 2)
                Write-SecurityLog "Cleaned $CleanedMB MB from $Folder" "INFO"
            } catch [System.UnauthorizedAccessException] {
                Write-SecurityLog "Skipping $Folder (requires administrator privileges)" "INFO"
            } catch {
                Write-SecurityLog "Could not clean $Folder`: $($_.Exception.Message)" "WARN"
            }
        }
    }
    
    # Clear browser caches (Chrome example)
    $ChromeCache = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Cache"
    if (Test-Path $ChromeCache) {
        try {
            # Only clean if Chrome is not running
            if (!(Get-Process "chrome" -ErrorAction SilentlyContinue)) {
                Remove-Item "$ChromeCache\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-SecurityLog "Cleared Chrome cache" "INFO"
            } else {
                Write-SecurityLog "Chrome is running, skipping cache cleanup" "INFO"
            }
        } catch {
            Write-SecurityLog "Could not clear Chrome cache: $($_.Exception.Message)" "WARN"
        }
    }
    
    # 4. System Maintenance
    Write-SecurityLog "Performing system maintenance..." "INFO"
    
    # Check system uptime
    $Uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    Write-SecurityLog "System uptime: $($Uptime.Days) days, $($Uptime.Hours) hours" "INFO"
    
    if ($Uptime.Days -gt 7) {
        Write-SecurityLog "System has been running for over 7 days - Consider restart" "WARN"
    }
    
    # Generate system report
    $SystemInfo = @{
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
        TotalRAM = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
        AvailableRAM = [math]::Round((Get-Counter '\Memory\Available MBytes').CounterSamples[0].CookedValue / 1024, 2)
        CPUUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
    }
    
    Write-SecurityLog "System Info: $($SystemInfo.OSVersion), RAM: $($SystemInfo.AvailableRAM)/$($SystemInfo.TotalRAM) GB available" "INFO"
    
    # 5. Backup Check (if enabled)
    if ($Backup) {
        Write-SecurityLog "Backup option enabled - Add your backup logic here" "INFO"
        # Add your backup commands here
    }
    
    Write-SecurityLog "=== Daily Security Health Check Completed ===" "INFO"
}

# Script execution
Write-Host "Starting Daily Security Health Check..." -ForegroundColor Green

if (!(Test-IsAdmin)) {
    Write-Warning "This script works best when run as Administrator for full system access."
}

Start-SecurityHealthCheck

# Schedule this script to run daily
Write-Host "`nTo schedule this script to run daily:" -ForegroundColor Yellow
Write-Host "1. Open Task Scheduler" -ForegroundColor White
Write-Host "2. Create Basic Task" -ForegroundColor White
Write-Host "3. Set trigger to Daily" -ForegroundColor White
Write-Host "4. Set action to start PowerShell with arguments: -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -ForegroundColor White

Write-Host "`nCheck your log file at: $LogFile" -ForegroundColor Green
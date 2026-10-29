#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SOC Lab File Integrity Monitor - Deployment Script.
.DESCRIPTION
    Deploys the lightweight FIM watcher to this endpoint: no third-party agent
    install, just a native PowerShell script (FileSystemWatcher) registered as
    a Scheduled Task so it survives reboots and logons. Events are tagged with
    the signed-in AD identity and machine name, then forwarded to Vector.
.PARAMETER VectorHost
    Vector log aggregator host/IP (default: auto-detect from SOC_VECTOR_HOST env).
.PARAMETER VectorPort
    Vector FIM ingestion port (matches VECTOR_FIM_PORT in the lab's .env, default 6005).
.PARAMETER WatchedExtensions
    File extensions to monitor, e.g. ".docx",".xlsx",".pdf". Set by the admin -
    only files with these extensions are watched. Leave unset to keep the
    extensions already in fim-config.json.
.EXAMPLE
    .\Deploy-FIM.ps1 -VectorHost 192.168.10.30
.EXAMPLE
    .\Deploy-FIM.ps1 -VectorHost 192.168.10.30 -WatchedExtensions ".docx",".pdf",".zip"
.EXAMPLE
    .\Deploy-FIM.ps1 -Uninstall
#>
param(
    [string]$VectorHost = $(if ($env:SOC_VECTOR_HOST) { $env:SOC_VECTOR_HOST } else { "192.168.10.30" }),
    [int]$VectorPort = 6005,
    [string[]]$WatchedExtensions,
    [string]$InstallDir = "C:\ProgramData\SOCLab\FIM",
    # Account the watcher runs as, which therefore needs Modify on InstallDir.
    # Defaults to whoever runs this script; when pushed by an RMM (so this runs
    # as SYSTEM) it falls back to BUILTIN\Users, since the watcher runs as
    # whichever user logs on later. Set explicitly on a shared machine.
    [string]$WatcherAccount,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$taskName = "SOCLab-FileIntegrityMonitor"

if ($Uninstall) {
    Write-Host "Removing $taskName scheduled task and $InstallDir..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*Watch-FileIntegrity.ps1*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host "Done. The custom FIM watcher is no longer running on this host." -ForegroundColor Green
    exit 0
}

Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|   SOC Lab File Integrity Monitor - Deployment       |" -ForegroundColor Cyan
Write-Host "|   No agent install - native PowerShell watcher      |" -ForegroundColor Cyan
Write-Host "+======================================================+`n" -ForegroundColor Cyan

# -- Step 1: Install files ------------------------------------------------------
Write-Host "[1/4] Installing watcher to $InstallDir..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item "$PSScriptRoot\Watch-FileIntegrity.ps1" "$InstallDir\Watch-FileIntegrity.ps1" -Force

# -- Step 1b: Lock down the install directory -----------------------------------
# ShadowCopies\ holds complete byte-for-byte copies of every watched file, and
# fim-events.log holds content previews of them. Inheriting C:\ProgramData's
# default ACL would hand every local user read access to both - turning a
# monitoring tool into a way for any standard user to read every other user's
# documents. Strip inheritance and grant only SYSTEM, Administrators, and the
# account the watcher actually runs under.
#
# Well-known SIDs rather than names, so this doesn't break on a non-English
# Windows where the groups are called something else.
Write-Host "   Hardening ACLs on $InstallDir..." -ForegroundColor Yellow

$runningAsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
if (-not $WatcherAccount) {
    if ($runningAsSystem) {
        # Pushed by an RMM (ManageEngine/Intune/GPO) - there's no interactive
        # user to read here, and the watcher runs as whoever logs on later, so
        # the local Users group is the only thing that covers them. Scope this
        # to named accounts with -WatcherAccount on a shared machine.
        $WatcherAccount = 'S-1-5-32-545'   # BUILTIN\Users
        Write-Warning "   Running as SYSTEM: granting BUILTIN\Users access to $InstallDir."
        Write-Warning "   On a multi-user machine, re-run with -WatcherAccount '<DOMAIN\user>' to scope this tighter."
    } else {
        $WatcherAccount = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    }
}

try {
    $acl = Get-Acl $InstallDir
    $acl.SetAccessRuleProtection($true, $false)          # break inheritance, drop inherited ACEs
    @($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $prop    = [System.Security.AccessControl.PropagationFlags]::None
    $allow   = [System.Security.AccessControl.AccessControlType]::Allow

    $grants = @(
        @{ Sid = 'S-1-5-18';     Rights = 'FullControl' }   # NT AUTHORITY\SYSTEM (Wazuh agent reads the log as this)
        @{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }   # BUILTIN\Administrators
        @{ Sid = $WatcherAccount; Rights = 'Modify'     }   # the watcher process itself
    )
    foreach ($g in $grants) {
        $id = try { [System.Security.Principal.SecurityIdentifier]::new($g.Sid) } catch { $g.Sid }
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $id, [System.Security.AccessControl.FileSystemRights]$g.Rights, $inherit, $prop, $allow)))
    }
    Set-Acl -Path $InstallDir -AclObject $acl
    Write-Host "   ACLs: SYSTEM + Administrators + watcher account only (inheritance broken)" -ForegroundColor Green
} catch {
    Write-Warning "   ACL hardening FAILED: $($_.Exception.Message)"
    Write-Warning "   Shadow copies may be readable by other local users - fix before treating this as production."
}

$configPath = "$InstallDir\fim-config.json"
$config = if (Test-Path $configPath) {
    Get-Content $configPath -Raw | ConvertFrom-Json
} else {
    Get-Content "$PSScriptRoot\fim-config.json" -Raw | ConvertFrom-Json
}

$config.forward_to_vector.host = $VectorHost
$config.forward_to_vector.port = $VectorPort
if ($WatchedExtensions) { $config.watched_extensions = $WatchedExtensions }

$config | ConvertTo-Json -Depth 5 | Out-File $configPath -Encoding UTF8
Write-Host "   Watched types: $($config.watched_extensions -join ', ')" -ForegroundColor White

# -- Step 2: Register Scheduled Task --------------------------------------------
Write-Host "[2/4] Registering Scheduled Task..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Unregistering the task does NOT kill a process an earlier version of it
# already spawned (e.g. one still running as SYSTEM from before this script
# fixed that) - without this, redeploys/re-runs (including repeated
# ManageEngine pushes) silently accumulate orphaned watcher instances, some
# of them watching the wrong folder under the wrong account.
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*Watch-FileIntegrity.ps1*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Minimized -ExecutionPolicy Bypass -File `"$InstallDir\Watch-FileIntegrity.ps1`" -ConfigPath `"$configPath`""
# -WindowStyle Hidden was empirically found (during real endpoint testing) to
# be unreliable for delivering FileSystemWatcher's Register-ObjectEvent
# callbacks - the exact same script, same account, same session, only
# differing by Hidden vs Minimized, intermittently failed to log any events
# at all when Hidden. Minimized keeps a real (just minimized) window/message
# context and was consistently reliable in testing. If this ever needs to be
# fully invisible to the user, wrap it via a small VBScript/WSH launcher
# instead of relying on -WindowStyle Hidden.
$trigger   = New-ScheduledTaskTrigger -AtLogOn
# IMPORTANT: this must run as the interactively logged-on user, not SYSTEM.
# watch_paths (fim-config.json) use %USERPROFILE%\Desktop etc - under SYSTEM
# that expands to C:\Windows\System32\config\systemprofile, a folder nobody's
# files are ever in, so the watcher would silently watch nothing real.
# GroupId "BUILTIN\Users" (rather than a hardcoded -UserId) also means this
# same task definition works for whichever user logs into a machine this was
# pushed to via RMM (ManageEngine/GPO/Intune) - no per-device username needed.
$principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users"
# RestartCount/RestartInterval make this self-healing: if the watcher process
# itself ever crashes (unhandled exception, killed, etc.) mid-session, Task
# Scheduler restarts it within a minute - it doesn't wait for the next logon
# or reboot to resume watching/forwarding.
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit 0 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description "SOC Lab lightweight file integrity watcher" | Out-Null

# -- Step 3: Start it now -------------------------------------------------------
Write-Host "[3/4] Starting watcher..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $taskName
Start-Sleep 2

# -- Step 4: Validate -----------------------------------------------------------
Write-Host "[4/4] Validating deployment..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "====================== DEPLOYMENT SUMMARY ========================" -ForegroundColor Cyan
Write-Host " Host:        $env:COMPUTERNAME" -ForegroundColor White
Write-Host " Vector:      ${VectorHost}:${VectorPort}" -ForegroundColor White
Write-Host " Watched ext: $($config.watched_extensions -join ', ')" -ForegroundColor White
Write-Host " Log file:    $($config.log_path)" -ForegroundColor White
Write-Host " Runs:        on logon, as the signed-in user, auto-restarts within 1 min if it ever crashes" -ForegroundColor White
$stateOk = $task -and ($task.State -in @('Ready','Running'))
Write-Host " Task state:  $(if ($stateOk) {'OK - ' + $task.State} else {'FAILED - ' + $task.State})" -ForegroundColor $(if ($stateOk) {'Green'} else {'Red'})
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To change watched file types later, edit $configPath" -ForegroundColor Yellow
Write-Host "and re-run this script, OR edit it directly on the endpoint -" -ForegroundColor Yellow
Write-Host "the watcher re-reads it automatically every $($config.config_reload_seconds) seconds." -ForegroundColor Yellow
Write-Host ""
Write-Host "Verify in OpenSearch: index soc-logs-* | filter log_type: file_integrity, host: $env:COMPUTERNAME" -ForegroundColor Yellow

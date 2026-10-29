#Requires -Version 5.1
<#
.SYNOPSIS
    SOC Lab File Integrity Monitor - endpoint watcher (DLP-lite).
.DESCRIPTION
    Watches the folders/extensions listed in fim-config.json for Created,
    Modified, Renamed/Moved and Deleted events using the native .NET
    FileSystemWatcher - no third-party agent required. Every matching event is
    written locally and forwarded (best-effort, non-blocking) as one JSON line
    to Vector, which tags it with a MITRE technique and indexes it into
    OpenSearch under soc-logs-*.

    Beyond plain FIM, this script also:
      - Keeps a content-addressed "shadow copy" of every watched file's bytes
        (deduped by SHA256, size-capped) so a deleted file's last-known
        content travels with its Deleted event and can be restored from the
        SOC dashboard - the endpoint is never contacted after the fact, since
        there is no inbound channel to it (outbound-only, by design).
      - Extracts a bounded, human-readable content_preview at every event so
        an analyst can see what is inside a file without downloading it.
      - Correlates hashes to distinguish "copied" (same content now exists at
        a second path while the original still exists) and cross-directory
        "moved" (a delete followed shortly by a create with the same hash)
        from genuinely new files - FileSystemWatcher itself cannot tell these
        apart, so this is a heuristic, not forensic proof.

    The admin can change watched_extensions (and most other settings except
    watch_paths) in fim-config.json at any time - this script re-reads the
    file every config_reload_seconds without needing a restart.

    KNOWN LIMITATIONS (see README.md):
      - Content preview for .pdf and .zip is not full-text (PDF has no plain
        text layer without a parser this script doesn't carry; .zip lists
        entry names only). .docx/.xlsx/.pptx/.csv/.txt get real text.
      - The copy/move hash correlation is heuristic: two unrelated files that
        happen to share identical content will look like a copy.
      - The in-memory known-file map is rebuilt via a startup baseline scan,
        so path history from *before* this run only goes as deep as that scan
        (it hashes and shadow-copies every existing watched file once).
.PARAMETER ConfigPath
    Path to fim-config.json. Defaults to the copy next to this script.
.NOTES
    Intended to be launched by Deploy-FIM.ps1 via a Scheduled Task, but can be
    run directly in a console for testing: .\Watch-FileIntegrity.ps1
#>
param(
    [string]$ConfigPath = "$PSScriptRoot\fim-config.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ConfigPath)) { throw "FIM config not found: $ConfigPath" }

function Read-FimConfig {
    param([string]$Path)
    Get-Content $Path -Raw | ConvertFrom-Json
}

$global:FimConfig     = Read-FimConfig -Path $ConfigPath
$global:FimConfigPath = $ConfigPath
$global:FimIdentity   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$global:FimMachine    = $env:COMPUTERNAME

New-Item -ItemType Directory -Force -Path (Split-Path $global:FimConfig.log_path) | Out-Null

# path -> sha256 of last-known content, for copy/move correlation and rekeying on rename.
$global:FimKnownFiles = @{}
# path -> "size|mtime-ticks" cheap fingerprint, used only by the periodic
# reconciliation scan (below) to skip re-hashing files that plainly haven't
# changed. Kept separate from FimKnownFiles so the correlation logic that
# already depends on FimKnownFiles is untouched.
$global:FimKnownMeta = @{}
# ring buffer of recently deleted files: [{ hash, path, time }], pruned by the
# configured correlation window - lets a delete+create pair on two different
# watched roots be recognised as one cross-directory "moved" event.
$global:FimRecentDeletes = New-Object System.Collections.ArrayList

function global:Get-FimShadowDir {
    if ($global:FimConfig.shadow_copy -and $global:FimConfig.shadow_copy.enabled) {
        $dir = $global:FimConfig.shadow_copy.path
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        return $dir
    }
    return $null
}

function global:Get-FimFileHashSafe {
    param([string]$Path)
    for ($i = 0; $i -lt 3; $i++) {
        try { return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
        catch { Start-Sleep -Milliseconds 150 }
    }
    return $null
}

# Copies $Path into the content-addressed shadow store (skipped if the hash is
# already stored, or the file is over shadow_copy.max_file_mb). Returns $true
# if a usable shadow copy now exists for this hash.
function global:Backup-FimShadowCopy {
    param([string]$Path, [string]$Hash)
    $shadowDir = Get-FimShadowDir
    if (-not $shadowDir -or -not $Hash) { return $false }

    $dest = Join-Path $shadowDir $Hash
    if (Test-Path $dest) { return $true }

    $maxMb = if ($global:FimConfig.shadow_copy.max_file_mb) { [int]$global:FimConfig.shadow_copy.max_file_mb } else { 20 }
    try {
        $size = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length
        if ($size -gt ($maxMb * 1MB)) { return $false }
        Copy-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
        Invoke-FimShadowStorePrune
        return $true
    } catch { return $false }
}

# Simple size cap on the whole shadow store - evicts oldest-accessed copies
# first once over max_store_mb. Best-effort; never blocks event forwarding.
function global:Invoke-FimShadowStorePrune {
    try {
        $shadowDir = Get-FimShadowDir
        if (-not $shadowDir) { return }
        $maxMb = if ($global:FimConfig.shadow_copy.max_store_mb) { [int]$global:FimConfig.shadow_copy.max_store_mb } else { 2048 }
        $files = Get-ChildItem -Path $shadowDir -File -ErrorAction SilentlyContinue | Sort-Object LastAccessTime
        $totalMb = ($files | Measure-Object Length -Sum).Sum / 1MB
        foreach ($f in $files) {
            if ($totalMb -le $maxMb) { break }
            $totalMb -= ($f.Length / 1MB)
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

# Diagnostic-only log, separate from fim-events.log: records that the raw
# .NET event actually fired (BEFORE any of our own logic runs) and captures
# any exception from inside an event action - Register-ObjectEvent action
# scriptblocks fail silently otherwise (their errors go into a PSEventJob
# nobody is watching), which made a real production issue undiagnosable
# from outside the process. Never throws itself.
function global:Write-FimDiag {
    param([string]$Message)
    try {
        $diagPath = Join-Path (Split-Path $global:FimConfig.log_path) "fim-diag.log"
        Add-Content -Path $diagPath -Value "$(Get-Date -Format o)  $Message" -ErrorAction SilentlyContinue
    } catch {}
}

function global:Test-FimWatchedExtension {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    return $global:FimConfig.watched_extensions -contains $ext
}

# Strips obvious secrets out of a content preview before it leaves the machine.
# Previews are shipped into the SIEM and stored in its alerts index, where
# anyone with dashboard access can read them - so a .env or passwords.txt on
# someone's Desktop would otherwise put live credentials in front of every
# analyst, permanently. Best-effort by nature: this catches the common,
# well-shaped secrets, not every possible one. Treat it as reducing exposure,
# not as a guarantee the preview is clean.
function global:Protect-FimSecrets {
    param([string]$Text)
    if (-not $Text) { return $Text }
    if ($global:FimConfig.content_preview -and
        $global:FimConfig.content_preview.PSObject.Properties.Name -contains 'redact_secrets' -and
        -not $global:FimConfig.content_preview.redact_secrets) { return $Text }

    $patterns = @(
        # key=value style assignments (ini/env/yaml/json/connection strings)
        '(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token)\s*[:=]\s*["'']?[^\s"'',;}]{4,}'
        # Cloud / service provider key formats
        'AKIA[0-9A-Z]{16}'                                   # AWS access key id
        'gh[pousr]_[A-Za-z0-9]{20,}'                         # GitHub tokens
        'xox[baprs]-[0-9A-Za-z-]{10,}'                       # Slack tokens
        # Structured credentials
        'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'  # JWT
        '(?i)bearer\s+[A-Za-z0-9._\-]{16,}'                  # bearer tokens
        '-----BEGIN[A-Z ]*PRIVATE KEY-----'                  # private key blocks
        # Long digit runs that look like a card / account number
        '\b(?:\d[ -]?){13,19}\b'
    )
    foreach ($p in $patterns) {
        try { $Text = [regex]::Replace($Text, $p, '[REDACTED]') } catch {}
    }
    return $Text
}

# Extracts a bounded, human-readable preview so an analyst can see what is
# inside a file without downloading it. Office formats are zip containers -
# their XML text parts are pulled and tag-stripped. PDF/zip get a best-effort
# fallback, not full text (see README limitations). Whatever comes out is run
# through Protect-FimSecrets before any caller sees it.
function global:Get-FimContentPreview {
    param([string]$SourcePath, [string]$Ext)
    return (Protect-FimSecrets -Text (Get-FimContentPreviewRaw -SourcePath $SourcePath -Ext $Ext))
}

function global:Get-FimContentPreviewRaw {
    param([string]$SourcePath, [string]$Ext)
    if (-not ($global:FimConfig.content_preview -and $global:FimConfig.content_preview.enabled)) { return $null }
    $maxChars = if ($global:FimConfig.content_preview.max_chars) { [int]$global:FimConfig.content_preview.max_chars } else { 4000 }

    try {
        switch ($Ext) {
            { $_ -in ".txt", ".csv" } {
                $text = Get-Content -LiteralPath $SourcePath -Raw -ErrorAction Stop
                return $text.Substring(0, [Math]::Min($text.Length, $maxChars))
            }
            { $_ -in ".docx", ".xlsx", ".pptx" } {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                $zip = [System.IO.Compression.ZipFile]::OpenRead($SourcePath)
                try {
                    $xmlEntries = switch ($Ext) {
                        ".docx" { $zip.Entries | Where-Object { $_.FullName -eq "word/document.xml" } }
                        ".pptx" { $zip.Entries | Where-Object { $_.FullName -like "ppt/slides/slide*.xml" } | Sort-Object FullName }
                        ".xlsx" { $zip.Entries | Where-Object { $_.FullName -like "xl/worksheets/sheet*.xml" -or $_.FullName -eq "xl/sharedStrings.xml" } | Sort-Object FullName }
                    }
                    $sb = New-Object System.Text.StringBuilder
                    foreach ($entry in $xmlEntries) {
                        if ($sb.Length -ge $maxChars) { break }
                        $reader = New-Object System.IO.StreamReader($entry.Open())
                        try {
                            $xml = $reader.ReadToEnd()
                            $text = [regex]::Replace($xml, '<[^>]+>', ' ')
                            $text = [regex]::Replace($text, '\s+', ' ').Trim()
                            [void]$sb.Append($text).Append(' ')
                        } finally { $reader.Dispose() }
                    }
                    $out = $sb.ToString()
                    return $out.Substring(0, [Math]::Min($out.Length, $maxChars))
                } finally { $zip.Dispose() }
            }
            ".zip" {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                $zip = [System.IO.Compression.ZipFile]::OpenRead($SourcePath)
                try {
                    $names = $zip.Entries | Select-Object -First 25 -ExpandProperty FullName
                    return "[zip archive - $($zip.Entries.Count) entries] " + ($names -join ', ')
                } finally { $zip.Dispose() }
            }
            default {
                return "[binary content - text preview not available for $Ext in this lab build; use restore to recover the exact original bytes]"
            }
        }
    } catch {
        return "[preview unavailable - file may have been locked or changed mid-read]"
    }
}

function global:Send-FimEvent {
    param(
        [string]$Action,
        [string]$FullPath,
        [string]$Destination = ""
    )
    if (-not (Test-FimWatchedExtension -Path $FullPath)) { return }

    $ext           = [System.IO.Path]::GetExtension($FullPath).ToLowerInvariant()
    $hash          = $null
    $sizeBytes     = $null
    $preview       = $null
    $recoverable   = $false
    $contentB64    = $null
    $shadowStored  = $false
    $correlation   = $null
    $correlatedAct = $Action

    if ($Action -eq "deleted") {
        # File is already gone - fall back to what we knew about it a moment
        # ago (from the startup baseline scan or a prior create/modify), which
        # is also our only chance at a recovery copy.
        if ($global:FimKnownFiles.ContainsKey($FullPath)) {
            $hash = $global:FimKnownFiles[$FullPath]
            $global:FimKnownFiles.Remove($FullPath)
        }
        if ($hash) {
            $shadowDir = Get-FimShadowDir
            $shadowFile = if ($shadowDir) { Join-Path $shadowDir $hash } else { $null }
            if ($shadowFile -and (Test-Path $shadowFile)) {
                $shadowStored = $true
                $preview = Get-FimContentPreview -SourcePath $shadowFile -Ext $ext
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($shadowFile)
                    $contentB64 = [System.Convert]::ToBase64String($bytes)
                    $recoverable = $true
                } catch {}
            }
            # Feed the correlation window so a create elsewhere with the same
            # hash within the window is recognised as a cross-directory move.
            [void]$global:FimRecentDeletes.Add(@{ hash = $hash; path = $FullPath; time = Get-Date })
        }
    }
    else {
        $hash = Get-FimFileHashSafe -Path $FullPath
        if ($hash) {
            try { $sizeBytes = (Get-Item -LiteralPath $FullPath -ErrorAction Stop).Length } catch {}
            $shadowStored = Backup-FimShadowCopy -Path $FullPath -Hash $hash
            $preview = Get-FimContentPreview -SourcePath $FullPath -Ext $ext
            $recoverable = $shadowStored

            if ($Action -eq "created") {
                # Prune the correlation window to the configured age first.
                $windowSec = if ($global:FimConfig.move_correlation_window_seconds) { [int]$global:FimConfig.move_correlation_window_seconds } else { 30 }
                $cutoff = (Get-Date).AddSeconds(-$windowSec)
                for ($i = $global:FimRecentDeletes.Count - 1; $i -ge 0; $i--) {
                    if ($global:FimRecentDeletes[$i].time -lt $cutoff) { $global:FimRecentDeletes.RemoveAt($i) }
                }

                $moveMatch = $global:FimRecentDeletes | Where-Object { $_.hash -eq $hash } | Select-Object -First 1
                if ($moveMatch) {
                    $correlatedAct = "moved"
                    $correlation = $moveMatch.path
                    $global:FimRecentDeletes.Remove($moveMatch)
                }
                else {
                    $copyMatch = $global:FimKnownFiles.GetEnumerator() |
                        Where-Object { $_.Value -eq $hash -and $_.Key -ne $FullPath -and (Test-Path -LiteralPath $_.Key) } |
                        Select-Object -First 1
                    if ($copyMatch) {
                        $correlatedAct = "copied"
                        $correlation = $copyMatch.Key
                    }
                }
            }
            $global:FimKnownFiles[$FullPath] = $hash
        }
    }

    if ($Destination -and -not $correlation) { $correlation = $Destination }

    $evt = [ordered]@{
        "@timestamp"      = (Get-Date).ToUniversalTime().ToString("o")
        # Marker so the Wazuh manager's local_rules.xml can target exactly
        # these events - matching on <decoded_as>json</decoded_as> alone would
        # also catch every other JSON log source on the agent.
        event_source      = "soclab_fim"
        action            = $correlatedAct
        user              = $global:FimIdentity
        machine           = $global:FimMachine
        file_path         = $FullPath
        destination       = $correlation
        file_hash         = $hash
        file_size         = $sizeBytes
        content_preview   = $preview
        recoverable       = $recoverable
    }

    # Two variants of the same event:
    #  - LEAN (no content_b64) goes to the local log file, which the Wazuh
    #    agent tails via <localfile>. Wazuh's logcollector truncates any event
    #    over ~64KB, and a recovered file's base64 runs to tens of MB - it
    #    would blow that limit and bloat the alerts index for no benefit. The
    #    bytes stay on the endpoint in the shadow store, addressable by the
    #    file_hash that every alert carries.
    #  - FULL (with content_b64) goes over the TCP forward to Vector, which
    #    has no such limit and is what backs the dashboard's restore button.
    $jsonLean = $evt | ConvertTo-Json -Compress -Depth 4
    $evt["content_b64"] = $contentB64
    $jsonFull = $evt | ConvertTo-Json -Compress -Depth 4

    try { Add-Content -Path $global:FimConfig.log_path -Value $jsonLean } catch {}

    if ($global:FimConfig.forward_to_vector.enabled) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($global:FimConfig.forward_to_vector.host, [int]$global:FimConfig.forward_to_vector.port)
            $stream = $client.GetStream()
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes("$jsonFull`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Close()
            $client.Close()
        } catch {
            # Forwarding is best-effort - never let a network blip kill the watcher.
        }
    }
}

# -- Baseline scan: hash + shadow-copy every watched file that already exists
#    on disk, so deletions of pre-existing files are recoverable too, not only
#    files created after this watcher started. Best-effort, skips unreadable
#    files silently (locked, permission-denied, etc.).
function global:Invoke-FimBaselineScan {
    foreach ($rawPath in $global:FimConfig.watch_paths) {
        $path = [System.Environment]::ExpandEnvironmentVariables($rawPath)
        if (-not (Test-Path $path)) { continue }
        $opts = @{ Path = $path; File = $true; ErrorAction = "SilentlyContinue" }
        if ($global:FimConfig.include_subdirectories) { $opts.Recurse = $true }
        Get-ChildItem @opts | Where-Object { Test-FimWatchedExtension -Path $_.FullName } | ForEach-Object {
            $hash = Get-FimFileHashSafe -Path $_.FullName
            if ($hash) {
                $global:FimKnownFiles[$_.FullName] = $hash
                $global:FimKnownMeta[$_.FullName] = "$($_.Length)|$($_.LastWriteTimeUtc.Ticks)"
                Backup-FimShadowCopy -Path $_.FullName -Hash $hash | Out-Null
            }
        }
    }
    Write-Host "Baseline scan complete: $($global:FimKnownFiles.Count) existing watched file(s) hashed."
}

# -- Periodic reconciliation scan ----------------------------------------------
# FileSystemWatcher's real-time notifications can be silently suppressed by
# things outside this script's control (observed in practice: an org-managed
# antivirus/EDR's filesystem filter driver occasionally swallows
# ReadDirectoryChangesW notifications with no error, no exception, nothing to
# catch - the .NET event simply never fires). Rather than depend entirely on
# real-time delivery, this periodically re-walks every watched path and diffs
# against known state, generating the exact same create/modified/deleted
# events (with the same hash correlation, shadow copy and content preview)
# that the real-time watcher would have - so a missed real-time notification
# is caught within one reconciliation interval instead of never. This mirrors
# why Wazuh's own FIM module pairs real-time watching with a periodic full
# scan rather than trusting real-time delivery alone.
function global:Invoke-FimReconciliationScan {
    $current = New-Object System.Collections.Generic.HashSet[string]

    foreach ($rawPath in $global:FimConfig.watch_paths) {
        $path = [System.Environment]::ExpandEnvironmentVariables($rawPath)
        if (-not (Test-Path $path)) { continue }
        $opts = @{ Path = $path; File = $true; ErrorAction = "SilentlyContinue" }
        if ($global:FimConfig.include_subdirectories) { $opts.Recurse = $true }

        Get-ChildItem @opts | Where-Object { Test-FimWatchedExtension -Path $_.FullName } | ForEach-Object {
            $fp = $_.FullName
            [void]$current.Add($fp)

            $meta = "$($_.Length)|$($_.LastWriteTimeUtc.Ticks)"
            if ($global:FimKnownMeta[$fp] -eq $meta) { return }  # unchanged since we last looked - skip re-hashing

            $hash = Get-FimFileHashSafe -Path $fp
            if (-not $hash) { return }
            $global:FimKnownMeta[$fp] = $meta

            if (-not $global:FimKnownFiles.ContainsKey($fp)) {
                Write-FimDiag "RECONCILE: new file the real-time watcher missed - $fp"
                try { Send-FimEvent -Action "created" -FullPath $fp }
                catch { Write-FimDiag "ERROR in reconcile (created) for $fp : $($_.Exception.Message)" }
            }
            elseif ($global:FimKnownFiles[$fp] -ne $hash) {
                Write-FimDiag "RECONCILE: modified file the real-time watcher missed - $fp"
                try { Send-FimEvent -Action "modified" -FullPath $fp }
                catch { Write-FimDiag "ERROR in reconcile (modified) for $fp : $($_.Exception.Message)" }
            }
        }
    }

    # Anything we knew about that no longer shows up anywhere in watch_paths
    # was deleted - and if the real-time Deleted handler already caught it,
    # it's already gone from FimKnownFiles, so this naturally never double-fires.
    $missing = @($global:FimKnownFiles.Keys) | Where-Object { -not $current.Contains($_) }
    foreach ($fp in $missing) {
        Write-FimDiag "RECONCILE: deleted file the real-time watcher missed - $fp"
        try { Send-FimEvent -Action "deleted" -FullPath $fp }
        catch { Write-FimDiag "ERROR in reconcile (deleted) for $fp : $($_.Exception.Message)" }
        $global:FimKnownMeta.Remove($fp)
    }
}

Invoke-FimBaselineScan

# -- Set up one FileSystemWatcher per configured path --------------------------
$global:FimWatchers = @()
foreach ($rawPath in $global:FimConfig.watch_paths) {
    $path = [System.Environment]::ExpandEnvironmentVariables($rawPath)
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }

    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path                  = $path
    $watcher.IncludeSubdirectories = [bool]$global:FimConfig.include_subdirectories
    $watcher.Filter                = "*.*"
    $watcher.NotifyFilter          = [System.IO.NotifyFilters]'FileName, LastWrite, Size, DirectoryName'
    # FileSystemWatcher's internal change-notification buffer defaults to just
    # 8KB. On a real profile folder with background churn (OneDrive sync,
    # Windows Search indexing, antivirus) this overflows easily - and once it
    # does, .NET raises an Error event and the watcher goes permanently silent
    # (no more Created/Changed/Deleted ever) until reset. Observed exactly
    # this in testing: the first event after startup logged fine, then every
    # subsequent file change was silently dropped forever. 64KB (the largest
    # size with reliable non-paged pool behavior) plus the Error handler below
    # (which resets the watcher on overflow) fixes it.
    $watcher.InternalBufferSize    = 65536
    $watcher.EnableRaisingEvents   = $true

    Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier "FIM_Created_$path" -Action {
        Write-FimDiag "RAW EVENT: Created $($Event.SourceEventArgs.FullPath)"
        try { Send-FimEvent -Action "created" -FullPath $Event.SourceEventArgs.FullPath }
        catch { Write-FimDiag "ERROR in Created handler: $($_.Exception.Message) | $($_.ScriptStackTrace)" }
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier "FIM_Changed_$path" -Action {
        Write-FimDiag "RAW EVENT: Changed $($Event.SourceEventArgs.FullPath) type=$($Event.SourceEventArgs.ChangeType)"
        try {
            if ($Event.SourceEventArgs.ChangeType -eq [System.IO.WatcherChangeTypes]::Changed) {
                Send-FimEvent -Action "modified" -FullPath $Event.SourceEventArgs.FullPath
            }
        } catch { Write-FimDiag "ERROR in Changed handler: $($_.Exception.Message) | $($_.ScriptStackTrace)" }
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Deleted -SourceIdentifier "FIM_Deleted_$path" -Action {
        Write-FimDiag "RAW EVENT: Deleted $($Event.SourceEventArgs.FullPath)"
        try { Send-FimEvent -Action "deleted" -FullPath $Event.SourceEventArgs.FullPath }
        catch { Write-FimDiag "ERROR in Deleted handler: $($_.Exception.Message) | $($_.ScriptStackTrace)" }
    } | Out-Null

    Register-ObjectEvent -InputObject $watcher -EventName Renamed -SourceIdentifier "FIM_Renamed_$path" -Action {
        Write-FimDiag "RAW EVENT: Renamed $($Event.SourceEventArgs.OldFullPath) -> $($Event.SourceEventArgs.FullPath)"
        try {
            $old = $Event.SourceEventArgs.OldFullPath
            $new = $Event.SourceEventArgs.FullPath
            $action = if ([System.IO.Path]::GetDirectoryName($old) -eq [System.IO.Path]::GetDirectoryName($new)) { "renamed" } else { "moved" }
            if ($global:FimKnownFiles.ContainsKey($old)) {
                $global:FimKnownFiles[$new] = $global:FimKnownFiles[$old]
                $global:FimKnownFiles.Remove($old)
            }
            Send-FimEvent -Action $action -FullPath $new -Destination $old
        } catch { Write-FimDiag "ERROR in Renamed handler: $($_.Exception.Message) | $($_.ScriptStackTrace)" }
    } | Out-Null

    # Recovers from an internal buffer overflow (see InternalBufferSize note
    # above) - without this, the watcher silently stops reporting changes
    # forever after the first overflow, with no visible error to anyone not
    # watching this console. $Event.Sender is the FileSystemWatcher instance
    # itself, so this doesn't depend on closing over the loop's $path variable.
    Register-ObjectEvent -InputObject $watcher -EventName Error -SourceIdentifier "FIM_Error_$path" -Action {
        $w = $Event.Sender
        Write-FimDiag "WATCHER ERROR on $($w.Path) (likely internal buffer overflow) - resetting"
        try {
            $w.EnableRaisingEvents = $false
            Start-Sleep -Milliseconds 250
            $w.EnableRaisingEvents = $true
        } catch {
            Write-FimDiag "Failed to reset watcher for $($w.Path): $($_.Exception.Message)"
        }
    } | Out-Null

    $global:FimWatchers += $watcher
    Write-Host "Watching: $path (subfolders: $($watcher.IncludeSubdirectories))"
}

Write-Host "SOC Lab FIM watcher running. Watched types: $($global:FimConfig.watched_extensions -join ', ')"

# -- Idle loop: keep events flowing, hot-reload config, periodic reconciliation
try {
    $lastReload = Get-Date
    $lastReconcile = Get-Date
    while ($true) {
        Wait-Event -Timeout 5 | Remove-Event -ErrorAction SilentlyContinue

        $reloadEvery = 300
        if ($global:FimConfig.config_reload_seconds) { $reloadEvery = [int]$global:FimConfig.config_reload_seconds }

        if (((Get-Date) - $lastReload).TotalSeconds -ge $reloadEvery) {
            try {
                $global:FimConfig = Read-FimConfig -Path $global:FimConfigPath
                Write-Host "$(Get-Date -Format o)  Reloaded config - watched types: $($global:FimConfig.watched_extensions -join ', ')"
            } catch {
                Write-Warning "Config reload failed, keeping previous settings: $($_.Exception.Message)"
            }
            $lastReload = Get-Date
        }

        # Roll the event log before it can fill the disk. The Wazuh agent
        # tails this file, and its logcollector follows the rotation (it
        # re-opens on inode/size change), so events aren't lost across a roll.
        # One generation is kept - anything older has already been shipped to
        # the manager and lives in the alerts index.
        try {
            $maxLogMb = if ($global:FimConfig.max_log_mb) { [int]$global:FimConfig.max_log_mb } else { 50 }
            $logFile = Get-Item -LiteralPath $global:FimConfig.log_path -ErrorAction SilentlyContinue
            if ($logFile -and $logFile.Length -gt ($maxLogMb * 1MB)) {
                $rolled = "$($global:FimConfig.log_path).1"
                Move-Item -LiteralPath $logFile.FullName -Destination $rolled -Force -ErrorAction Stop
                Write-FimDiag "Rotated event log at $([math]::Round($logFile.Length/1MB,1)) MB -> $rolled"
            }
        } catch { Write-FimDiag "Log rotation failed: $($_.Exception.Message)" }

        $reconcileEvery = 120
        if ($global:FimConfig.reconciliation_scan_seconds) { $reconcileEvery = [int]$global:FimConfig.reconciliation_scan_seconds }

        if (((Get-Date) - $lastReconcile).TotalSeconds -ge $reconcileEvery) {
            try { Invoke-FimReconciliationScan }
            catch { Write-FimDiag "ERROR in reconciliation scan: $($_.Exception.Message)" }
            $lastReconcile = Get-Date
        }
    }
} finally {
    Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like "FIM_*" } | Unregister-Event
    foreach ($w in $global:FimWatchers) { $w.Dispose() }
}

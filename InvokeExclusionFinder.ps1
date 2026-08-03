<#
.SYNOPSIS
    SharpExclusionFinder (PS) v2.0
    Authors: Hoshea Yarden, Hai Vaknin, Yehuda Smirnov, Noam Pomerantz, Kasem545
.DESCRIPTION
    Find Windows Defender exclusion paths via Event Log (Event ID 5007) and/or brute-force MpCmdRun probing.
.NOTES
    Only use on systems you are authorized to test.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$BasePath,

    [ValidateSet("bruteforce","eventlog","both")]
    [string]$Method = "bruteforce",

    [int]$MaxThreads = 3,
    [int]$Depth = [int]::MaxValue,
    [string]$Output,

    [switch]$Trace,
    [switch]$h,
    [switch]$Help
)

function NC([int[]]$c) { -join ($c | ForEach-Object { [char]$_ }) }

$script:dSwd = NC @(87,105,110,100,111,119,115,32,68,101,102,101,110,100,101,114)
$script:dSmp = NC @(77,112,67,109,100,82,117,110,46,101,120,101)
$script:dPmp = (NC @(67,58,92,80,114,111,103,114,97,109,32,70,105,108,101,115,92)) + $script:dSwd + "\" + $script:dSmp
$script:dEln = (NC @(77,105,99,114,111,115,111,102,116,45,87,105,110,100,111,119,115,45)) + $script:dSwd + (NC @(47,79,112,101,114,97,116,105,111,110,97,108))

$_hk = NC @(72,75,76,77)
$_so = NC @(83,79,70,84,87,65,82,69)
$_ms = NC @(77,105,99,114,111,115,111,102,116)
$_ex = NC @(69,120,99,108,117,115,105,111,110,115)

$script:dRegPath = "{0}\{1}\{2}\{3}\{4}\{5}" -f $_hk, $_so, $_ms, $script:dSwd, $_ex, (NC @(80,97,116,104,115))
$script:dRegExt  = "{0}\{1}\{2}\{3}\{4}\{5}" -f $_hk, $_so, $_ms, $script:dSwd, $_ex, (NC @(69,120,116,101,110,115,105,111,110,115))
$script:dRegProc = "{0}\{1}\{2}\{3}\{4}\{5}" -f $_hk, $_so, $_ms, $script:dSwd, $_ex, (NC @(80,114,111,99,101,115,115,101,115))

$script:dSkip = NC @(119,97,115,32,115,107,105,112,112,101,100)
$script:dArgs = NC @(45,83,99,97,110,32,45,83,99,97,110,84,121,112,101,32,51,32,45,70,105,108,101,32)
$script:dExt  = NC @(92,92,63,92)
$script:dExcl = NC @(69,120,99,108,117,115,105,111,110,115)
$script:dGwe  = NC @(71,101,116,45,87,105,110,69,118,101,110,116)

$script:Excl   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:Supp   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:Cntr   = 0
$script:Total  = 0
$script:MaxThr = 3
$script:MaxDpt = [int]::MaxValue
$script:Sw     = [System.Diagnostics.Stopwatch]::new()
$script:Log    = $null
$script:Verb   = $false
$script:Lock   = [System.Object]::new()

function script:NormPath([string]$p) {
    try { return [System.IO.Path]::GetFullPath($p) } catch { return $p }
}

function script:Test-SuppressDir([string]$d) {
    if ([string]::IsNullOrWhiteSpace($d)) { return $false }
    $n = $d.Trim().TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $script:Supp.Contains($n)
}

function script:Write-Out([string]$msg, [switch]$IsErr) {
    if ($msg -and $msg -imatch "access denied") { return }
    $isHit = $msg -match '\[\+\]' -or $msg -match '\[-\]' -or $msg -match '\[~\]'
    if ($script:Log -and ($IsErr -or $isHit)) {
        [System.Threading.Monitor]::Enter($script:Lock)
        try { Add-Content -Path $script:Log -Value $msg -ErrorAction SilentlyContinue }
        finally { [System.Threading.Monitor]::Exit($script:Lock) }
    }
    if ($IsErr -or $isHit -or $script:Verb) {
        $orig = [Console]::ForegroundColor
        if     ($IsErr)                { [Console]::ForegroundColor = [ConsoleColor]::Red    }
        elseif ($msg -match '\[\+\]')  { [Console]::ForegroundColor = [ConsoleColor]::Green  }
        elseif ($msg -match '\[-\]')   { [Console]::ForegroundColor = [ConsoleColor]::Red    }
        elseif ($msg -match '\[~\]')   { [Console]::ForegroundColor = [ConsoleColor]::Yellow }
        [Console]::WriteLine($msg)
        [Console]::ForegroundColor = $orig
    }
}

function script:Invoke-Proc([string]$exe, [string]$procArgs) {
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $exe
        $psi.Arguments              = $procArgs
        $psi.RedirectStandardOutput = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $out  = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        return $out
    } catch {
        Write-Out -Msg ("{0}: {1}" -f (NC @(69,114,114,111,114)), $_.Exception.Message) -IsErr
        return [string]::Empty
    }
}

function script:Test-ParentExcluded([string]$dir) {
    $parent = [System.IO.Path]::GetDirectoryName($dir)
    while (-not [string]::IsNullOrEmpty($parent)) {
        if ($script:Excl.Contains((NormPath $parent))) { return $true }
        $parent = [System.IO.Path]::GetDirectoryName($parent)
    }
    return $false
}

function script:Test-DirOrAncestorExcluded([string]$dir) {
    $cur = $dir
    while (-not [string]::IsNullOrEmpty($cur)) {
        if ($script:Excl.Contains((NormPath $cur))) { return $true }
        $cur = [System.IO.Path]::GetDirectoryName($cur)
    }
    return $false
}

function script:Get-ExclViaEventLog {
    try {
        $evId = 5007
        $gweCmd = Get-Command $script:dGwe -ErrorAction SilentlyContinue
        if ($null -eq $gweCmd) {
            Write-Out -Msg ("{0}: {1}" -f (NC @(69,114,114,111,114)), "Get-WinEvent not available.") -IsErr
            return
        }

        $events = & $gweCmd -FilterHashtable @{ LogName = $script:dEln; Id = $evId } -ErrorAction SilentlyContinue
        if (-not $events) {
            if ($script:Verb) { [Console]::WriteLine("No exclusion events found in log.") }
            return
        }

        $events = @($events)
        $rxPaths = [Regex]::new(([Regex]::Escape($script:dRegPath) + "\\([^=\r\n]+)"), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $rxExts  = [Regex]::new(([Regex]::Escape($script:dRegExt)  + "\\([^=\r\n]+)"), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $rxProcs = [Regex]::new(([Regex]::Escape($script:dRegProc) + "\\([^=\r\n]+)"), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        $hits = [System.Collections.Generic.List[object]]::new()

        foreach ($evt in $events) {
            $msg = $evt.Message
            if (-not $msg -or -not $msg.Contains($script:dExcl)) { continue }

            $action = "unknown"
            $lines  = $msg -split "[\r\n]" | Where-Object { $_.Trim() -ne "" }
            $inOld = $false; $inNew = $false; $hasOld = $false; $hasNew = $false

            foreach ($ln in $lines) {
                $t = $ln.Trim()
                $isOldHdr = $t.StartsWith("Old value:", [StringComparison]::OrdinalIgnoreCase)
                $isNewHdr = $t.StartsWith("New value:", [StringComparison]::OrdinalIgnoreCase)
                if ($isOldHdr) {
                    $inOld = $true; $inNew = $false
                    if ($t.Length -gt 10 -and $t.Contains($script:dExcl)) { $hasOld = $true }
                } elseif ($isNewHdr) {
                    $inNew = $true; $inOld = $false
                    if ($t.Length -gt 10 -and $t.Contains($script:dExcl)) { $hasNew = $true }
                } elseif ($inOld -and $t.Contains($script:dExcl)) {
                    $hasOld = $true
                } elseif ($inNew -and $t.Contains($script:dExcl)) {
                    $hasNew = $true
                }
            }

            if     ($hasNew -and -not $hasOld) { $action = "added"    }
            elseif ($hasOld -and -not $hasNew) { $action = "deleted"  }
            elseif ($hasOld -and $hasNew)      { $action = "modified" }

            $ts = if ($evt.TimeCreated) { $evt.TimeCreated } else { [DateTime]::Now }

            foreach ($m in $rxPaths.Matches($msg)) {
                if ($m.Groups.Count -gt 1) {
                    $ep = $m.Groups[1].Value.Trim().Replace($script:dExt, "").Trim()
                    if (-not [string]::IsNullOrWhiteSpace($ep)) {
                        $hits.Add([pscustomobject]@{ Action=$action; Type=(NC @(80,97,116,104)); Path=$ep; TS=$ts })
                    }
                }
            }
            foreach ($m in $rxExts.Matches($msg)) {
                if ($m.Groups.Count -gt 1) {
                    $ep = $m.Groups[1].Value.Trim().Replace($script:dExt, "").Trim()
                    if (-not [string]::IsNullOrWhiteSpace($ep)) {
                        $hits.Add([pscustomobject]@{ Action=$action; Type=(NC @(69,120,116,101,110,115,105,111,110)); Path=$ep; TS=$ts })
                    }
                }
            }
            foreach ($m in $rxProcs.Matches($msg)) {
                if ($m.Groups.Count -gt 1) {
                    $ep = $m.Groups[1].Value.Trim().Replace($script:dExt, "").Trim()
                    if (-not [string]::IsNullOrWhiteSpace($ep)) {
                        $hits.Add([pscustomobject]@{ Action=$action; Type=(NC @(80,114,111,99,101,115,115)); Path=$ep; TS=$ts })
                    }
                }
            }
        }

        $sorted = $hits | Sort-Object TS
        if ($sorted -and $sorted.Count -gt 0) {
            $bar = "=" * 120
            [Console]::WriteLine($bar)
            [Console]::WriteLine("{0,-10} {1,-12} {2,-70} {3,-25}" -f "Action", "Type", "Path", "Timestamp")
            [Console]::WriteLine($bar)

            foreach ($e in $sorted) {
                $aStr = switch ($e.Action) {
                    "added"    { "[+] Added"    }
                    "deleted"  { "[-] Deleted"  }
                    "modified" { "[~] Modified" }
                    default    { "[?] Unknown"  }
                }
                $trunc = if ($e.Path.Length -gt 70) { $e.Path.Substring(0, 67) + "..." } else { $e.Path }
                $tsStr = $e.TS.ToString("MM/dd/yyyy hh:mm:ss tt")
                $orig = [Console]::ForegroundColor
                switch ($e.Action) {
                    "added"    { [Console]::ForegroundColor = [ConsoleColor]::Green  }
                    "deleted"  { [Console]::ForegroundColor = [ConsoleColor]::Red    }
                    "modified" { [Console]::ForegroundColor = [ConsoleColor]::Yellow }
                }
                $row = "{0,-10} {1,-12} {2,-70} {3,-25}" -f $aStr, $e.Type, $trunc, $tsStr
                [Console]::WriteLine($row)
                [Console]::ForegroundColor = $orig
                if ($script:Log) {
                    [System.Threading.Monitor]::Enter($script:Lock)
                    try { Add-Content -Path $script:Log -Value $row -ErrorAction SilentlyContinue }
                    finally { [System.Threading.Monitor]::Exit($script:Lock) }
                }
            }
            [Console]::WriteLine($bar)
        }
    } catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        Write-Out -Msg ("{0}: Defender event log not found." -f (NC @(69,114,114,111,114))) -IsErr
    } catch [System.UnauthorizedAccessException] {
        Write-Out -Msg ("{0}: Access denied to event logs. Run elevated." -f (NC @(69,114,114,111,114))) -IsErr
    } catch {
        Write-Out -Msg ("{0}: {1}" -f (NC @(69,114,114,111,114)), $_.Exception.Message) -IsErr
    }
}

function script:Scan-Dir([string]$path) {
    try {
        $script:Cntr++
        if ($script:Cntr % 500 -eq 0 -and $script:Verb) {
            $el = $script:Sw.Elapsed
            [Console]::WriteLine("Processed $($script:Cntr) dirs. Elapsed: $([Math]::Round($el.TotalSeconds, 2))s.")
        }
        $probeArg = "{0}`"{1}\|*`"" -f $script:dArgs, $path
        $out = Invoke-Proc $script:dPmp $probeArg
        if ($out -and $out.Contains($script:dSkip)) {
            $script:Excl.Add((NormPath $path)) | Out-Null
            if (-not (Test-ParentExcluded $path)) {
                Write-Out -Msg "[+] Folder $path is excluded"
            }
        }
    } catch [System.UnauthorizedAccessException] {
    } catch {
        Write-Out -Msg "Error scanning ${path}: $($_.Exception.Message)" -IsErr
    }
}

function script:Get-ExclViaBruteForce([string]$basePath) {
    $depth = 0
    $baseOut = Invoke-Proc $script:dPmp ("{0}`"{1}\|*`"" -f $script:dArgs, $basePath)
    if ($baseOut -and $baseOut.Contains($script:dSkip)) {
        Write-Out -Msg "[+] Folder $basePath is excluded"
        $script:Excl.Add((NormPath $basePath)) | Out-Null
        $script:Sw.Stop()
        if ($script:Verb) { [Console]::WriteLine("Base path excluded. Elapsed: $([Math]::Round($script:Sw.Elapsed.TotalSeconds, 2))s.") }
        return
    }

    $queue = [System.Collections.Generic.Queue[System.Collections.Generic.List[string]]]::new()
    $tier0 = [System.Collections.Generic.List[string]]::new()

    try {
        [IO.Directory]::GetDirectories($basePath) | ForEach-Object { $tier0.Add($_) }
        $queue.Enqueue($tier0)
    } catch {
        Write-Out -Msg "Error listing ${basePath}: $($_.Exception.Message)" -IsErr
    }

    while ($queue.Count -gt 0 -and $depth -le $script:MaxDpt) {
        $tier = $queue.Dequeue()
        $script:Total += $tier.Count
        $work = [System.Collections.Generic.List[string]]::new()
        foreach ($d in $tier) {
            if (-not (Test-DirOrAncestorExcluded $d)) { $work.Add($d) }
        }
        foreach ($d in $work) { Scan-Dir $d }
        $next = [System.Collections.Generic.List[string]]::new()
        foreach ($d in $work) {
            try {
                [IO.Directory]::GetDirectories($d) | ForEach-Object { $next.Add($_) }
            } catch [System.UnauthorizedAccessException] {
                if (-not (Test-SuppressDir $d)) {
                    Write-Out -Msg "Access denied to $d. Skipping." -IsErr
                }
            } catch {
                Write-Out -Msg "Error listing subdirs of ${d}: $($_.Exception.Message)" -IsErr
            }
        }
        if ($next.Count -gt 0) { $queue.Enqueue($next) }
        $depth++
    }

    if ($depth -le $script:MaxDpt) {
        $script:Sw.Stop()
        if ($script:Verb) {
            [Console]::WriteLine("Scan complete (depth $($script:MaxDpt)). Elapsed: $([Math]::Round($script:Sw.Elapsed.TotalSeconds, 2))s.")
        }
    }
}

function Invoke-FindExclusion {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$BasePath,
        [ValidateSet("bruteforce","eventlog","both")]
        [string]$Method = "bruteforce",
        [int]$MaxThreads = 3,
        [int]$Depth = [int]::MaxValue,
        [string]$Output,
        [switch]$Trace
    )

    $script:MaxThr = $MaxThreads
    $script:MaxDpt = $Depth
    $script:Verb   = [bool]$Trace
    $script:Log    = $Output

    if ($Method -in @("bruteforce","both") -and [string]::IsNullOrEmpty($BasePath)) {
        [Console]::WriteLine("Error: BasePath required for bruteforce method.")
        return
    }

    $script:Sw.Restart()

    if ($Method -in @("eventlog","both")) {
        Get-ExclViaEventLog
        if ($Method -eq "eventlog") {
            $script:Sw.Stop()
            if ($script:Verb) { [Console]::WriteLine("Event log scan done. Elapsed: $([Math]::Round($script:Sw.Elapsed.TotalSeconds, 2))s.") }
        }
    }

    if ($Method -in @("bruteforce","both")) {
        if ($Method -eq "both" -and $script:Verb) { [Console]::WriteLine("`n[*] Starting brute-force scan...") }
        Get-ExclViaBruteForce $BasePath
    }
}

function Show-ExclusionHelp {
    $bar = "=" * 60
    [Console]::WriteLine("")
    [Console]::WriteLine($bar)
    [Console]::WriteLine("  SharpExclusionFinder (PS) v2.0")
    [Console]::WriteLine("  Authors: Hoshea Yarden, Hai Vaknin, Yehuda Smirnov, Noam Pomerantz, Kasem545")
    [Console]::WriteLine($bar)
    [Console]::WriteLine("")
    [Console]::WriteLine("  Find Windows Defender exclusion paths via Event Log")
    [Console]::WriteLine("  (Event ID 5007) and/or brute-force MpCmdRun probing.")
    [Console]::WriteLine("")
    [Console]::WriteLine("USAGE:")
    [Console]::WriteLine("  .\InvokeExclusionFinder.ps1 [<BasePath>] [options]")
    [Console]::WriteLine("  Invoke-FindExclusion [-BasePath] <path> [options]")
    [Console]::WriteLine("")
    [Console]::WriteLine("OPTIONS:")
    [Console]::WriteLine("  <BasePath>           Root dir for bruteforce (positional)")
    [Console]::WriteLine("  -Method <type>       bruteforce (default), eventlog, or both")
    [Console]::WriteLine("  -MaxThreads N        Reserved (sequential scan for OPSEC)")
    [Console]::WriteLine("  -Depth N             Max directory depth for bruteforce")
    [Console]::WriteLine("  -Output <filePath>   Log exclusions and errors to file")
    [Console]::WriteLine("  -Trace               Show all output (progress, errors)")
    [Console]::WriteLine("  -h, -Help            Show this help menu")
    [Console]::WriteLine("")
    [Console]::WriteLine("METHODS:")
    [Console]::WriteLine("  eventlog    Read Defender Event ID 5007 (zero process spawns)")
    [Console]::WriteLine("  bruteforce  Probe each dir via MpCmdRun (noisy but thorough)")
    [Console]::WriteLine("  both        Run eventlog first, then bruteforce")
    [Console]::WriteLine("")
    [Console]::WriteLine("EXAMPLES:")
    [Console]::WriteLine("  .\InvokeExclusionFinder.ps1 -Method eventlog")
    [Console]::WriteLine("  .\InvokeExclusionFinder.ps1 C:\Users -Method bruteforce")
    [Console]::WriteLine("  .\InvokeExclusionFinder.ps1 C:\Users -Method both -Trace")
    [Console]::WriteLine("  .\InvokeExclusionFinder.ps1 C:\ -Depth 2 -Output C:\temp\out.txt")
    [Console]::WriteLine("")
    [Console]::WriteLine("  . .\InvokeExclusionFinder.ps1")
    [Console]::WriteLine("  Invoke-FindExclusion -Method eventlog")
    [Console]::WriteLine("")
    [Console]::WriteLine($bar)
    [Console]::WriteLine("")
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($h -or $Help) { Show-ExclusionHelp; return }
    if ($PSBoundParameters.Count -eq 0) { Show-ExclusionHelp; return }
    if ($Method -in @("bruteforce","both") -and [string]::IsNullOrEmpty($BasePath)) {
        [Console]::WriteLine("Error: BasePath required for bruteforce method.")
        [Console]::WriteLine("")
        Show-ExclusionHelp
        return
    }
    $invokeParams = @{ Method = $Method; MaxThreads = $MaxThreads; Depth = $Depth }
    if ($BasePath) { $invokeParams.BasePath = $BasePath }
    if ($Output)   { $invokeParams.Output   = $Output }
    if ($Trace)    { $invokeParams.Trace    = [switch]$true }
    Invoke-FindExclusion @invokeParams
}

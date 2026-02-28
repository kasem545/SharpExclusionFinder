# SharpExclusionFinder

## Overview

This C# tool discovers Windows Defender exclusions using two methods: **Event Log analysis** and **Brute-force scanning**. Either method can run independently or combined for maximum coverage.

- **Event Log Method** — Fast extraction from Windows Defender Event Logs (Event ID 5007). Shows added/deleted exclusions with color-coded table output.
- **Brute-force Method** — Scans directories using `MpCmdRun.exe` to detect excluded paths without admin privileges.
- **Combined Mode** — Run both for comprehensive detection.

## Usage

```powershell
SharpExclusionFinder.exe [<BasePath>] [options]
```

### Options

| Option | Description |
|---|---|
| `--method <type>` | Detection method: `bruteforce` (default), `eventlog`, or `both` |
| `--max-threads N` | Max threads for scanning (default 3, bruteforce only) |
| `--depth N` | Max directory depth to scan (bruteforce only) |
| `--output <filePath>` | Log results to file |
| `-Verbose` | Show progress, errors, and debug info |
| `-h`, `--help` | Display help |

### Examples

```powershell
# Event Log method (fast, requires admin)
SharpExclusionFinder.exe --method eventlog

# Brute-force method (stealthy, no admin needed)
SharpExclusionFinder.exe C:\Users --method bruteforce --max-threads 5 --depth 3

# Combined mode with verbose output and file logging
SharpExclusionFinder.exe C:\Users --method both -Verbose --output results.txt
```

## Detection Methods

### 1. Event Log Method (`--method eventlog`)

| Property | Value |
|---|---|
| **Speed** | Very fast (seconds) |
| **Admin Required** | Yes |
| **Stealth** | High (reads existing logs) |
| **Coverage** | Paths, extensions, and process exclusions |

Parses Event ID 5007 from `Microsoft-Windows-Windows Defender/Operational` log.

### 2. Brute-force Method (`--method bruteforce`)

| Property | Value |
|---|---|
| **Speed** | Slower (depends on directory count) |
| **Admin Required** | No |
| **Stealth** | Medium (executes MpCmdRun.exe) |
| **Coverage** | Excluded directories only |

Tests each directory with `MpCmdRun.exe -Scan` and detects "skipped" responses. Automatically detects root exclusions — if a parent directory is excluded, subdirectories are not reported.

### 3. Both Methods (`--method both`)

Combines Event Log analysis with brute-force scanning for maximum coverage.

**Blog post**: https://blog.fndsec.net/2024/10/04/uncovering-exclusion-paths-in-microsoft-defender-a-security-research-insight

## Example Output

**Event Log method** — color-coded table (green = added, red = deleted):
```
========================================================================================================================
Action     Type         Path                                                                   Timestamp
========================================================================================================================
[+] Added  Path         D:\work                                                                02/28/2026 02:38:18 AM
[-] Deleted Path        C:\Users\x\OneDrive\Desktop\test\                                      02/28/2026 02:39:41 AM
[-] Deleted Path        C:\Users\x\AppData\Roaming\configs                                     02/28/2026 02:39:47 AM
[+] Added  Extension    *.iso                                                                  02/28/2026 02:41:06 AM
[-] Deleted Extension   *.iso                                                                  02/28/2026 02:41:22 AM
[+] Added  Path         C:\Users\x\OneDrive\Desktop\script                                     02/28/2026 02:45:11 AM
========================================================================================================================
```

**Brute-force method:**
```
[+] Folder C:\Users\Public is excluded
```

**Brute-force with `-Verbose`:**
```
Processed 500 directories. Time elapsed: 5.23 seconds.
[+] Folder C:\Users\Public is excluded
Processed 1000 directories. Time elapsed: 12.41 seconds.
Scan completed up to depth 2147483647. Total time: 15.80 seconds.
```

## Prerequisites

- **.NET Framework 4.5.2** or later
- **Windows Defender** installed and enabled
- **Administrator privileges** (Event Log method only)
- **MpCmdRun.exe** at `C:\Program Files\Windows Defender\MpCmdRun.exe` (brute-force method only)

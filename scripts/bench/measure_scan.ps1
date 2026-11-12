# Runs the `scan` example over a fixture and records peak working set, result JSON size and
# walk time (M3 verification 4-1). The fixture stands in for the user folder: it is passed as
# `--root`, and USERPROFILE is pointed at it too for builds from before `--root` existed.
#
#   powershell -File scripts/bench/measure_scan.ps1 -Exe <path to scan.exe> -Fixture <dir> [-Runs 3]

param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $Fixture,
    [int] $Runs = 3
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Mem {
    [StructLayout(LayoutKind.Sequential)]
    public struct Counters {
        public uint cb; public uint PageFaultCount;
        public UIntPtr PeakWorkingSetSize; public UIntPtr WorkingSetSize;
        public UIntPtr QuotaPeakPagedPoolUsage; public UIntPtr QuotaPagedPoolUsage;
        public UIntPtr QuotaPeakNonPagedPoolUsage; public UIntPtr QuotaNonPagedPoolUsage;
        public UIntPtr PagefileUsage; public UIntPtr PeakPagefileUsage;
    }
    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool GetProcessMemoryInfo(IntPtr h, out Counters c, uint cb);
    // Works on an exited process while its handle is still open.
    public static ulong Peak(IntPtr h) {
        Counters c; c.cb = (uint)Marshal.SizeOf(typeof(Counters));
        if (!GetProcessMemoryInfo(h, out c, c.cb)) throw new System.ComponentModel.Win32Exception();
        return c.PeakWorkingSetSize.ToUInt64();
    }
}
"@

$out = Join-Path $env:TEMP "clearcache-bench"
New-Item -ItemType Directory -Force $out | Out-Null

$rows = @()
for ($i = 0; $i -le $Runs; $i++) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    # `--root` for builds after the shell-folder change; older builds ignore it and use USERPROFILE.
    $psi.Arguments = "--target user_home --root `"$Fixture`" --json"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables["USERPROFILE"] = $Fixture
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    $peak = [Mem]::Peak($p.Handle)
    $json = $stdout.Result
    $log = $stderr.Result
    if ($p.ExitCode -ne 0) { throw "scan failed ($($p.ExitCode)): $log" }
    $jsonPath = Join-Path $out "result-$i.json"
    [System.IO.File]::WriteAllText($jsonPath, $json)
    $compact = (ConvertFrom-Json $json | ConvertTo-Json -Depth 64 -Compress)
    $walk = [regex]::Match($log, "walk=(\d+) ms").Groups[1].Value
    $files = [regex]::Match($log, "files=(\d+)").Groups[1].Value
    $nodes = ([regex]::Matches($json, '"parent_id"')).Count
    $row = [pscustomobject]@{
        run          = if ($i -eq 0) { "warm-up" } else { "$i" }
        files        = [int]$files
        nodes        = $nodes
        walk_ms      = [int]$walk
        peak_ws_mib  = [math]::Round($peak / 1MB, 1)
        json_kib     = [math]::Round([System.Text.Encoding]::UTF8.GetByteCount($json) / 1KB, 1)
        compact_kib  = [math]::Round([System.Text.Encoding]::UTF8.GetByteCount($compact) / 1KB, 1)
    }
    $rows += $row
}
$rows | Format-Table -AutoSize | Out-String -Width 200

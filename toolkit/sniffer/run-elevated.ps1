[CmdletBinding()]
param(
    [string]$Interface,
    [string]$Read,
    [string]$Filter,
    [string]$Write,
    [int]$Count,
    [double]$Duration,
    [switch]$Lines,
    [switch]$AlertsOnly,
    [switch]$ListInterfaces,
    [switch]$ShowRules,
    [switch]$MakeSample,
    [ValidateSet("auto", "raw", "scapy")]
    [string]$Backend = "auto",
    [string]$JsonAlerts,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Extra
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Get-PythonCommand {
    foreach ($candidate in @("py", "python", "python3")) {
        $found = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($found) {
            if ($candidate -eq "py") { return @("py", "-3") }
            return @($candidate)
        }
    }
    throw "Python was not found. Install it with: winget install OpenJS.Python.3.12  (or from python.org) and reopen PowerShell."
}

$python = Get-PythonCommand
$exe = $python[0]
$prefix = @()
if ($python.Count -gt 1) { $prefix = $python[1..($python.Count - 1)] }

if ($MakeSample) {
    & $exe @($prefix + @("tools\make_sample_pcap.py", "sample.pcap"))
    if (-not $Read) { $Read = "sample.pcap" }
    if (-not $Lines) { $Lines = $true }
}

$netscopeArgs = @("-m", "netscope")
if ($ListInterfaces) { $netscopeArgs += "--list-interfaces" }
if ($ShowRules)      { $netscopeArgs += "--show-rules" }
if ($Interface)      { $netscopeArgs += @("-i", $Interface) }
if ($Read)           { $netscopeArgs += @("-r", $Read) }
if ($Filter)         { $netscopeArgs += @("-f", $Filter) }
if ($Write)          { $netscopeArgs += @("-w", $Write) }
if ($Count)          { $netscopeArgs += @("-c", $Count) }
if ($Duration)       { $netscopeArgs += @("-t", $Duration) }
if ($Lines)          { $netscopeArgs += "--lines" }
if ($AlertsOnly)     { $netscopeArgs += "--alerts-only" }
if ($JsonAlerts)     { $netscopeArgs += @("--json-alerts", $JsonAlerts) }
if ($Backend -ne "auto") { $netscopeArgs += @("--backend", $Backend) }
if ($Extra)          { $netscopeArgs += $Extra }

if ($netscopeArgs.Count -eq 2) {
    & $exe @($prefix + $netscopeArgs + @("--help"))
    exit 0
}

$needsAdmin = [bool]$Interface -and -not $Read
$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($needsAdmin -and -not $isAdmin) {
    Write-Host "Live capture needs Administrator rights - opening an elevated window..." -ForegroundColor Yellow
    $quoted = $netscopeArgs | ForEach-Object { '"' + ($_ -replace '"', '`"') + '"' }
    $inner = "Set-Location '$PSScriptRoot'; & $exe $($prefix -join ' ') $($quoted -join ' '); Write-Host ''; Read-Host 'Press Enter to close'"
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $inner)
    exit 0
}

if ($needsAdmin) {
    Write-Host "Capturing on '$Interface'. Press Ctrl+C to stop." -ForegroundColor Cyan
    Write-Host "Tip: for full layer-2 capture install Npcap + 'pip install scapy' and add -Backend scapy." -ForegroundColor DarkGray
}

& $exe @($prefix + $netscopeArgs)
exit $LASTEXITCODE

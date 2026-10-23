<#
.SYNOPSIS
    Streams one of the test VM's COM ports to this console and to a log in
    run\: by default COM2, Aleph0's output, into run\serial.log.

.DESCRIPTION
    Hyper-V exposes a VM's COM port as a named pipe (configured by
    run-hyperv.ps1 with Set-VMComPort). Hyper-V is the pipe server; this
    script connects as the client and prints each line the hypervisor sends.

    Output written while no client is connected is dropped, so connect as
    soon as the VM starts. run-hyperv.ps1 does that automatically; run this
    script on its own to reattach to a VM that is already running.

    Requires an elevated PowerShell session (the pipe is only open to
    administrators). Reading ends when the VM turns off; Ctrl+C also stops it
    once the next line arrives.

.PARAMETER PipeName
    Pipe name without the \\.\pipe\ prefix. Must match run-hyperv.ps1:
    aleph0-com2 for Aleph0's output (the default), aleph0-com1 for the
    guest's COM1.

.PARAMETER LogName
    File in run\ the lines are saved to: serial.log by default; run-hyperv.ps1
    saves the guest's COM1 to guest-serial.log.

.PARAMETER Quiet
    Save the lines without printing them. run-hyperv.ps1 reads COM1 this way,
    so the console shows Aleph0's lines only.

.PARAMETER TimeoutSeconds
    How long to keep retrying while the VM is starting and the pipe does
    not exist yet.
#>
param(
    [string]$PipeName      = "aleph0-com2",
    [string]$LogName       = "serial.log",
    [switch]$Quiet,
    [int]$TimeoutSeconds   = 30
)

# See run.ps1 for why $ErrorActionPreference is not set to "Stop" globally.

$root    = Split-Path -Parent $PSScriptRoot   # this script lives in scripts/
$runDir  = Join-Path $root "run"
$logPath = Join-Path $runDir $LogName
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    ".", $PipeName, [System.IO.Pipes.PipeDirection]::InOut)

# The pipe only exists while the VM is running, so retry until it appears.
# run-hyperv.ps1 waits for this line before it starts the VM.
Write-Host "==> Waiting for \\.\pipe\$PipeName" -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while (-not $pipe.IsConnected) {
    try {
        # Waits up to 1 s for the pipe to appear; throws TimeoutException if
        # not. No sleep after it: the VM may start printing at once.
        $pipe.Connect(1000)
    } catch {
        Start-Sleep -Milliseconds 20
    }
    if (-not $pipe.IsConnected -and (Get-Date) -gt $deadline) {
        Write-Error "Could not connect to \\.\pipe\$PipeName within $TimeoutSeconds s. Is the VM running with COM1 attached?"
        $pipe.Dispose()
        exit 1
    }
}

Write-Host "==> Connected to \\.\pipe\$PipeName; logging to $logPath" -ForegroundColor Cyan

# One writer for the whole session. Add-Content opened and closed the file
# for every line, slow enough to fall behind a burst of output. AutoFlush
# keeps the file current for the -InjectNmi job, which reads it meanwhile
# (the writer shares the file for reading).
$writer = [System.IO.StreamWriter]::new($logPath, $false, [System.Text.Encoding]::ASCII)
$writer.AutoFlush = $true
$reader = [System.IO.StreamReader]::new($pipe, [System.Text.Encoding]::ASCII)
try {
    # ReadLine returns $null when Hyper-V closes the pipe (VM turned off).
    while ($null -ne ($line = $reader.ReadLine())) {
        if (-not $Quiet) { Write-Host $line }
        $writer.WriteLine($line)
    }
    Write-Host "==> Serial pipe closed (VM stopped)." -ForegroundColor Cyan
} finally {
    $reader.Dispose()
    $writer.Dispose()
    $pipe.Dispose()
}

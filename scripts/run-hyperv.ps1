<#
.SYNOPSIS
    Builds the hypervisor and boots it in a Hyper-V Gen 2 VM with nested
    virtualization enabled, so VMX is actually exposed to the guest.

    Requires an elevated PowerShell session and the Hyper-V role installed.

.PARAMETER VMName
    Name of the Hyper-V VM to create/reuse.

.PARAMETER MemoryMB
    Static startup memory. Nested virtualization requires Dynamic Memory off.

.PARAMETER Release
    Builds the release profile instead of debug.

.PARAMETER PipeName
    Named pipe COM2, Aleph0's serial output, is attached to (without the
    \\.\pipe\ prefix). Streamed to this console and run\serial.log.

.PARAMETER GuestPipeName
    Named pipe COM1, the guest's serial port, is attached to. Saved to
    run\guest-serial.log without being printed.

.PARAMETER NoSerial
    Do not read the COM ports after starting the VM. Both stay attached, so
    read-serial.ps1 can connect later.

.PARAMETER InjectNmi
    Gives the VM one vCPU and, as soon as serial shows the guest resumed
    after its first VMCALL, injects an NMI with Debug-VM. Tests NMI exiting
    and reinjection; the result appears on serial.

.PARAMETER Features
    Cargo features to build with, comma-separated, for the test-only
    switches in Cargo.toml: host-fault-test (the exit handler faults on
    purpose), host-nmi-test (with -InjectNmi, the NMI arrives while Aleph0
    runs in VMX root operation), unexpected-exit-test (the guest stops at
    main VMCALL #1 as an unexpected exit), or trace-exits (every VM exit
    printed in full).

.PARAMETER ProcessorCount
    vCPUs to give the VM: 2 by default, 1 with -InjectNmi, which refuses any
    other count.

.PARAMETER Kernel
    A Linux EFI image, such as run\linux\linux.efi from
    scripts/linux/build.sh, to put on the ESP as \EFI\aleph0\linux.efi, next
    to Aleph0.

.PARAMETER WithoutAleph0
    Boots the -Kernel image directly: it becomes \EFI\BOOT\BOOTX64.EFI in
    Aleph0's place, and Aleph0 is not built. Nothing writes COM2 then, and
    the kernel's console is COM1, so COM1 streams to this console (and
    run\guest-serial.log) instead.
#>
param(
    [string]$VMName   = "Aleph0Test",
    [int]$MemoryMB    = 2048,
    [switch]$Release,
    [string]$PipeName = "aleph0-com2",
    [string]$GuestPipeName = "aleph0-com1",
    [switch]$NoSerial,
    [switch]$InjectNmi,
    [string]$Features = "",
    [ValidateRange(1, 1024)]
    [int]$ProcessorCount = $(if ($InjectNmi) { 1 } else { 2 }),
    [string]$Kernel = "",
    [switch]$WithoutAleph0
)

# See run.ps1 for why $ErrorActionPreference is not set to "Stop" globally.

$espType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'   # EFI System Partition GPT type

$root         = Split-Path -Parent $PSScriptRoot   # this script lives in scripts/
$buildProfile = if ($Release) { "release" } else { "debug" }
$efiSrc       = Join-Path $root "target\x86_64-unknown-uefi\$buildProfile\aleph0hypervisor.efi"
$runDir       = Join-Path $root "run"
$vhdPath      = Join-Path $runDir "aleph0-esp.vhdx"

# 0. Preconditions
$isAdmin = ([System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent())
).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must run from an elevated PowerShell session."
    exit 1
}
if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    Write-Error "Hyper-V role not installed. Run: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All"
    exit 1
}
# The script turns the VM off hard and replaces its disks, so it must only
# ever touch its own VM. Its disks live in run\: the ESP, and the
# differencing disk Hyper-V makes from it for a checkpoint.
$existingVm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if ($existingVm) {
    $foreignDisks = Get-VMHardDiskDrive -VMName $VMName |
        Where-Object { -not "$($_.Path)".StartsWith("$runDir\", [System.StringComparison]::OrdinalIgnoreCase) }
    if ($foreignDisks) {
        Write-Error ("VM '$VMName' has disks outside ${runDir}: $(($foreignDisks | ForEach-Object Path) -join ', '). " +
            "Refusing to turn it off and reconfigure it; pass another -VMName.")
        exit 1
    }
}
# The NMI job triggers on a serial line; without the serial stream nothing
# writes serial.log, so the NMI would never be injected.
if ($InjectNmi -and $NoSerial) {
    Write-Error "-InjectNmi needs the serial stream; do not combine it with -NoSerial."
    exit 1
}
# Debug-VM may deliver the NMI to any vCPU, and only the one running Aleph0's
# guest turns it into a VM exit.
if ($InjectNmi -and $ProcessorCount -ne 1) {
    Write-Error "-InjectNmi needs one vCPU; do not combine it with -ProcessorCount $ProcessorCount."
    exit 1
}
if ($Kernel -and -not (Test-Path -LiteralPath $Kernel -PathType Leaf)) {
    Write-Error "Kernel image $Kernel not found; scripts/linux/build.sh builds run\linux\linux.efi."
    exit 1
}
if ($WithoutAleph0 -and -not $Kernel) {
    Write-Error "-WithoutAleph0 boots the -Kernel image; pass -Kernel."
    exit 1
}
# The NMI job waits for a line only Aleph0 prints.
if ($WithoutAleph0 -and $InjectNmi) {
    Write-Error "-InjectNmi needs Aleph0; do not combine it with -WithoutAleph0."
    exit 1
}

# 1. Build, unless Aleph0 is not on the ESP at all
if (-not $WithoutAleph0) {
    $cargoArgs = @("build")
    if ($Release) { $cargoArgs += "--release" }
    if ($Features) { $cargoArgs += @("--features", $Features) }
    Write-Host "==> cargo $($cargoArgs -join ' ')" -ForegroundColor Cyan
    Push-Location $root
    cargo @cargoArgs
    $buildExit = $LASTEXITCODE
    Pop-Location
    if ($buildExit -ne 0) {
        Write-Error "cargo build failed (exit code $buildExit)."
        exit $buildExit
    }
    if (-not (Test-Path $efiSrc)) {
        Write-Error "Compiled binary not found at $efiSrc"
        exit 1
    }
}

try {
    # 2. Stop the VM and detach the old disk so the VHDX can be rebuilt
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($vm -and $vm.State -ne 'Off') {
        Write-Host "==> Stopping $VMName" -ForegroundColor Cyan
        Stop-VM -Name $VMName -TurnOff -Force -ErrorAction Stop
    }
    if ($vm) {
        Get-VMHardDiskDrive -VMName $VMName | Remove-VMHardDiskDrive -ErrorAction Stop
    }

    # 3. Rebuild the ESP VHDX from scratch. Simplest way to refresh BOOTX64.EFI:
    #    once the partition carries the ESP GPT type it no longer takes a drive letter.
    New-Item -ItemType Directory -Force -ErrorAction Stop -Path $runDir | Out-Null
    if (Test-Path $vhdPath) {
        Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue
        Remove-Item -Force -ErrorAction Stop $vhdPath
    }

    Write-Host "==> Creating ESP disk $vhdPath" -ForegroundColor Cyan
    New-VHD -Path $vhdPath -SizeBytes 256MB -Dynamic -ErrorAction Stop | Out-Null

    $disk = Mount-VHD -Path $vhdPath -Passthru -ErrorAction Stop | Get-Disk
    try {
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop
        # Formatted as basic data first: Format-Volume needs a drive letter, and an
        # ESP-typed partition will not take one. The type is set afterwards.
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        Format-Volume -DriveLetter $part.DriveLetter -FileSystem FAT32 `
            -NewFileSystemLabel "ESP" -Confirm:$false -ErrorAction Stop | Out-Null

        $bootDir = "$($part.DriveLetter):\EFI\BOOT"
        New-Item -ItemType Directory -Force -ErrorAction Stop -Path $bootDir | Out-Null
        $bootImage = if ($WithoutAleph0) { $Kernel } else { $efiSrc }
        Copy-Item -Force -ErrorAction Stop -LiteralPath $bootImage -Destination (Join-Path $bootDir "BOOTX64.EFI")
        if ($Kernel) {
            $kernelDir = "$($part.DriveLetter):\EFI\aleph0"
            New-Item -ItemType Directory -Force -ErrorAction Stop -Path $kernelDir | Out-Null
            Copy-Item -Force -ErrorAction Stop -LiteralPath $Kernel -Destination (Join-Path $kernelDir "linux.efi")
        }

        $part | Set-Partition -GptType $espType -ErrorAction Stop
    } finally {
        Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue
    }

    # 4. Create or reconfigure the VM
    if (-not $vm) {
        Write-Host "==> Creating VM $VMName" -ForegroundColor Cyan
        New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ($MemoryMB * 1MB) `
            -NoVHD -ErrorAction Stop | Out-Null
        # No network adapter: nothing here needs one, and it keeps the nested setup simple.
        Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter -ErrorAction Stop
    }

    Add-VMHardDiskDrive -VMName $VMName -Path $vhdPath -ErrorAction Stop
    # Secure Boot off: the .efi is unsigned. Boot straight off the ESP disk.
    Set-VMFirmware -VMName $VMName -EnableSecureBoot Off -ErrorAction Stop
    Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMHardDiskDrive -VMName $VMName) -ErrorAction Stop
    # Nested virtualization requires static memory.
    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes ($MemoryMB * 1MB) -ErrorAction Stop
    Set-VMProcessor -VMName $VMName -Count $ProcessorCount -ExposeVirtualizationExtensions $true -ErrorAction Stop
    # COM ports -> named pipes. Gen 2 VMs have no COM ports in the UI; this
    # is the only way to attach them. Aleph0 prints on COM2; COM1 is the
    # guest's.
    Set-VMComPort -VMName $VMName -Number 1 -Path "\\.\pipe\$GuestPipeName" -ErrorAction Stop
    Set-VMComPort -VMName $VMName -Number 2 -Path "\\.\pipe\$PipeName" -ErrorAction Stop
} catch {
    Write-Error "Setup failed: $_"
    exit 1
}

# 5. Boot it and open the console (uefi::println writes to ConOut, i.e. the video console)
# A log left over from the previous run must not trigger the NMI job below,
# nor pass for this run's when a reader cannot connect.
$serialLog = Join-Path $runDir "serial.log"
Remove-Item -Force -ErrorAction SilentlyContinue $serialLog, (Join-Path $runDir "guest-serial.log")

# With -InjectNmi, a background job waits until the guest has resumed after
# its first VMCALL (it then sits in its wait loop) and injects one NMI.
# read-serial.ps1 below writes the log the job watches. The job is started
# before Start-VM so its start-up cost cannot delay anything after boot: the
# injection is a race against the guest's wait loop.
$nmiJob = $null
if ($InjectNmi) {
    Write-Host "==> NMI injection armed: waiting for 'resuming the guest' on serial" -ForegroundColor Cyan
    $nmiJob = Start-Job -ArgumentList $VMName, $serialLog -ScriptBlock {
        param($vmName, $logPath)
        # Load the module now so the first Debug-VM call is not slowed by
        # module auto-loading.
        Import-Module Hyper-V -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds(120)
        while ((Get-Date) -lt $deadline) {
            if ((Test-Path $logPath) -and (Select-String -Path $logPath -SimpleMatch 'resuming the guest' -Quiet)) {
                Debug-VM -Name $vmName -InjectNonMaskableInterrupt -Force -ErrorAction Stop
                return "NMI injected into $vmName at $(Get-Date -Format 'HH:mm:ss.fff')."
            }
            Start-Sleep -Milliseconds 200
        }
        return "No 'resuming the guest' line within 120 s; no NMI injected."
    }
}

# 6. Read both COM ports, with the readers waiting before the VM starts:
#    Hyper-V drops serial output written while no client is attached, and
#    Start-VM can return after Aleph0 has already printed its first lines.
#    Each reader runs as a job (in its own process, with this session's
#    elevation) and connects as soon as Start-VM creates its pipe. COM2,
#    Aleph0's output, streams to this console and run\serial.log; COM1, the
#    guest's, goes to run\guest-serial.log only. With -WithoutAleph0 nothing
#    writes COM2, so only COM1 is read, and it streams too. Ctrl+C stops the
#    streaming here; the jobs themselves end when the VM turns off.
function Start-SerialReader([string]$Pipe, [string]$Log, [switch]$Quiet) {
    Start-Job -ArgumentList (Join-Path $PSScriptRoot "read-serial.ps1"), $Pipe, $Log, $Quiet.IsPresent -ScriptBlock {
        param($readerScript, $pipeName, $logName, $quiet)
        & $readerScript -PipeName $pipeName -LogName $logName -Quiet:$quiet
    }
}

$serialJob = $null
$guestSerialJob = $null
if (-not $NoSerial) {
    if (-not $WithoutAleph0) {
        $serialJob = Start-SerialReader -Pipe $PipeName -Log "serial.log"
    }
    $guestSerialJob = Start-SerialReader -Pipe $GuestPipeName -Log "guest-serial.log" -Quiet:(-not $WithoutAleph0)
    # A reader's first output is its "Waiting for" line, printed right before
    # it starts connecting.
    $readyDeadline = (Get-Date).AddSeconds(30)
    foreach ($job in @($serialJob, $guestSerialJob) | Where-Object { $_ }) {
        while ($job.ChildJobs[0].Information.Count -eq 0 -and
               $job.State -in 'NotStarted', 'Running' -and
               (Get-Date) -lt $readyDeadline) {
            Start-Sleep -Milliseconds 50
        }
    }
}

Write-Host "==> Starting $VMName" -ForegroundColor Cyan
Start-VM -Name $VMName
vmconnect.exe localhost $VMName

if ($serialJob) {
    Receive-Job -Job $serialJob -Wait -AutoRemoveJob
}
if ($guestSerialJob) {
    # Only its own status lines, unless -WithoutAleph0: otherwise it saves the
    # guest's lines without printing.
    Receive-Job -Job $guestSerialJob -Wait -AutoRemoveJob
}

if ($nmiJob) {
    Receive-Job -Job $nmiJob -Wait -AutoRemoveJob | ForEach-Object {
        Write-Host "==> $_" -ForegroundColor Cyan
    }
}

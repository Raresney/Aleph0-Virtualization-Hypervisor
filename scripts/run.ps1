<#
.SYNOPSIS
    Builds the hypervisor, prepares an ESP disk layout, and starts QEMU with OVMF.

.PARAMETER Release
    Builds the release profile instead of debug.

.PARAMETER Clean
    Removes the esp/ folder before rebuilding it.
#>
param(
    [switch]$Release,
    [switch]$Clean
)

# $ErrorActionPreference is intentionally not set to "Stop": cargo/qemu write
# normal status text to stderr, and under "Stop" that gets treated as a
# terminating error whenever output is redirected or captured. Exit codes are
# checked explicitly after native commands instead.

$root      = Split-Path -Parent $PSScriptRoot   # this script lives in scripts/
$profile  = if ($Release) { "release" } else { "debug" }
$target    = "x86_64-unknown-uefi"
$efiSrc    = Join-Path $root "target\$target\$profile\aleph0hypervisor.efi"
$espDir    = Join-Path $root "esp"
$bootDir   = Join-Path $espDir "EFI\BOOT"
$ovmfDir   = Join-Path $root "ovmf"
$ovmfCode  = Join-Path $ovmfDir "OVMF_CODE.fd"
$ovmfVarsTemplate = Join-Path $ovmfDir "OVMF_VARS.fd"
$runDir    = Join-Path $root "run"
$ovmfVars  = Join-Path $runDir "OVMF_VARS.fd"
$guestSerialLog = Join-Path $runDir "guest-serial.log"

# 1. Build
Write-Host "==> cargo build $(if ($Release) { '--release' })" -ForegroundColor Cyan
if ($Release) {
    cargo build --release
} else {
    cargo build
}
if ($LASTEXITCODE -ne 0) {
    Write-Error "cargo build failed (exit code $LASTEXITCODE)."
    exit $LASTEXITCODE
}

if (-not (Test-Path $efiSrc)) {
    Write-Error "Compiled binary not found at $efiSrc"
    exit 1
}

try {
    # 2. ESP disk layout
    if ($Clean -and (Test-Path $espDir)) {
        Write-Host "==> Cleaning $espDir" -ForegroundColor Cyan
        Remove-Item -Recurse -Force -ErrorAction Stop $espDir
    }

    Write-Host "==> Preparing ESP layout in $espDir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -ErrorAction Stop -Path $bootDir | Out-Null
    Copy-Item -Force -ErrorAction Stop $efiSrc (Join-Path $bootDir "BOOTX64.EFI")

    # 3. OVMF firmware
    if (-not (Test-Path $ovmfCode) -or -not (Test-Path $ovmfVarsTemplate)) {
        Write-Error "OVMF_CODE.fd / OVMF_VARS.fd not found in $ovmfDir. Download them from rust-osdev/ovmf-prebuilt first."
        exit 1
    }

    New-Item -ItemType Directory -Force -ErrorAction Stop -Path $runDir | Out-Null
    if (-not (Test-Path $ovmfVars)) {
        Write-Host "==> Copying writable OVMF_VARS.fd to $runDir" -ForegroundColor Cyan
        Copy-Item -Force -ErrorAction Stop $ovmfVarsTemplate $ovmfVars
    }
} catch {
    Write-Error "File preparation failed: $_"
    exit 1
}

# 4. Locate the QEMU executable (may not be in this session's PATH yet)
$qemuExe = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
if ($qemuExe) {
    $qemuExe = $qemuExe.Source
} else {
    $fallback = "C:\Program Files\qemu\qemu-system-x86_64.exe"
    if (Test-Path $fallback) {
        $qemuExe = $fallback
    } else {
        Write-Error "qemu-system-x86_64 not found in PATH or at $fallback."
        exit 1
    }
}

# 5. Launch QEMU. The first -serial is COM1, the second COM2: Aleph0's
#    output (COM2) goes to this terminal, and COM1, where OVMF mirrors its
#    own console, to run\guest-serial.log, so each line shows up once.
Write-Host "==> Starting QEMU ($qemuExe); COM1 -> $guestSerialLog" -ForegroundColor Cyan
& $qemuExe `
    -drive "if=pflash,format=raw,readonly=on,file=$ovmfCode" `
    -drive "if=pflash,format=raw,file=$ovmfVars" `
    -drive "format=raw,file=fat:rw:$espDir" `
    -net none `
    -serial "file:$guestSerialLog" `
    -serial stdio `
    -machine q35

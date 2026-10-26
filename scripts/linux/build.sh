#!/usr/bin/env bash
# Builds the first-boot Linux target: a pinned LTS kernel with the EFI stub,
# its command line and a busybox initramfs built in, as one file the firmware
# can start. For Linux or WSL; docs/LINUX_GUEST.md lists the packages it needs.
#
# Writes linux.efi, System.map and the final .config to run/linux/. Sources and
# the build tree go to $ALEPH0_LINUX_WORK (default ~/.cache/aleph0-linux), which
# must be on a Linux filesystem: the kernel tree has file names that differ only
# in case, which a Windows drive under /mnt would merge.
set -euo pipefail

KERNEL_VERSION=6.18.58
KERNEL_SHA256=069b19f9032c4dac8149ae4b6520c35debca0f42a9f6d52ee55ba6ca9b818013
BUSYBOX_VERSION=1.35.0
BUSYBOX_SHA256=6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348

here=$(cd "$(dirname "$0")" && pwd)
out=$here/../../run/linux
work=${ALEPH0_LINUX_WORK:-$HOME/.cache/aleph0-linux}
src=$work/linux-$KERNEL_VERSION
build=$work/build-$KERNEL_VERSION
mkdir -p "$work" "$build" "$out"

# fetch URL SHA256 FILE: downloads FILE once, and checks it on every run.
fetch() {
    if [ ! -f "$3" ]; then
        curl -fL --retry 3 -o "$3.part" "$1"
        mv "$3.part" "$3"
    fi
    echo "$2  $3" | sha256sum --check --quiet || { rm -f "$3"; exit 1; }
}

fetch "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz" "$KERNEL_SHA256" "$src.tar.xz"
fetch "https://busybox.net/downloads/binaries/$BUSYBOX_VERSION-x86_64-linux-musl/busybox" "$BUSYBOX_SHA256" \
    "$work/busybox-$BUSYBOX_VERSION"
if [ ! -d "$src" ]; then
    rm -rf "$src.part" && mkdir "$src.part"
    tar -xf "$src.tar.xz" -C "$src.part" --strip-components=1
    mv "$src.part" "$src"
fi

# The initramfs, as a gen_init_cpio list. /dev/console is a device node in it,
# so the kernel can open a console for /init and the build needs no root.
# init is listed from a copy: the list splits fields on spaces, and a Windows
# checkout's path (/mnt/c/Users/Jane Doe/...) can have one.
cp -p "$here/init" "$work/init"
cat > "$work/initramfs.list" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /bin 0755 0 0
dir /proc 0755 0 0
dir /sys 0755 0 0
file /bin/busybox $work/busybox-$BUSYBOX_VERSION 0755 0 0
file /init $work/init 0755 0 0
EOF
echo "CONFIG_INITRAMFS_SOURCE=\"$work/initramfs.list\"" > "$work/initramfs.config"

(cd "$src" && scripts/kconfig/merge_config.sh -O "$build" arch/x86/configs/x86_64_defconfig \
    "$here/aleph0.config" "$work/initramfs.config")
# Kconfig drops a value whose dependencies are unmet, with only a warning.
missing=$(grep -hE '^(CONFIG_|# CONFIG_.* is not set$)' "$here/aleph0.config" "$work/initramfs.config" |
    grep -vxF -f "$build/.config" || true)
if [ -n "$missing" ]; then
    printf 'Not in the final .config:\n%s\n' "$missing" >&2
    exit 1
fi

make -C "$src" O="$build" -j"$(nproc)" bzImage
cp "$build/arch/x86/boot/bzImage" "$out/linux.efi"
cp "$build/System.map" "$build/.config" "$out/"
echo "Linux $KERNEL_VERSION: $(cd "$out" && pwd)/linux.efi"

#!/usr/bin/env bash
# CI-only qualification of exact release bytes; no target installation script.
set -euo pipefail
binary=$(realpath "$1")
version=$2
test -x "$binary"
LC_ALL=C readelf -h "$binary" | grep -F 'Advanced Micro Devices X86-64'
LC_ALL=C readelf -lW "$binary" > /tmp/nezha-agent-elf-headers-$$
LC_ALL=C readelf -dW "$binary" > /tmp/nezha-agent-elf-dynamic-$$
root=$(mktemp -d)
trap 'rm -rf -- "$root"; rm -f /tmp/nezha-agent-elf-headers-$$ /tmp/nezha-agent-elf-dynamic-$$' EXIT
if grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)' /tmp/nezha-agent-elf-headers-$$; then
    echo 'Agent must not require an ELF interpreter' >&2
    exit 1
fi
if grep -Fq '(NEEDED)' /tmp/nezha-agent-elf-dynamic-$$; then
    echo 'Agent must not require shared libraries' >&2
    exit 1
fi
# No /lib, /lib64, /usr, libc, loader, or shell exists in this root.
install -m 0755 "$binary" "$root/nezha-agent"
test "$(sudo -n chroot "$root" /nezha-agent --version)" = "$version"
echo 'Static ELF, no libc or dynamic loader, exact release binary execution: passed'

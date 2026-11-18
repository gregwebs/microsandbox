#!/usr/bin/env bash
set -euo pipefail

# GitHub's hosted Ubuntu runners expose /dev/kvm, but only to the `kvm` group,
# which the runner user is not in. The microVM lanes therefore cannot open the
# device until its mode permits it. Self-hosted KVM runners normally grant
# access through group membership, in which case this script changes nothing.

readonly KVM_DEVICE=/dev/kvm

kvm_is_openable() {
  { exec 3<>"${KVM_DEVICE}"; } 2>/dev/null || return 1
  exec 3>&-
}

if [[ ! -e ${KVM_DEVICE} ]]; then
  echo "::error::${KVM_DEVICE} is missing; this runner cannot host microVMs"
  exit 1
fi

if kvm_is_openable; then
  echo "${KVM_DEVICE} is readable and writable"
  exit 0
fi

# The device exists and the kernel provides KVM; the runner user simply lacks
# the `kvm` group. Widening the mode on this ephemeral runner is enough, since
# the runner user cannot re-exec its own service to pick up group membership.
echo "::group::granting ${KVM_DEVICE} access"
ls -l "${KVM_DEVICE}" || true
sudo chmod 666 "${KVM_DEVICE}"
ls -l "${KVM_DEVICE}"
echo "::endgroup::"

if ! kvm_is_openable; then
  echo "::error::cannot open ${KVM_DEVICE} after granting access"
  exit 1
fi

echo "${KVM_DEVICE} is readable and writable"

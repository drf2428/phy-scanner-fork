#!/usr/bin/env bash
# build-appliance.sh — Build the Physeter Scanner appliance OVA
#
# REQUIREMENTS (run on Debian/Ubuntu Linux host):
#   sudo apt-get install debootstrap qemu-utils genisoimage cloud-image-utils
#   Must run as root (debootstrap requires it)
#
# USAGE:
#   sudo ./scripts/build-appliance.sh [VERSION]
#   VERSION defaults to contents of agent/version.txt

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
    VERSION_FILE="${REPO_ROOT}/agent/version.txt"
    if [[ ! -f "${VERSION_FILE}" ]]; then
        echo "ERROR: agent/version.txt not found and no VERSION argument given." >&2
        exit 1
    fi
    VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"
fi
echo "==> Building phy-internal-scanner v${VERSION}"

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root (debootstrap requires it)." >&2
    exit 1
fi

for cmd in debootstrap qemu-img; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "ERROR: Required tool '${cmd}' not found. Install it first:" >&2
        echo "  sudo apt-get install debootstrap qemu-utils" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
BUILD_DIR="$(mktemp -d /tmp/phy-scanner-build.XXXXXX)"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
DIST_DIR="${REPO_ROOT}/dist"
OVA_NAME="phy-internal-scanner-v${VERSION}.ova"
RAW_IMG="${BUILD_DIR}/disk.raw"
QCOW2_IMG="${BUILD_DIR}/disk.qcow2"

mkdir -p "${ROOTFS_DIR}" "${DIST_DIR}"

cleanup() {
    echo "==> Cleaning up build directory ${BUILD_DIR}"
    # Unmount any lingering bind mounts before removing
    for mnt in proc sys dev; do
        mountpoint -q "${ROOTFS_DIR}/${mnt}" && umount -lf "${ROOTFS_DIR}/${mnt}" || true
    done
    rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

echo "==> Build directory: ${BUILD_DIR}"

# ---------------------------------------------------------------------------
# Step 1 — Bootstrap Debian 12 (bookworm) minimal rootfs
# ---------------------------------------------------------------------------
# OPERATOR NOTE: This step requires network access to a Debian mirror and
# may take several minutes depending on connection speed.
echo "==> [1/9] Bootstrapping Debian 12 (bookworm) minimal rootfs..."
debootstrap \
    --variant=minbase \
    --include=systemd,systemd-sysv,python3,python3-pip,ca-certificates,curl \
    bookworm \
    "${ROOTFS_DIR}" \
    https://deb.debian.org/debian

# ---------------------------------------------------------------------------
# Step 2 — Mount virtual filesystems for chroot operations
# ---------------------------------------------------------------------------
echo "==> [2/9] Mounting virtual filesystems for chroot..."
mount -t proc  none "${ROOTFS_DIR}/proc"
mount -t sysfs none "${ROOTFS_DIR}/sys"
mount --bind /dev  "${ROOTFS_DIR}/dev"

# ---------------------------------------------------------------------------
# Step 3 — Install Python 3.11, systemd, pip inside chroot
# ---------------------------------------------------------------------------
echo "==> [3/9] Installing Python 3.11, systemd, pip in chroot..."
chroot "${ROOTFS_DIR}" /bin/bash -c "
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3.11 python3.11-venv python3-pip \
        systemd systemd-sysv dbus \
        adduser
    apt-get clean
    rm -rf /var/lib/apt/lists/*
"

# ---------------------------------------------------------------------------
# Step 4 — Create service user and copy agent to /opt/phy-scanner/agent/
# ---------------------------------------------------------------------------
echo "==> [4/9] Creating service user and copying agent..."
chroot "${ROOTFS_DIR}" /bin/bash -c "
    id phy-scanner &>/dev/null || adduser --system --no-create-home --group phy-scanner
"
install -d -m 755 "${ROOTFS_DIR}/opt/phy-scanner"
cp -r "${REPO_ROOT}/agent" "${ROOTFS_DIR}/opt/phy-scanner/agent"
chroot "${ROOTFS_DIR}" chown -R root:root /opt/phy-scanner

# ---------------------------------------------------------------------------
# Step 5 — Install pip deps from agent/requirements.txt
# ---------------------------------------------------------------------------
echo "==> [5/9] Installing pip dependencies..."
chroot "${ROOTFS_DIR}" /bin/bash -c "
    pip3 install --no-cache-dir --break-system-packages \
        -r /opt/phy-scanner/agent/requirements.txt
"

# ---------------------------------------------------------------------------
# Step 6 — Install systemd service unit
# ---------------------------------------------------------------------------
echo "==> [6/9] Installing systemd service unit..."
install -m 644 \
    "${REPO_ROOT}/systemd/phy-scanner-agent.service" \
    "${ROOTFS_DIR}/etc/systemd/system/phy-scanner-agent.service"

# ---------------------------------------------------------------------------
# Step 7 — Enable the service
# ---------------------------------------------------------------------------
echo "==> [7/9] Enabling phy-scanner-agent service..."
chroot "${ROOTFS_DIR}" /bin/bash -c "
    systemctl enable phy-scanner-agent
" || true  # may warn if systemd isn't PID 1 in chroot; unit symlink is still created

# ---------------------------------------------------------------------------
# Step 8 — Install cloud-init template
# ---------------------------------------------------------------------------
echo "==> [8/9] Installing cloud-init configuration..."
install -d -m 755 "${ROOTFS_DIR}/etc/cloud/cloud.cfg.d"
install -m 644 \
    "${SCRIPT_DIR}/cloud-init-template.yaml" \
    "${ROOTFS_DIR}/etc/cloud/cloud.cfg.d/99-phy-scanner.cfg"

# Also create the config directory that cloud-init will populate on first boot
install -d -m 700 "${ROOTFS_DIR}/etc/phy-scanner"

# ---------------------------------------------------------------------------
# Step 9 — Create disk image and convert to OVA
# ---------------------------------------------------------------------------
echo "==> [9/9] Building disk image and converting to OVA..."

# OPERATOR NOTE: Disk size can be tuned here.  4G is sufficient for the agent
# and OS; increase if you intend to store large scan result caches on-disk.
DISK_SIZE_GB=4

# Create a sparse raw image
qemu-img create -f raw "${RAW_IMG}" "${DISK_SIZE_GB}G"

# Partition + format (requires parted and mkfs.ext4 on the build host)
# OPERATOR NOTE: Install 'parted' and 'e2fsprogs' if not already present:
#   sudo apt-get install parted e2fsprogs
if ! command -v parted &>/dev/null || ! command -v mkfs.ext4 &>/dev/null; then
    echo "ERROR: 'parted' and 'e2fsprogs' are required for disk image creation." >&2
    echo "  sudo apt-get install parted e2fsprogs" >&2
    exit 1
fi

parted --script "${RAW_IMG}" \
    mklabel msdos \
    mkpart primary ext4 1MiB 100%

# Associate loop device
LOOP_DEV="$(losetup --find --show --partscan "${RAW_IMG}")"
trap "losetup -d ${LOOP_DEV} 2>/dev/null || true; cleanup" EXIT

mkfs.ext4 -q -L phy-scanner-root "${LOOP_DEV}p1"

# Mount and copy rootfs into image
MOUNT_DIR="${BUILD_DIR}/mnt"
mkdir -p "${MOUNT_DIR}"
mount "${LOOP_DEV}p1" "${MOUNT_DIR}"
cp -a "${ROOTFS_DIR}/." "${MOUNT_DIR}/"
umount "${MOUNT_DIR}"
losetup -d "${LOOP_DEV}" || true

# Convert raw -> qcow2 -> OVA (OVF + VMDK)
qemu-img convert -f raw -O qcow2 "${RAW_IMG}" "${QCOW2_IMG}"

# Build a minimal OVF descriptor + package as OVA (tar)
OVF_FILE="${BUILD_DIR}/phy-internal-scanner.ovf"
VMDK_FILE="${BUILD_DIR}/phy-internal-scanner.vmdk"

# Convert qcow2 to VMDK for broad hypervisor compatibility
qemu-img convert -f qcow2 -O vmdk "${QCOW2_IMG}" "${VMDK_FILE}"

VMDK_SIZE="$(stat -c '%s' "${VMDK_FILE}")"

cat > "${OVF_FILE}" <<OVF_EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="phy-internal-scanner.vmdk"
          ovf:id="file1"
          ovf:size="${VMDK_SIZE}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="${DISK_SIZE_GB}"
          ovf:capacityAllocationUnits="byte * 2^30"
          ovf:diskId="vmdisk1"
          ovf:fileRef="file1"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <VirtualSystem ovf:id="phy-internal-scanner">
    <Info>Physeter Internal Scanner Appliance v${VERSION}</Info>
    <Name>phy-internal-scanner-v${VERSION}</Name>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>vmx-13 xen vmware-4</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of virtual CPUs</rasd:Description>
        <rasd:ElementName>2 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>512 MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>512</rasd:VirtualQuantity>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVF_EOF

# Package as OVA (uncompressed tar, OVF first per DMTF spec)
OVA_PATH="${DIST_DIR}/${OVA_NAME}"
tar -C "${BUILD_DIR}" -cf "${OVA_PATH}" \
    "phy-internal-scanner.ovf" \
    "phy-internal-scanner.vmdk"

echo ""
echo "==> Build complete!"
echo "    Output: ${OVA_PATH}"
echo "    Size:   $(du -sh "${OVA_PATH}" | cut -f1)"
echo ""
echo "    Upload to S3/CloudFront when ready:"
echo "      aws s3 cp ${OVA_PATH} s3://artifacts.physeter.cloud/phy-scanner/v${VERSION}/${OVA_NAME}"
echo "      aws s3 cp ${OVA_PATH} s3://artifacts.physeter.cloud/phy-scanner/latest/phy-internal-scanner.ova"

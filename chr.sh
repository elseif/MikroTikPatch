#!/bin/bash
set -e
LATEST_VERSION="${1:-7.19.4}"
echo "VERSION: $LATEST_VERSION"
ARCH=$(uname -m)
case $ARCH in
    x86_64|i386|i486|i586|i686)
        echo "ARCH: $ARCH"
        if [ -d /sys/firmware/efi ]; then
            echo "BOOT MODE: UEFI"
            IMG_URL="https://github.com/elseif/MikroTikPatch/releases/download/$LATEST_VERSION/chr-$LATEST_VERSION.img.zip"
        else
            echo "BOOT MODE: BIOS/MBR"
            IMG_URL="https://github.com/elseif/MikroTikPatch/releases/download/$LATEST_VERSION/chr-$LATEST_VERSION-legacy-bios.img.zip"
        fi
        ;; 
    aarch64)
         echo "ARCH: $ARCH"
         IMG_URL="https://github.com/elseif/MikroTikPatch/releases/download/$LATEST_VERSION-arm64/chr-$LATEST_VERSION-arm64.img.zip"
        ;; 
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac
STORAGE=$(for d in /sys/block/*; do
    case $(basename $d) in
        loop*|ram*|sr*) continue ;;
        *) echo $(basename $d); break ;;
    esac
done)
echo "STORAGE: $STORAGE"
ETH=$(ip route show default | grep '^default' | sed -n 's/.* dev \([^\ ]*\) .*/\1/p')
echo "ETH: $ETH"
ADDRESS=$(ip addr show $ETH | grep global | cut -d' ' -f 6 | head -n 1)
echo "ADDRESS: $ADDRESS"
GATEWAY=$(ip route list | grep default | cut -d' ' -f 3)
echo "GATEWAY:  $GATEWAY"
DNS=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | head -n 1)
[ -z "$DNS" ] && DNS="8.8.8.8"  
echo "DNS: $DNS"


echo "WARNING: All data on /dev/$STORAGE will be lost!"
read -p "Do you want to continue? [Y/n]: " confirm < /dev/tty
confirm=${confirm:-Y}
if [[ "$confirm" =~ ^[Nn]$ ]]; then
    echo "Operation aborted."
    exit 1
fi

echo "FILE: $(basename $IMG_URL)"
wget --no-check-certificate -O /tmp/chr.img.zip "$IMG_URL" || echo "Download failed!"
cd /tmp
unzip -p chr.img.zip > chr.img
if LOOP=$(losetup -Pf --show chr.img 2>/dev/null); then
    sleep 3
    MNT=/tmp/chr
    mkdir -p $MNT
    if mount ${LOOP}p2 $MNT 2>/dev/null; then
        cat <<EOF | tee $MNT/rw/autorun.scr
/ip address add address=$ADDRESS interface=ether1
/ip route add gateway=$GATEWAY
/ip dns set servers=$DNS
EOF
        echo "autorun.scr file created."
        umount $MNT
    else
        echo "Failed to mount partition 2, skipping autorun.scr creation."
    fi
    losetup -d $LOOP
fi

dd if=chr.img of=/dev/$STORAGE bs=4M conv=fsync
echo "Ok, rebooting..."
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo b > /proc/sysrq-trigger 2>/dev/null || true
reboot -f

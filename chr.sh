#!/bin/bash
set -e
LATEST_VERSION="${1:-7.19.6}"
echo "VERSION: $LATEST_VERSION"
ARCH=$(uname -m)

if [[ $LATEST_VERSION == 7.* ]]; then
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
else
    case $ARCH in
        x86_64|i386|i486|i586|i686)
            echo "ARCH: $ARCH"
            IMG_URL="https://github.com/elseif/MikroTikPatch/releases/download/$LATEST_VERSION/chr-$LATEST_VERSION.img.zip"
            ;; 
        *)
            echo "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
fi

STORAGE=$(lsblk -d -n -o NAME,TYPE | awk '$2=="disk"{print $1; exit}')
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

echo "FILE: $(basename $IMG_URL)"
if command -v wget >/dev/null 2>&1; then
    wget --no-check-certificate -O /tmp/chr.img.zip "$IMG_URL" || { echo "Download failed!"; exit 1; }
elif command -v curl >/dev/null 2>&1; then
    curl -L --insecure -o /tmp/chr.img.zip "$IMG_URL" || { echo "Download failed!"; exit 1; }
else
    echo "Neither wget nor curl is installed. Cannot download $url"
    exit 1
fi
cd /tmp
gunzip -c chr.img.zip  > chr.img
RANDOM_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 8)
if LOOP=$(losetup -Pf --show chr.img 2>/dev/null); then
    sleep 3
    MNT=/tmp/chr
    mkdir -p $MNT
    if mount ${LOOP}p2 $MNT 2>/dev/null; then
        cat <<EOF | tee $MNT/rw/autorun.scr
/ip address add address=$ADDRESS interface=ether1
/ip route add gateway=$GATEWAY
/ip dns set servers=$DNS
/user set admin password="$RANDOM_PASS"
EOF
        echo "autorun.scr file created."
        echo -e "admin password: \e[31m$RANDOM_PASS\e[0m"
        umount $MNT
    else
        echo "Failed to mount partition 2, skipping autorun.scr creation."
    fi
    losetup -d $LOOP
fi

echo "WARNING: All data on /dev/$STORAGE will be lost!"
read -p "Do you want to continue? [Y/n]: " confirm < /dev/tty
confirm=${confirm:-Y}
if [[ "$confirm" =~ ^[Nn]$ ]]; then
    echo "Operation aborted."
    exit 1
fi

dd if=chr.img of=/dev/$STORAGE bs=4M conv=fsync
echo "Ok, rebooting..."
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo b > /proc/sysrq-trigger 2>/dev/null || true
reboot -f

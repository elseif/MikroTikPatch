#!/bin/sh
set -e
if [ -d /sys/firmware/efi ]; then
    echo "System boot mode: UEFI"
    wget --no-check-certificate -O /tmp/chr.img.zip https://github.com/elseif/MikroTikPatch/releases/download/7.19.4/chr-7.19.4.img.zip
else
    echo "System boot mode: BIOS/MBR"
    wget --no-check-certificate -O /tmp/chr.img.zip https://github.com/elseif/MikroTikPatch/releases/download/7.19.4/chr-7.19.4-legacy-bios.img.zip
fi
cd /tmp
unzip -p chr.img.zip > chr.img

STORAGE=$(for d in /sys/block/*; do
    case $(basename $d) in
        loop*|ram*|sr*) continue ;;
        *) echo $(basename $d); break ;;
    esac
done)
echo "STORAGE is $STORAGE"

ETH=$(ip route show default | grep '^default' | sed -n 's/.* dev \([^\ ]*\) .*/\1/p')
echo "ETH is $ETH"

ADDRESS=$(ip addr show $ETH | grep global | cut -d' ' -f 6 | head -n 1)
echo "ADDRESS is $ADDRESS"

GATEWAY=$(ip route list | grep default | cut -d' ' -f 3)
echo "GATEWAY is $GATEWAY"

if LOOP=$(losetup -Pf --show chr.img 2>/dev/null); then
    echo "LOOP device is $LOOP"
    sleep 3
    MNT=/tmp/chr
    mkdir -p $MNT
    if mount ${LOOP}p2 $MNT 2>/dev/null; then
        cat <<EOF | tee $MNT/rw/autorun.scr
/ip address add address=$ADDRESS interface=ether1
/ip route add gateway=$GATEWAY
EOF
        echo "autorun.scr file created."
        umount $MNT
    else
        echo "Failed to mount partition 2, skipping autorun.scr creation."
    fi
    losetup -d $LOOP
fi

echo "WARNING: All data on /dev/$STORAGE will be lost!"
read -p "Do you want to continue? [Y/n]: " confirm
[ "$confirm" = "n" ] && echo "Operation aborted." && exit 1

dd if=chr.img of=/dev/$STORAGE bs=4M conv=fsync
echo "Ok, rebooting..."
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo b > /proc/sysrq-trigger 2>/dev/null || true
reboot -f

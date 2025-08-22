#!/bin/sh
set -e
wget --no-check-certificate -O /tmp/chr.img.zip https://gh-proxy.com/https://github.com/elseif/MikroTikPatch/releases/download/7.19.4/chr-7.19.4-legacy-bios.img.zip
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

#LOOP=$(losetup -Pf --show chr.img)
#echo "LOOP device is $LOOP"
sleep 3

#MNT=/mnt/chr
#mkdir -p $MNT
#mount ${LOOP}p2 $MNT

#cat <<EOF | tee $MNT/rw/autorun.scr
#/ip address add address=$ADDRESS interface=ether1
#/ip route add gateway=$GATEWAY
#EOF

#umount $MNT
#losetup -d $LOOP

echo "WARNING: All data on /dev/$STORAGE will be lost!"
read -p "Do you want to continue? [Y/n]: " confirm
[ "$confirm" = "n" ] && echo "Operation aborted." && exit 1

dd if=chr.img of=/dev/$STORAGE bs=4M conv=fsync
echo "Ok, rebooting..."
echo 1 > /proc/sys/kernel/sysrq
echo b > /proc/sysrq-trigger

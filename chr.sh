#!/bin/bash
apt-get install -y sgdisk extlinux > /dev/null 2>&1
dd if=/dev/zero of=/dev/sda bs=1 count=512 conv=notrunc
sgdisk --set-alignment=2 --new=1::+32M --typecode=1:8300 --change-name=1:"RouterOS Boot" --attributes=1:set:2 --new=2::-0 --typecode=2:8300 --change-name=2:"RouterOS" --gpttombr=1:2 /dev/sda
dd if=/dev/sda of=pt.bin bs=1 count=66 skip=446
echo -e "\x80" | dd of=pt.bin  bs=1 count=1  conv=notrunc
dd if=/dev/zero of=/dev/sda  bs=1 count=512 conv=notrunc
sgdisk --set-alignment=2 --new=1::+32M --typecode=1:8300 --change-name=1:"RouterOS Boot" --attributes=1:set:2 --new=2::-0 --typecode=2:8300 --change-name=2:"RouterOS" /dev/sda
wget -O mbr.bin https://raw.gitmirror.com/elseif/MikroTikPatch/main/mbr.bin
dd if=mbr.bin of=/dev/sda  bs=1 count=446 conv=notrunc
dd if=pt.bin of=/dev/sda  bs=1 count=66 seek=446 conv=notrunc
sync
partprobe /dev/sda
mkfs.vfat -n "Boot" /dev/sda1
mkfs.ext4 -F -L "RouterOS"  -m 0 /dev/sda2
mkdir -p /tmp/{boot,routeros}
mount -o loop,rw /dev/sda1  /tmp/boot
mkdir -p  /tmp/boot/{BOOT,EFI/BOOT}
wget -O /tmp/boot/EFI/BOOT/BOOTX64.EFI https://hub.gitmirror.com/https://github.com/elseif/MikroTikPatch/releases/download/7.15.2/BOOTX64.EFI
extlinux --install  -H 64 -S 32 ./img/boot/BOOT
echo -e "default system\nlabel system\n\tkernel /EFI/BOOT/BOOTX64.EFI\n\tappend load_ramdisk=1 root=/dev/ram0 quiet" > /tmp/boot/BOOT/syslinux.cfg
umount /tmp/boot
mount -o loop,rw /dev/sda2  /tmp/routeros
mkdir -p /tmp/routeros/{var/pdb/{system,option},boot,rw}
wget -O /tmp/routeros/var/pdb/option/image https://hub.gitmirror.com/https://github.com/elseif/MikroTikPatch/releases/download/7.15.2/option-7.15.2.npk
wget -O /tmp/routeros/var/pdb/system/image https://hub.gitmirror.com/https://github.com/elseif/MikroTikPatch/releases/download/7.15.2/routeros-7.15.2.npk
umount /tmp/routeros
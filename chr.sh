
DEV=/dev/sda
sgdisk --clear --set-alignment=2 \
    --new=1::+32M --typecode=1:8300 --change-name=1:"RouterOS Boot" --attributes=1:set:2 \
    --new=2::-0 --typecode=2:8300 --change-name=2:"RouterOS" \
    --gpttombr=1:2 \
    $DEV

dd if=$DEV of=pt.bin bs=1 count=66 skip=446
echo -e "\x80" | dd of=pt.bin  bs=1 count=1  conv=notrunc
sgdisk --mbrtogpt --clear --set-alignment=2 \
    --new=1::+32M --typecode=1:8300 --change-name=1:"RouterOS Boot" --attributes=1:set:2 \
    --new=2::-0 --typecode=2:8300 --change-name=2:"RouterOS" \
    $DEV
dd if=mbr.bin of=$DEV  bs=1 count=446 conv=notrunc
dd if=pt.bin of=$DEV  bs=1 count=66 seek=446 conv=notrunc
mkfs.vfat -n "Boot" $DEV1
mkfs.ext4 -F -L "RouterOS"  -m 0 $DEV2
sudo mkdir -p /tmp/{boot,routeros}

mount -o loop,rw $DEV1  /tmp/boot
mkdir -p  /tmp/boot/{BOOT,EFI/BOOT}
wget -O /tmp/boot/EFI/BOOT/BOOTX64.EFI https://github.com/elseif/MikroTikPatch/releases/download/7.15.2/BOOTX64.EFI
umount /tmp/boot

mount -o loop,rw $DEV2  /tmp/routeros
sudo mkdir -p /tmp/routeros/{var/pdb/{system,option},boot,rw}
wget -O /tmp/routeros/var/pdb/option/image https://github.com/elseif/MikroTikPatch/releases/download/7.15.2/option-7.15.2.npk
wget -O /tmp/routeros/var/pdb/system/image https://github.com/elseif/MikroTikPatch/releases/download/7.15.2/routeros-7.15.2.npk
umount /tmp/routeros
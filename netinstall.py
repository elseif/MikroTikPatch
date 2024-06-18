import struct,lzma
ROUTEROS_BOOT = {
    129:{'arch':'power','name':'Powerboot','filter':lzma.FILTER_POWERPC},
    130:{'arch':'e500','name':'e500_boot'},
    131:{'arch':'mips','name':'Mips_boot'},
    135:{'arch':'400','name':'440__boot'},
    136:{'arch':'tile','name':'tile_boot'},
    137:{'arch':'arm','name':'ARM__boot','filter':lzma.FILTER_ARMTHUMB},
    138:{'arch':'mmips','name':'MMipsBoot'},
    139:{'arch':'arm64','name':'ARM64__boot','filter':lzma.FILTER_ARMTHUMB},
    143:{'arch':'x86_64','name':'x86_64boot'}
}
def find_7zXZ_data(data:bytes):
    offset1 = 0
    _data = data
    while b'\xFD7zXZ\x00\x00\x01' in _data:
        offset1 = offset1 + _data.index(b'\xFD7zXZ\x00\x00\x01') + 8
        _data = _data[offset1:]
    offset1 -= 8
    offset2 = 0
    _data = data
    while b'\x00\x01\x59\x5A' in _data:
        offset2 = offset2 + _data.index(b'\x00\x01\x59\x5A') + 4
        _data = _data[offset2:]
    offset2
    return data[offset1:offset2] 

def patch_elf(data: bytes,key_dict:dict,filter=None):
    initrd_xz = find_7zXZ_data(data)
    initrd = lzma.decompress(initrd_xz)
    new_initrd = initrd  
    for old_public_key,new_public_key in key_dict.items():
        if old_public_key in new_initrd:
            print(f'initramfs public key patched {old_public_key[:16].hex().upper()}...')
            new_initrd = new_initrd.replace(old_public_key,new_public_key)

    filters=[{"id":filter},{"id": lzma.FILTER_LZMA2, "preset": 9,}] if filter else [{"id": lzma.FILTER_LZMA2, "preset": 9,}] 
    new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=filters)
    assert len(new_initrd_xz) <= len(initrd_xz),'new initrd xz size is too big'
  
    new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz),b'\0')
    new_data = data.replace(initrd_xz,new_initrd_xz)
    return new_data

def patch_pe(data: bytes,key_dict:dict,filter=None):
    vmlinux_xz_offset = data.index(b'\xFD7zXZ\x00\x00\x01')
    vmlinux_xz_size = data.index(b'\x00\x01\x59\x5A') + 4 - vmlinux_xz_offset
    vmlinux_xz = data[vmlinux_xz_offset:vmlinux_xz_offset+vmlinux_xz_size]
    vmlinux = lzma.decompress(vmlinux_xz)
    initrd_xz_offset = vmlinux.index(b'\xFD7zXZ\x00\x00\x01')
    initrd_xz_size = vmlinux.index(b'\x00\x01\x59\x5A') + 4 - initrd_xz_offset
    initrd_xz = vmlinux[initrd_xz_offset:initrd_xz_offset+initrd_xz_size]
    initrd = lzma.decompress(initrd_xz)
    new_initrd = initrd  
    for old_public_key,new_public_key in key_dict.items():
        if old_public_key in new_initrd:
            print(f'initrd public key patched {old_public_key[:16].hex().upper()}...')
            new_initrd = new_initrd.replace(old_public_key,new_public_key)

    filters=[{"id":filter},{"id": lzma.FILTER_LZMA2, "preset": 9,}] if filter else [{"id": lzma.FILTER_LZMA2, "preset": 9,}] 
    new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=filters)
    assert len(new_initrd_xz) <= len(initrd_xz),'new initrd xz size is too big'
  
    new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz),b'\0')
    new_vmlinux = vmlinux.replace(initrd_xz,new_initrd_xz)

    filters=[{"id":filter},{"id": lzma.FILTER_LZMA2, "preset": 9,}] if filter else [{"id": lzma.FILTER_LZMA2, "preset": 9,}] 
    new_vmlinux_xz = lzma.compress(new_vmlinux,check=lzma.CHECK_CRC32,filters=filters)
    assert len(new_vmlinux_xz) <= len(vmlinux_xz),'new vmlinux xz size is too big'

    new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz),b'\0')
    new_data = data.replace(vmlinux_xz,new_vmlinux_xz)
    return new_data
    


def patch_netinstall(key_dict: dict,input_file,output_file=None):
    import pefile
    with pefile.PE(input_file) as pe:
        for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                for sub_resource in resource.directory.entries:
                    if sub_resource.id in ROUTEROS_BOOT:
                        bootloader = ROUTEROS_BOOT[sub_resource.id]
                        filter = bootloader.get("filter")
                        print(f'found {bootloader["arch"]}({sub_resource.id}) bootloader')
                        rva = sub_resource.directory.entries[0].data.struct.OffsetToData
                        size = sub_resource.directory.entries[0].data.struct.Size
                        data = pe.get_data(rva,size)
                        assert len(data) -4 >= struct.unpack_from('<I',data)[0] ,f'bootloader data size mismathch'
                        data = data[4:]
                        try:
                            if data[:2] == b'MZ':
                                new_data = patch_pe(data,key_dict,filter)
                            elif data[:4] == b'\x7FELF':
                                new_data = patch_elf(data,key_dict,filter)
                            else:
                                raise Exception(f'unknown bootloader format {data[:4].hex().upper()}')
                        except Exception as e:
                            print(f'patch {bootloader["arch"]}({sub_resource.id}) bootloader failed {e}')
                            new_data = data
                        new_data = struct.pack("<I",len(new_data)) + new_data.ljust(len(data),b'\0')
                        pe.set_bytes_at_rva(rva,new_data)
        pe.write(output_file)

from package import check_install_package
check_install_package(['pefile'])


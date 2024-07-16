import struct,lzma

def find_7zXZ_data(data:bytes):
    offset1 = 0
    _data = data
    while b'\xFD7zXZ\x00\x00\x01' in _data:
        offset1 = offset1 + _data.index(b'\xFD7zXZ\x00\x00\x01') + 8
        _data = _data[offset1:]
    offset1 -= 8
    offset2 = 0
    _data = data
    while b'\x00\x00\x00\x00\x01\x59\x5A' in _data:
        offset2 = offset2 + _data.index(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
        _data = _data[offset2:]
    return data[offset1:offset2] 

def patch_elf(data: bytes,key_dict:dict):
    initrd_xz = find_7zXZ_data(data)
    initrd = lzma.decompress(initrd_xz)
    new_initrd = initrd  
    for old_public_key,new_public_key in key_dict.items():
        if old_public_key in new_initrd:
            print(f'initramfs public key patched {old_public_key[:16].hex().upper()}...')
            new_initrd = new_initrd.replace(old_public_key,new_public_key)

    filters=[{"id": lzma.FILTER_LZMA2, "preset": 9,}] 
    new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=filters)
    assert len(new_initrd_xz) <= len(initrd_xz),'new initrd xz size is too big'
  
    new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz),b'\0')
    new_data = data.replace(initrd_xz,new_initrd_xz)
    return new_data

def patch_pe(data: bytes,key_dict:dict):
    vmlinux_xz = find_7zXZ_data(data)
    vmlinux = lzma.decompress(vmlinux_xz)
    initrd_xz_offset = vmlinux.index(b'\xFD7zXZ\x00\x00\x01')
    initrd_xz_size = vmlinux[initrd_xz_offset:].index(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
    initrd_xz = vmlinux[initrd_xz_offset:initrd_xz_offset+initrd_xz_size]
    initrd = lzma.decompress(initrd_xz)
    new_initrd = initrd  
    for old_public_key,new_public_key in key_dict.items():
        if old_public_key in new_initrd:
            print(f'initrd public key patched {old_public_key[:16].hex().upper()}...')
            new_initrd = new_initrd.replace(old_public_key,new_public_key)

    filters= [{"id": lzma.FILTER_LZMA2, "preset": 9,}] 
    new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=filters)
    assert len(new_initrd_xz) <= len(initrd_xz),'new initrd xz size is too big'
  
    new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz),b'\0')
    new_vmlinux = vmlinux.replace(initrd_xz,new_initrd_xz)

    new_vmlinux_xz = lzma.compress(new_vmlinux,check=lzma.CHECK_CRC32,filters=filters)
    assert len(new_vmlinux_xz) <= len(vmlinux_xz),'new vmlinux xz size is too big'

    new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz),b'\0')
    new_data = data.replace(vmlinux_xz,new_vmlinux_xz)
    return new_data
    


def patch_netinstall(key_dict: dict,input_file,output_file=None):
    netinstall = open(input_file,'rb').read()
    if netinstall[:2] == b'MZ':
        from package import check_install_package
        check_install_package(['pefile'])
        import pefile
        ROUTEROS_BOOT = {
            129:{'arch':'power','name':'Powerboot'},
            130:{'arch':'e500','name':'e500_boot'},
            131:{'arch':'mips','name':'Mips_boot'},
            135:{'arch':'400','name':'440__boot'},
            136:{'arch':'tile','name':'tile_boot'},
            137:{'arch':'arm','name':'ARM__boot'},
            138:{'arch':'mmips','name':'MMipsBoot'},
            139:{'arch':'arm64','name':'ARM64__boot'},
            143:{'arch':'x86_64','name':'x86_64boot'}
        }
        with pefile.PE(input_file) as pe:
            for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                    for sub_resource in resource.directory.entries:
                        if sub_resource.id in ROUTEROS_BOOT:
                            bootloader = ROUTEROS_BOOT[sub_resource.id]
                            print(f'found {bootloader["arch"]}({sub_resource.id}) bootloader')
                            rva = sub_resource.directory.entries[0].data.struct.OffsetToData
                            size = sub_resource.directory.entries[0].data.struct.Size
                            data = pe.get_data(rva,size)
                            assert len(data) -4 >= struct.unpack_from('<I',data)[0] ,f'bootloader data size mismathch'
                            data = data[4:]
                            try:
                                if data[:2] == b'MZ':
                                    new_data = patch_pe(data,key_dict)
                                elif data[:4] == b'\x7FELF':
                                    new_data = patch_elf(data,key_dict)
                                else:
                                    raise Exception(f'unknown bootloader format {data[:4].hex().upper()}')
                            except Exception as e:
                                print(f'patch {bootloader["arch"]}({sub_resource.id}) bootloader failed {e}')
                                new_data = data
                            new_data = struct.pack("<I",len(new_data)) + new_data.ljust(len(data),b'\0')
                            pe.set_bytes_at_rva(rva,new_data)
            pe.write(output_file or input_file)
    elif netinstall[:4] == b'\x7FELF':
        import re
        # 83 00 00 00 C4 68 C4 0B  5A C2 04 08 10 9E 52 00
        # 8A 00 00 00 C3 68 C4 0B  6A 60 57 08 C0 3D 54 00
        # 81 00 00 00 D3 68 C4 0B  2A 9E AB 08 5C 1B 78 00
        # 82 00 00 00 E8 6B C4 0B  86 B9 23 09 78 01 82 00
        # 87 00 00 00 ED 6B C4 0B  FE BA A5 09 44 BF 7B 00
        # 89 00 00 00 0C 6A C4 0B  42 7A 21 0A C4 1D 3E 00
        # 8B 00 00 00 1E 69 C4 0B  06 98 5F 0A 28 95 5E 00
        # 8C 00 00 00 F1 6B C4 0B  2E 2D BE 0A 78 EA 5D 00
        # 88 00 00 00 03 69 C4 0B  A6 17 1C 0B 28 55 4A 00
        # 8F 00 00 00 FC 6B C4 0B  CE 6C 66 0B E0 E8 58 00
        SECTION_HEADER_OFFSET_IN_FILE = struct.unpack_from(b'<I',netinstall[0x20:])[0]
        SECTION_HEADER_ENTRY_SIZE = struct.unpack_from(b'<H',netinstall[0x2E:])[0]
        NUMBER_OF_SECTION_HEADER_ENTRIES = struct.unpack_from(b'<H',netinstall[0x30:])[0]
        STRING_TABLE_INDEX = struct.unpack_from(b'<H',netinstall[0x32:])[0]
        section_name_offset = SECTION_HEADER_OFFSET_IN_FILE + STRING_TABLE_INDEX * SECTION_HEADER_ENTRY_SIZE + 16
        SECTION_NAME_BLOCK = struct.unpack_from(b'<I',netinstall[section_name_offset:])[0]
        for i in range(NUMBER_OF_SECTION_HEADER_ENTRIES):
            section_offset = SECTION_HEADER_OFFSET_IN_FILE + i * SECTION_HEADER_ENTRY_SIZE
            name_offset,_,_,addr,offset = struct.unpack_from('<IIIII',netinstall[section_offset:])
            name = netinstall[SECTION_NAME_BLOCK+name_offset:].split(b'\0')[0]
            if name == b'.text':
                print(f'found .text section at {hex(offset)} addr {hex(addr)}')
                text_section_addr = addr
                text_section_offset = offset
                break
        offset = re.search(rb'\x83\x00\x00\x00.{12}\x8A\x00\x00\x00.{12}\x81\x00\x00\x00.{12}',netinstall).start()
        print(f'found bootloaders offset {hex(offset)}')
        for i in range(10):
            id,name_ptr,data_ptr,data_size = struct.unpack_from('<IIII',netinstall[offset+i*16:offset+i*16+16])
            name = netinstall[text_section_offset+name_ptr-text_section_addr:].split(b'\0')[0]
            data = netinstall[text_section_offset+data_ptr-text_section_addr:text_section_offset+data_ptr-text_section_addr+data_size]
            print(f'found {name.decode()}({id}) bootloader offset {hex(text_section_offset+data_ptr-text_section_addr)} size {data_size}')
            try:
                if data[:2] == b'MZ':
                    new_data = patch_pe(data,key_dict)
                elif data[:4] == b'\x7FELF':
                    new_data = patch_elf(data,key_dict)
                else:
                    raise Exception(f'unknown bootloader format {data[:4].hex().upper()}')
            except Exception as e:
                print(f'patch {name.decode()}({id}) bootloader failed {e}')
                new_data = data
            new_data = new_data.ljust(len(data),b'\0')
            netinstall = netinstall.replace(data,new_data)
        open(output_file or input_file,'wb').write(netinstall)
  




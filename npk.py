
import struct,zlib
from datetime import datetime
from dataclasses import dataclass
from enum import IntEnum
class NpkPartID(IntEnum):
    NAME_INFO               =0x01	# Package information: name, ver, etc.
    DESCRIPTION             =0x02	# Package description
    DEPENDENCIES            =0x03	# Package Dependencies
    FILE_CONTAINER          =0x04	# Files container zlib 1.2.3
    INSTALL_SCRIPT          =0x07	# Install script
    UNINSTALL_SCRIPT        =0x08	# Uninstall script
    SIGNATURE               =0x09	# Package signature
    ARCHITECTURE            =0x10	# Package architecture (e.g. i386)
    PKG_CONFLICTS           =0x11	# Package conflicts
    PKG_INFO                =0x12	
    FEATURES                =0x13
    PKG_FEATURES            =0x14	
    SQUASHFS                =0x15	# SquashFS 
    NULL_BLOCK              =0X16
    GIT_COMMIT              =0x17	# Git commit
    CHANNEL                 =0x18	# Release type (e.g. stable, testing, etc.)
    HEADER                  =0x19	

@dataclass
class NpkPartItem:
    id: NpkPartID
    data: bytes|object
class NpkNameInfo:
    _format = '<16s4sI12s'
    def __init__(self,name:str,version:str,build_time=datetime.now(),_unknow=b'\x00'*12):
        self._name = name[:16].encode().ljust(16,b'\x00')
        self._version = self.encode_version(version)
        self._build_time = int(build_time.timestamp())
        self._unknow = _unknow
    def serialize(self)->bytes:
        return struct.pack(self._format, self._name,self._version,self._build_time,self._unknow)
    @staticmethod
    def unserialize_from(data:bytes)->'NpkNameInfo':
        assert len(data) == struct.calcsize(NpkNameInfo._format),'Invalid data length'
        _name, _version,_build_time,_unknow = struct.unpack_from(NpkNameInfo._format,data)
        return NpkNameInfo(_name.decode(),NpkNameInfo.decode_version(_version),datetime.fromtimestamp(_build_time),_unknow)
    def __len__ (self)->int:
        return struct.calcsize(self._format)
    @property
    def name(self)->str:
        return self._name.decode().strip('\x00')
    @name.setter
    def name(self,value:str):
        self._name = value[:16].encode().ljust(16,b'\x00')
    @staticmethod
    def decode_version(value:bytes):
        revision,build,minor,major = struct.unpack_from('4B',value)
        if build == 97:
            build = 'alpha'
        elif build == 98:
            build = 'beta'
        elif build == 99:
            build = 'rc'
        elif build == 102:
            if revision & 0x80:
                build = 'test'
                revision &= 0x7f
            else:
                build = 'final'
        else:
            build = 'unknown'
        return f'{major}.{minor}.{revision}.{build}'
    @staticmethod
    def encode_version(value:str):
        s = value.split('.')
        if 4 != len(s) and s[3] in [ 'alpha', 'beta', 'rc','final', 'test']:
            raise ValueError('Invalid version string')
        major = int(s[0])
        minor = int(s[1])
        revision = int(s[2])
        if s[3] == 'alpha':
            build = 97
        elif s[3] == 'beta':
            build = 98
        elif s[3] == 'rc':
            build = 99
        elif s[3] == 'final':
            build = 102
            revision &= 0x7f
        else: #'test'
            build = 102
            revision |= 0x80
        return struct.pack('4B',revision,build,minor,major)
    @property
    def version(self)->str:
        return self.decode_version(self._version)
    @version.setter
    def version(self,value:str = '7.15.1.final'):
        self._version = self.encode_version(value)
    @property
    def build_time(self):
        return datetime.fromtimestamp(self._build_time) 
    @build_time.setter
    def build_time(self,value:datetime):
        self._build_time = int(value.timestamp())

class NpkFileContainer:
    _format = '<BB6sIBBBBIIIH'
    @dataclass
    class NpkFileItem:
        perm: int
        type: int
        usr_or_grp: int
        modify_time: int
        revision: int
        rc: int
        minor: int
        major: int
        create_time: int
        unknow: int
        name: bytes
        data: bytes
    def __init__(self,items:list['NpkFileContainer.NpkFileItem']=None):
        self._items= items
    def serialize(self)->bytes:
        compressed_data = b''
        compressor = zlib.compressobj()
        for item in self._items:
            data = struct.pack(self._format, item.perm,item.type,item.usr_or_grp, item.modify_time,item.revision,item.rc,item.minor,item.major,item.create_time,item.unknow,len(item.data),len(item.name)) 
            data += item.name + item.data
            compressed_data += compressor.compress(data)
        return compressed_data + compressor.flush()
    @staticmethod
    def unserialize_from(data:bytes):
        items:list['NpkFileContainer.NpkFileItem'] = []
        decompressed_data = zlib.decompress(data)
        while len(decompressed_data):
            offset = struct.calcsize(NpkFileContainer._format)
            perm,type,usr_or_grp, modify_time,revision,rc,minor,major,create_time,unknow,data_size,name_size= struct.unpack_from(NpkFileContainer._format, decompressed_data)
            name = decompressed_data[offset:offset+name_size]
            data = decompressed_data[offset+name_size:offset+name_size+data_size]
            items.append(NpkFileContainer.NpkFileItem(perm,type,usr_or_grp, modify_time,revision,rc,minor,major,create_time,unknow,name,data))
            decompressed_data = decompressed_data[offset+name_size+data_size:]
        return NpkFileContainer(items)

    def __len__ (self)->int:
        return len(self.serialize())
    def __getitem__(self,index:int)->'NpkFileContainer.NpkFileItem':
        return self._items[index]
    def __iter__(self):
        for item in self._items:
            yield item


class NovaPackage:
    NPK_MAGIC = 0xbad0f11e
    def __init__(self,data:bytes=b''):
        self._parts:list[NpkPartItem] = []
        offset = 0
        while offset < len(data):
            part_id,part_size = struct.unpack_from('<HI',data,offset)
            offset += 6
            part_data = data[offset:offset+part_size]
            offset += part_size
            if part_id == NpkPartID.NAME_INFO:
                self._parts.append(NpkPartItem(NpkPartID(part_id),NpkNameInfo.unserialize_from(part_data)))
            # elif part_id == NpkPartID.FILE_CONTAINER:
            #     self._parts.append(NpkPartItem(NpkPartID(part_id),NpkFileContainer.unserialize_from(part_data)))
            else:
                self._parts.append(NpkPartItem(NpkPartID(part_id),part_data))


    def get_digest(self,hash_fnc)->bytes:
        for part in self._parts:
            data_header = struct.pack('<HI',part.id.value,len(part.data))
            if part.id == NpkPartID.HEADER:
                continue
            else:
                hash_fnc.update(data_header)
                if part.id == NpkPartID.SIGNATURE:
                    break
                elif part.data:
                    if isinstance(part.data,bytes):
                        hash_fnc.update(part.data)
                    else:
                        hash_fnc.update(part.data.serialize())
        return hash_fnc.digest()    
   
    def sign(self,kcdsa_private_key:bytes,eddsa_private_key:bytes):
        import hashlib
        from mikro import mikro_kcdsa_sign,mikro_eddsa_sign
        self[NpkPartID.SIGNATURE].data = b'\0'*(20+48+64)
        sha1_digest = self.get_digest(hashlib.new('SHA1'))
        sha256_digest = self.get_digest(hashlib.new('SHA256'))
        kcdsa_signature = mikro_kcdsa_sign(sha256_digest[:20],kcdsa_private_key)
        eddsa_signature = mikro_eddsa_sign(sha256_digest,eddsa_private_key)
        self[NpkPartID.SIGNATURE].data = sha1_digest + kcdsa_signature + eddsa_signature

    def verify(self,kcdsa_public_key:bytes,eddsa_public_key:bytes):
        import hashlib
        from mikro import mikro_kcdsa_verify,mikro_eddsa_verify
        sha1_digest = self.get_digest(hashlib.new('SHA1'))
        sha256_digest = self.get_digest(hashlib.new('SHA256'))
        signature = self[NpkPartID.SIGNATURE].data
        if sha1_digest != signature[:20]: 
            return False
        if not mikro_kcdsa_verify(sha256_digest[:20],signature[20:68],kcdsa_public_key):
            return False
        if not mikro_eddsa_verify(sha256_digest,signature[68:132],eddsa_public_key):
            return False
        return True
    
    def __iter__(self):
        for part in self._parts:
            yield part

    def __getitem__(self, id:NpkPartID):
        for part in self._parts:
            if part.id == id:
                return part
        part = NpkPartItem(id,b'')
        self._parts.append(part)
        return part
            
    def save(self,file):
        size = 0
        for part in self._parts:
            size += 6 + len(part.data)
        with open(file,'wb') as f:
            f.write(struct.pack('<II', NovaPackage.NPK_MAGIC, size))
            for part in self._parts:
                f.write(struct.pack('<HI',part.id.value ,len(part.data)))
                if isinstance(part.data,bytes):
                    f.write(part.data)
                else:
                    f.write(part.data.serialize())

    @staticmethod
    def load(file):
        with open(file,'rb') as f:
            data = f.read()
        assert int.from_bytes(data[:4],'little') == NovaPackage.NPK_MAGIC, 'Invalid Nova Package Magic'
        assert int.from_bytes(data[4:8],'little') == len(data) - 8, 'Invalid Nova Package Size'
        return NovaPackage(data[8:])
  

    
if __name__=='__main__':
    import argparse,os
    parser = argparse.ArgumentParser(description='nova package creator and editor')
    subparsers = parser.add_subparsers(dest="command")
    sign_parser = subparsers.add_parser('sign',help='sign npk file')
    sign_parser.add_argument('input',type=str, help='Input file')
    sign_parser.add_argument('output',type=str,help='Output file')
    verify_parser = subparsers.add_parser('verify',help='Verify npk file')
    verify_parser.add_argument('input',type=str, help='Input file')
    create_option_parser = subparsers.add_parser('create',help='Create option.npk file')
    create_option_parser.add_argument('input',type=str,help='From npk file')
    create_option_parser.add_argument('output',type=str,help='Output file')
    create_option_parser.add_argument('name',type=str,help='NPK name')
    create_option_parser.add_argument('squashfs',type=str,help='NPK squashfs file')
    create_option_parser.add_argument('-desc','--description',type=str,help='NPK description')
    args = parser.parse_args()
    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])
    kcdsa_public_key = bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY'])
    eddsa_public_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    
    build_time = os.environ['BUILD_TIME'] if 'BUILD_TIME' in os.environ else None
    if args.command =='sign':
        print(f'Signing {args.input}')
        npk = NovaPackage.load(args.input)
        if build_time:
            npk[NpkPartID.NAME_INFO].data._build_time = int(build_time)
        npk.sign(kcdsa_private_key,eddsa_private_key)
        npk.save(args.output)
    elif args.command == 'verify':
        npk = NovaPackage.load(args.input)
        print(f'Verifying {args.input} ',end="")
        if npk.verify(kcdsa_public_key,eddsa_public_key):
            print('Valid')
            exit(0)
        else:
            print('Invalid')
            exit(-1)
    elif args.command =='create':
        print(f'Creating {args.output} from {args.input}')
        option_npk = NovaPackage.load(args.input)
        option_npk[NpkPartID.NAME_INFO].data.name = args.name
        if build_time:
            option_npk[NpkPartID.NAME_INFO].data._build_time = int(build_time)
        option_npk[NpkPartID.DESCRIPTION].data = args.description.encode() if args.description else args.name.encode()
        option_npk[NpkPartID.NULL_BLOCK].data = b''
        option_npk[NpkPartID.SQUASHFS].data = open(args.squashfs,'rb').read() 
        option_npk.sign(kcdsa_private_key,eddsa_private_key)
        option_npk.save(args.output)
        print(f'Created {args.output}')
    else:
        parser.print_help()
#!/usr/bin/python3

import gzip
import json
import struct
import os.path

from requests import get
from lightpdbparser import Pdb
from pefile import PE, DIRECTORY_ENTRY

def find(key: str, d: dict):
    for k, v in d.items():
        if k == key:
            return v
        if isinstance(v, dict):
            return find(key, v)
    return None

def downloadPdb(pe: PE, pe_filepath):
    pdb_file = pe_filepath.rsplit(".", maxsplit=1)[0] + ".pdb"
    pe.parse_data_directories(directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    guid_string = (
        f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data1:08X}"
        + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data2:04X}"
        + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data3:04X}"
        + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data4:02X}"
        + f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data5:02X}"
        + pe.DIRECTORY_ENTRY_DEBUG[0].entry.Signature_Data6.hex().upper()
    )
    age_string = f"{pe.DIRECTORY_ENTRY_DEBUG[0].entry.Age:X}"
    pdb_filename = pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName.decode().replace("\x00", "")
    pdb_url = f"https://msdl.microsoft.com/download/symbols/{pdb_filename}/{guid_string}{age_string}/{pdb_filename}"
    # print(pdb_url)

    # print(f"[*] Downloading {pdb_url} for file {pe_filepath}...", end="")
    if not os.path.isfile(pdb_file):
        pdb_content = get(pdb_url)
        # print("OK")
        if len(pdb_content.content) == 0:
            return "SKIP"
        f = open(pdb_file, "wb")
        f.write(pdb_content.content)
        f.close()
    # else:
        # print(" OK (file exists)")

    return (pdb_file)

def downloadFile(fileEntry):
    if 'fileInfo' not in fileEntry or 'virtualSize' not in fileEntry['fileInfo']:
        return "SKIP"

    timestamp = fileEntry['fileInfo']['timestamp']
    size = fileEntry['fileInfo']['virtualSize']
    fileId = hex(timestamp).replace("0x", "").zfill(8).upper() + hex(size).replace("0x", "").upper()
    url = "https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/" + fileId + "/ntoskrnl.exe"
    try:
        version = fileEntry["fileInfo"]["version"].split(" ")[0]
    except KeyError:
        version_field = find("version", fileEntry)
        if version_field is None:
            return "SKIP"
        version = version_field.split(" ")[0]
        if version and version.count(".") != 3:
            version = None

    if not version:
        return

    file_size = 0
    output_file = f"ntoskrnl_{'-'.join(version.split('.')[-2:])}.exe"
    # print(f"[*] Downloading {url}...", end="")
    if os.path.isfile("Binaries/" + output_file):
        # print(" OK (file exists)")
        f = open("Binaries/" + output_file, "rb")
        file_size = len(f.read())
        f.close()
    else:
        file_content = get(url)
        file_size = len(file_content.content)
        f = open("Binaries/" + output_file, "wb")
        f.write(file_content.content)
        f.close()
        # print(" OK")

    if file_size == 0:
        return "SKIP"
    return "Binaries/" + output_file

def scan_exe_for_rop(pe, code_section, CODE, ADDRESS, packing_type, gadget, mask=None):
    size = code_section.SizeOfRawData - len(gadget)
    if len(gadget) == 2 or len(gadget) == 4:
        converted_gadget = struct.unpack(packing_type, gadget)[0]
        for i in range(size):
            instr = CODE[i:i+len(gadget)]
            if struct.unpack(packing_type, instr)[0] == converted_gadget:
                # print(f"[+] POP_RCX_RET found at {hex(ADDRESS + i)}, offset = {hex(ADDRESS + i - pe.OPTIONAL_HEADER.ImageBase)}")
                return (ADDRESS + i - pe.OPTIONAL_HEADER.ImageBase)
    else:
        for i in range(size):
            valid = True
            instr = CODE[i:i+len(gadget)]
            for j in range(len(gadget)):
                if ((mask is not None and mask[j] == '?') or mask is None) and gadget[j] != instr[j]:
                    valid = False
                    break
            if valid:
                return ADDRESS + i - pe.OPTIONAL_HEADER.ImageBase

    return 0x00

def getFilelist():
    pe_name = "ntoskrnl.exe"
    json_gz = get(f"https://winbindex.m417z.com/data/by_filename_compressed/{pe_name}.json.gz").content
    json_raw = gzip.decompress(json_gz)
    exe_list = json.loads(json_raw)

    print(f"[+] Processing {len(exe_list)} kernel versions")
    # for exe_hash in exe_list:
    for exe_hash in exe_list:
        # if exe_hash != "24b0b77571625270fd9f5a6100320e1636f5f0728f223eab11a0a78d9cbe299b":
        #   continue

        #print("======================")
        #print(f"{exe_hash}")
        #print(exe_list[exe_hash])

        pefile = downloadFile(exe_list[exe_hash])
        if pefile == "SKIP":
            continue

        pe = PE(pefile, fast_load=True)
        pdbfile = downloadPdb(pe, pefile)
        if pdbfile == "SKIP":
            continue

        pdb = Pdb(path=pdbfile)
        ZwClose_offset = pdb.get_symbol_offset("ZwClose")
        ZwOpenProcess_offset = pdb.get_symbol_offset("ZwOpenProcess")
        PsLookupProcessByProcessId_offset = pdb.get_symbol_offset("PsLookupProcessByProcessId")
        ZwDuplicateObject_offset = pdb.get_symbol_offset("ZwDuplicateObject")
        NtShutdownSystem_offset = pdb.get_symbol_offset("NtShutdownSystem")
        PsGetProcessPeb_offset = pdb.get_symbol_offset("PsGetProcessPeb")
        memcpy_offset = pdb.get_symbol_offset("memcpy")
        MmCopyMemory_offset = pdb.get_symbol_offset("MmCopyMemory")
        MmMapIoSpace_offset = pdb.get_symbol_offset("MmMapIoSpace")
        ZwReadVirtualMemory_offset = pdb.get_symbol_offset("ZwReadVirtualMemory")
        ZwQueryVirtualMemory_offset = pdb.get_symbol_offset("ZwQueryVirtualMemory")
        MiQueryAddressState_offset = pdb.get_symbol_offset("MiQueryAddressState")
        print(f"{{ compiletime_md5(\"{pefile.split('_')[1].split('.')[0]}\"), {hex(ZwClose_offset)}, {hex(ZwOpenProcess_offset)}, {hex(PsLookupProcessByProcessId_offset)}, {hex(ZwDuplicateObject_offset)}, {hex(NtShutdownSystem_offset)}, {hex(PsGetProcessPeb_offset)}, {hex(memcpy_offset)}, {hex(MmCopyMemory_offset)}, {hex(MmMapIoSpace_offset)}, {hex(ZwReadVirtualMemory_offset)}, {hex(ZwQueryVirtualMemory_offset)}, {hex(MiQueryAddressState_offset)} }},")

if __name__ == "__main__":
    getFilelist()


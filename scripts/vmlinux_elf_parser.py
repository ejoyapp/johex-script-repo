"""
JoHex Official Script: Linux vmlinux (ELF) Parser
=================================================
A forensic structural parser for uncompressed Linux Kernel images (vmlinux).
Parses 32-bit and 64-bit ELF headers and section headers, specifically 
targeting and isolating kernel modules (.modinfo) and symbol tables (kallsyms).

This is an officially maintained script distributed with JoHex.
"""

__id__          = "johex.parser.vmlinux_elf"
__name__        = "vmlinux (ELF) Parser"
__version__     = "1.0.0"
__author__      = "EJoyApp Team"
__category__    = "Firmware & System"
__description__ = '''
    "A structural parser for uncompressed Linux Kernel images (vmlinux/ELF). "
    "Automatically resolves section headers to extract forensics data like "
    ".modinfo, kallsyms, and symbol tables."
'''
__features__    = '''
    "• 32-bit and 64-bit ELF structural parsing"
    "• Section Header Table (SHT) mapping"
    "• Automated extraction for .modinfo (Kernel Modules)"
    "• Automated extraction for .symtab, .strtab, and __ksymtab"
'''
__formats__     = ".elf, vmlinux, .ko"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"

import johexedit as hx
import struct

MAGIC_BYTES = b"\x7FELF"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    if hex_prefix.startswith(MAGIC_BYTES):
        name_lower = file_ext.lower()
        if "vmlinux" in name_lower or "elf" in name_lower or "ko" in name_lower:
            return 100
        return 80 # Generic ELF
    return 0

def detect(r):
    if r.size < 64: return False
    return r.read(0, 4) == MAGIC_BYTES

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse ELF Identity (e_ident)
    # =========================================================
    with root.struct("ELF Header", color=hx.BLUE) as ehdr:
        ehdr.bytes("Magic", 4, color=hx.YELLOW)
        
        bitness = r.u8(4)
        is_64 = (bitness == 2)
        ehdr.u8("Class", fmt=lambda v: "64-bit" if v == 2 else "32-bit" if v == 1 else "Unknown")
        
        endian = r.u8(5)
        # Note: We assume Little-Endian for simplicity in this script, 
        # as the vast majority of Android/Linux VMs are LE.
        ehdr.u8("Data (Endianness)", fmt=lambda v: "Little Endian" if v == 1 else "Big Endian" if v == 2 else "Unknown")
        
        ehdr.u8("Version")
        ehdr.u8("OS/ABI")
        ehdr.u8("ABI Version")
        ehdr.seek(16) # Skip padding
        
        ehdr.u16("Type", color=hx.CYAN)
        ehdr.u16("Machine (Architecture)")
        ehdr.u32("Version")

        # Handle 32/64 bit differences for the rest of the header
        if is_64:
            ehdr.u64("Entry Point Address", color=hx.YELLOW)
            phoff = ehdr.u64("Program Header Offset")
            shoff = ehdr.u64("Section Header Offset", color=hx.RED)
        else:
            ehdr.u32("Entry Point Address", color=hx.YELLOW)
            phoff = ehdr.u32("Program Header Offset")
            shoff = ehdr.u32("Section Header Offset", color=hx.RED)
            
        ehdr.u32("Flags")
        ehdr.u16("ELF Header Size")
        ehdr.u16("Program Header Entry Size")
        ehdr.u16("Program Header Number")
        shentsize = ehdr.u16("Section Header Entry Size")
        shnum = ehdr.u16("Section Header Number")
        shstrndx = ehdr.u16("Section Header String Table Index")

    # =========================================================
    # 2. Locate Section Header String Table (.shstrtab)
    # =========================================================
    # We need the string table to know the names of the sections (.modinfo, etc.)
    shstrtab_offset = 0
    if 0 < shoff < file_size and shstrndx < shnum:
        # Calculate where the string table section header is
        strtab_sh_offset = shoff + (shstrndx * shentsize)
        if is_64:
            shstrtab_offset = r.u64(strtab_sh_offset + 24)
        else:
            shstrtab_offset = r.u32(strtab_sh_offset + 16)

    # =========================================================
    # 3. Parse Section Headers & Extract Key Kernel Data
    # =========================================================
    if 0 < shoff < file_size and shnum > 0:
        
        # We'll create a dedicated group for our extractions
        extract_group = root.struct("Extracted Kernel Artifacts", color=hx.ORANGE)
        has_artifacts = False
        
        with root.struct(f"Section Headers ({shnum} entries)", color=hx.PURPLE) as shdrs:
            shdrs.seek(shoff)
            
            for i in range(shnum):
                entry_start = shoff + (i * shentsize)
                sh_name_idx = r.u32(entry_start)
                
                # Resolve section name
                sec_name = "Unknown"
                if shstrtab_offset > 0 and sh_name_idx > 0:
                    name_cursor = shstrtab_offset + sh_name_idx
                    name_bytes = bytearray()
                    while name_cursor < file_size:
                        b = r.u8(name_cursor)
                        if b == 0: break
                        name_bytes.append(b)
                        name_cursor += 1
                    sec_name = name_bytes.decode('ascii', 'ignore')
                elif i == 0:
                    sec_name = "NULL"

                with shdrs.struct(f"[{i}] {sec_name}") as sec:
                    sec.seek(entry_start)
                    sec.u32("Name Index")
                    sec.u32("Type")
                    
                    if is_64:
                        sec.u64("Flags")
                        sec.u64("Virtual Address", color=hx.YELLOW)
                        sec_offset = sec.u64("File Offset", color=hx.YELLOW)
                        sec_size = sec.u64("Size")
                        sec.u32("Link")
                        sec.u32("Info")
                        sec.u64("Address Alignment")
                        sec.u64("Entry Size")
                    else:
                        sec.u32("Flags")
                        sec.u32("Virtual Address", color=hx.YELLOW)
                        sec_offset = sec.u32("File Offset", color=hx.YELLOW)
                        sec_size = sec.u32("Size")
                        sec.u32("Link")
                        sec.u32("Info")
                        sec.u32("Address Alignment")
                        sec.u32("Entry Size")

                    if sec_offset > 0 and sec_size > 0 and sec_offset + sec_size <= file_size:
                        
                        extract_name = ""
                        ext_type = ".bin"
                        
                        if sec_name == ".modinfo":
                            extract_name = "kernel_modules_info.txt"
                            
                        elif sec_name.startswith("__ksymtab"):
                            extract_name = f"kernel{sec_name.replace('__', '_')}.bin"
                            
                        elif sec_name in (".symtab", ".strtab"):
                            extract_name = f"kernel{sec_name}.bin"
                            
                        elif "kallsyms" in sec_name:
                            extract_name = f"kernel_{sec_name}.bin"
                            
                        if extract_name:
                            has_artifacts = True
                            extract_group.seek(sec_offset)
                            extract_group.region(f"[EXTRACT:raw]{extract_name}", sec_offset, sec_size, color=hx.RED)

        if not has_artifacts:
            extract_group.region("No standard forensics sections found (Stripped).", 0, 0, color=hx.GRAY)

hx.register("vmlinux", detect, parse)
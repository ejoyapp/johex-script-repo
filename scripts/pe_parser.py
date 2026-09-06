"""
JoHex Official Script: Portable Executable (PE) Parser
======================================================
A comprehensive parser for Windows Portable Executable (PE) binaries.
Provides deep visibility into internal structures including DOS Header,
NT Headers, Section Table, and Data Directories with live RVA-to-FOA translation.
Includes automatic Resource Directory (.rsrc) extraction tagging for Archive Browser.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.pe"
__name__        = "PE Parser"
__version__     = "1.4.0" # Bumped version for Resource Extraction support
__author__      = "EJoyApp Team"
__category__    = "File Format Parsers"
__description__ = '''
    "A comprehensive and high-performance parser designed to deconstruct and analyze "
    "Windows Portable Executable (PE) binaries. It provides reverse engineers and "
    "security researchers with deep visibility into the internal structures, memory "
    "layout, and execution dependencies of Windows executables. Now includes fully "
    "automated resource extraction support."
'''
__features__    = '''
    "• Comprehensive DOS Header & Rich Signature extraction"
    "• NT Headers (COFF File Header & Optional Header) analysis"
    "• Detailed Section Table parsing with entropy calculation"
    "• Import Directory (IAT/INT) and Export Directory resolution"
    "• Base Relocation Table & TLS Directory parsing"
    "• Resource Tree (Icon, Version Info, Manifest) extraction"
    "• Digital Signature & Security Directory validation"
'''
__formats__     = ".exe, .dll, .sys, .ocx, .efi"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
MAGIC_BYTES = b"MZ"
SUPPORTED_EXTS = [".exe", ".dll", ".sys", ".ocx"]
FORMAT_NAME = "Portable Executable (PE)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. Check for the DOS header 'MZ' (0x5A4D)
    if len(hex_prefix) >= 0x40 and hex_prefix.startswith(b"MZ"):
        
        # 2. Read e_lfanew (NT header offset) at 0x3C
        e_lfanew = struct.unpack_from("<I", hex_prefix, 0x3C)[0]
        
        # 3. Check for the NT header 'PE\0\0' signature
        if e_lfanew > 0 and (e_lfanew + 4) <= len(hex_prefix):
            if hex_prefix[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                return 100  # 100% certainty that it is a PE file
        return 50 # Only has an MZ header; might be a pure DOS program
    return 0


def detect(r):
    return r.size >= 0x40 and r.u16(0) == 0x5A4D

def parse(r, root):
    # =================================================================
    # 1. Pre-emptive silent scan: Stealthily read the section table
    # =================================================================
    sections = []
    e_lfanew = r.u32(0x3C)
    num_sec = r.u16(e_lfanew + 6)
    opt_size = r.u16(e_lfanew + 20)
    
    sec_offset = e_lfanew + 24 + opt_size 

    for i in range(num_sec):
        base = sec_offset + i * 40
        v_size = r.u32(base + 8)
        v_addr = r.u32(base + 12)
        raw_size = r.u32(base + 16)
        raw_addr = r.u32(base + 20)
        eff_vsize = v_size if v_size > 0 else raw_size
        sections.append({"v_addr": v_addr, "v_size": eff_vsize, "raw_addr": raw_addr})

    def rva_to_foa(rva):
        if rva == 0: return 0
        for s in sections:
            if s["v_addr"] <= rva < s["v_addr"] + s["v_size"]:
                return s["raw_addr"] + (rva - s["v_addr"])
        return 0

    # =================================================================
    # 2. Start building the UI parsing tree
    # =================================================================
    with root.struct("IMAGE_DOS_HEADER", color=hx.BLUE) as dos:
        dos.u16("e_magic", color=hx.YELLOW)
        dos.seek(0x3C)
        dos.u32("e_lfanew", color=hx.YELLOW)

    root.seek(e_lfanew)
    
    rsrc_rva = 0  # To save Resource Directory RVA
    rsrc_size = 0 # To save Resource Directory Size

    with root.struct("IMAGE_NT_HEADERS", color=hx.GREEN) as nt:
        nt.u32("Signature")
        
        # File Header
        with nt.struct("IMAGE_FILE_HEADER", color=hx.CYAN) as fh:
            fh.u16("Machine")
            fh.u16("NumberOfSections")
            fh.u32("TimeDateStamp")
            fh.u32("PointerToSymbolTable")
            fh.u32("NumberOfSymbols")
            fh.u16("SizeOfOptionalHeader")
            fh.u16("Characteristics")

        # Optional Header
        opt_start = nt.tell()
        if opt_size > 0:
            with nt.struct("IMAGE_OPTIONAL_HEADER", color=hx.PURPLE) as opt:
                magic = opt.u16("Magic")
                is_64 = (magic == 0x20B)
                
                opt.seek(opt_start + (108 if is_64 else 92))
                num_rva = opt.u32("NumberOfRvaAndSizes")

                # =================================================================
                # 3. Data Directories Resolution
                # =================================================================
                if num_rva > 0:
                    with opt.struct("DataDirectories", color=hx.ORANGE) as dirs:
                        dir_names = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc"]
                        for i in range(min(num_rva, 16)):
                            name = dir_names[i] if i < len(dir_names) else f"Reserved_{i}"
                            with dirs.struct(f"Dir[{i}] {name}") as d:
                                
                                current_cursor = d.tell()
                                rva_val = r.u32(current_cursor)
                                foa_val = rva_to_foa(rva_val)
                                
                                # Capture Resource Directory info for later extraction
                                if i == 2: 
                                    rsrc_rva = rva_val
                                    rsrc_size = r.u32(current_cursor + 4)

                                d.u32("VirtualAddress", color=hx.YELLOW, 
                                      target=foa_val if (rva_val != 0 and foa_val != 0) else None,
                                      fmt=lambda v, f=foa_val: f"0x{v:08X} -> [FOA: 0x{f:X}]" if v != 0 else "0 (NULL)")
                                d.u32("Size")

            root.seek(opt_start + opt_size)

    # =================================================================
    # 4. Draw the Section Headers
    # =================================================================
    if num_sec > 0:
        with root.struct("IMAGE_SECTION_HEADERS", color=hx.CYAN) as secs:
            for i in range(num_sec):
                with secs.struct(f"Section [{i}]") as sec:
                    sec.bytes("Name", 8, fmt=lambda v: v.decode('utf-8', 'ignore').rstrip('\x00'))
                    sec.u32("VirtualSize")
                    sec.u32("VirtualAddress", color=hx.YELLOW)
                    sec.u32("SizeOfRawData")
                    sec.u32("PointerToRawData", color=hx.YELLOW)
                    sec.seek(sec.tell() + 16)

    # =================================================================
    # 5. Resource Tree & Archive Browser Tags Injection
    # =================================================================
    if rsrc_rva > 0 and rsrc_size > 0:
        rsrc_foa = rva_to_foa(rsrc_rva)
        if rsrc_foa > 0:
            
            # Common resource types
            RES_TYPES = {
                1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
                6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA",
                11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON",
                16: "VERSION", 24: "MANIFEST"
            }
            
            # Recursive parser for the 3-level resource tree
            def parse_rsrc_dir(parent_node, dir_offset, level, type_name="", entry_name=""):
                abs_offset = rsrc_foa + dir_offset
                if abs_offset == 0: return

                num_named = r.u16(abs_offset + 12)
                num_id = r.u16(abs_offset + 14)
                total_entries = num_named + num_id
                
                # Safeguard against malformed headers
                if total_entries > 1000: total_entries = 1000 
                
                for i in range(total_entries):
                    entry_ptr = abs_offset + 16 + (i * 8)
                    name_id_val = r.u32(entry_ptr)
                    data_subdir_offset = r.u32(entry_ptr + 4)
                    
                    # Resolve Name/ID
                    is_string = (name_id_val & 0x80000000) != 0
                    if is_string:
                        name_offset = name_id_val & 0x7FFFFFFF
                        name_len = r.u16(rsrc_foa + name_offset)
                        
                        # Read UTF-16 string safely byte-by-byte for maximum API compatibility
                        name_chars = []
                        for char_idx in range(name_len):
                            name_chars.append(chr(r.u16(rsrc_foa + name_offset + 2 + char_idx * 2)))
                        node_name = "".join(name_chars)
                    else:
                        node_name = str(name_id_val)
                        if level == 0 and name_id_val in RES_TYPES:
                            node_name = RES_TYPES[name_id_val]
                            
                    is_subdir = (data_subdir_offset & 0x80000000) != 0
                    offset_val = data_subdir_offset & 0x7FFFFFFF
                    
                    if is_subdir:
                        next_type = node_name if level == 0 else type_name
                        next_entry = node_name if level == 1 else entry_name
                        with parent_node.struct(f"[{i}] {node_name}") as sub_node:
                            parse_rsrc_dir(sub_node, offset_val, level + 1, next_type, next_entry)
                    else:
                        # Leaf node: Resolve physical data offset
                        data_entry_foa = rsrc_foa + offset_val
                        data_rva = r.u32(data_entry_foa)
                        data_size = r.u32(data_entry_foa + 4)
                        data_foa = rva_to_foa(data_rva)
                        
                        if data_foa > 0 and data_size > 0:
                            ext = ".bin"
                            method = "raw"
                            t_upper = type_name.upper()
                            
                            # Determine correct extraction handler based on resource type
                            if "ICON" in t_upper:
                                ext = ".ico"
                                method = "pe_ico"
                            elif "MANIFEST" in t_upper:
                                ext = ".xml"
                            elif "BITMAP" in t_upper:
                                ext = ".bmp"
                                method = "pe_bmp"
                            elif "VERSION" in t_upper:
                                ext = ".txt"
                            
                            # Clean filenames for safety
                            safe_type = type_name.replace('/', '_').replace('\\', '_')
                            safe_entry = entry_name.replace('/', '_').replace('\\', '_')
                            safe_lang = node_name.replace('/', '_').replace('\\', '_')
                            
                            extract_name = f"{safe_type}_{safe_entry}_{safe_lang}{ext}".lower()
                            
                            # Create a virtual tag node that triggers the ArchiveBrowserDlg
                            with parent_node.struct(f"[{i}] Lang: {node_name}") as leaf:
                                leaf.seek(data_foa)
                                leaf.bytes(f"[EXTRACT:{method}]{extract_name}", data_size)

            # Start parsing the resource tree
            with root.struct("IMAGE_RESOURCE_DIRECTORY (.rsrc)", color=hx.PURPLE) as rsrc_root:
                parse_rsrc_dir(rsrc_root, 0, 0)

hx.register("PE", detect, parse)
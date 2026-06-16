# pe_parser.py

"""
JoHex Official Script: Portable Executable (PE) Parser
======================================================
A comprehensive parser for Windows Portable Executable (PE) binaries.
Provides deep visibility into internal structures including DOS Header,
NT Headers, Section Table, and Data Directories with live RVA-to-FOA translation.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.pe"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    return r.size >= 0x40 and r.u16(0) == 0x5A4D

def parse(r, root):
    # =================================================================
    # 1. [Core Fix] Pre-emptive silent scan: Stealthily read the section 
    #    table before drawing the UI tree!
    # =================================================================
    sections = []
    e_lfanew = r.u32(0x3C)
    num_sec = r.u16(e_lfanew + 6)
    opt_size = r.u16(e_lfanew + 20)
    
    # Absolute physical offset of the section table = NT Header base + FileHeader(24) + OptionalHeaderSize
    sec_offset = e_lfanew + 24 + opt_size 

    # Read directly using Reader (r) without affecting the root cursor or generating UI nodes
    for i in range(num_sec):
        base = sec_offset + i * 40
        v_size = r.u32(base + 8)
        v_addr = r.u32(base + 12)
        raw_size = r.u32(base + 16)
        raw_addr = r.u32(base + 20)
        eff_vsize = v_size if v_size > 0 else raw_size
        sections.append({"v_addr": v_addr, "v_size": eff_vsize, "raw_addr": raw_addr})

    # The RVA to FOA converter is now ready to use at any time!
    def rva_to_foa(rva):
        if rva == 0: return 0
        for s in sections:
            if s["v_addr"] <= rva < s["v_addr"] + s["v_size"]:
                return s["raw_addr"] + (rva - s["v_addr"])
        return 0

    # =================================================================
    # 2. Start building the UI parsing tree in normal sequence
    # =================================================================
    with root.struct("IMAGE_DOS_HEADER", color=hx.BLUE) as dos:
        dos.u16("e_magic", color=hx.YELLOW)
        dos.seek(0x3C)
        dos.u32("e_lfanew", color=hx.YELLOW)

    root.seek(e_lfanew)
    with root.struct("IMAGE_NT_HEADERS", color=hx.GREEN) as nt:
        nt.u32("Signature")
        
        # File Header
        with nt.struct("IMAGE_FILE_HEADER", color=hx.CYAN) as fh:
            fh.seek(fh.tell() + 20) # Quickly skip the preceding fields
            fh.u16("SizeOfOptionalHeader")
            fh.u16("Characteristics")

        # Optional Header
        opt_start = nt.tell()
        if opt_size > 0:
            with nt.struct("IMAGE_OPTIONAL_HEADER", color=hx.PURPLE) as opt:
                magic = opt.u16("Magic")
                is_64 = (magic == 0x20B)
                
                # Skip a bunch of fields and head straight for the Data Directories count
                opt.seek(opt_start + (108 if is_64 else 92))
                num_rva = opt.u32("NumberOfRvaAndSizes")

                # =================================================================
                # 3. The moment to bring the hyperlinks to life!
                # =================================================================
                if num_rva > 0:
                    with opt.struct("DataDirectories", color=hx.ORANGE) as dirs:
                        dir_names = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc"]
                        for i in range(min(num_rva, 16)):
                            name = dir_names[i] if i < len(dir_names) else f"Reserved_{i}"
                            with dirs.struct(f"Dir[{i}] {name}") as d:
                                
                                # A. Peek ahead at the RVA value using r.u32()
                                current_cursor = d.tell()
                                rva_val = r.u32(current_cursor)
                                
                                # B. Calculate the actual physical FOA address
                                foa_val = rva_to_foa(rva_val)
                                
                                # C. Actually call C++ u32 to draw the node and inject the target!
                                d.u32("VirtualAddress", color=hx.YELLOW, 
                                      target=foa_val if (rva_val != 0 and foa_val != 0) else None,
                                      fmt=lambda v, f=foa_val: f"0x{v:08X} -> [FOA: 0x{f:X}]" if v != 0 else "0 (NULL)")
                                
                                d.u32("Size")

            root.seek(opt_start + opt_size)

    # 4. Draw the Section Headers
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

hx.register("PE", detect, parse)
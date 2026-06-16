# vmdk_parser.py

"""
JoHex Official Script: Virtual Machine Disk (VMDK) Parser
=========================================================
A forensic parser for VMware monolithic sparse virtual disks.
Extracts the embedded plaintext configuration descriptor and maps
the dual-layer Grain Directory (L1) and Grain Table (L2) paging structures.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.vmdk"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # The VMDK Sparse format header is fixed at 512 bytes or larger
    if r.size < 512:
        return False
        
    # VMDK magic number: "KDMV" (VMware Virtual Disk)
    try:
        magic = r.read(0, 4)
        return magic == b'KDMV'
    except Exception:
        return False

def parse(r, root):
    file_size = r.size

    # Sizes and offsets in VMDK are usually in units of "sectors" (512 bytes)
    SECTOR_SIZE = 512

    # =========================================================
    # 1. Parse VMDK Sparse Header
    # =========================================================
    with root.struct("VMDK Sparse Header", color=hx.BLUE) as hdr:
        hdr.bytes("Magic Number", 4, color=hx.YELLOW, fmt=lambda v: v.decode('ascii') + " (VMware Disk)")
        version = hdr.u32("Version", color=hx.CYAN)
        hdr.u32("Flags", fmt=lambda v: f"0x{v:08X} (Bit 0: Valid Newlines, Bit 1: Redundant GD)")
        
        # Core capacity calculation: capacity is in units of sectors
        capacity_sectors = hdr.u64("Capacity (in sectors)", color=hx.RED)
        capacity_bytes = capacity_sectors * SECTOR_SIZE
        hdr.u64("Capacity (Decoded)", fmt=lambda v, c=capacity_bytes: f"{c} bytes ({c / (1024**3):.2f} GB)")
        
        # Grain is the smallest physical storage block allocated by VMDK (similar to a Block in VDI)
        grain_sectors = hdr.u64("Grain Size (in sectors)", color=hx.RED)
        grain_bytes = grain_sectors * SECTOR_SIZE
        hdr.u64("Grain Size (Decoded)", fmt=lambda v, g=grain_bytes: f"{g} bytes ({g / 1024:.0f} KB)")
        
        # Extract key offsets (all must be multiplied by 512 to convert to FOA)
        desc_offset_sec = hdr.u64("Descriptor Offset", color=hx.YELLOW)
        desc_size_sec = hdr.u64("Descriptor Size")
        num_gtes_per_gt = hdr.u32("GTEs per GT", fmt=lambda v: f"{v} entries")
        rgd_offset_sec = hdr.u64("Redundant Grain Directory Offset")
        gd_offset_sec = hdr.u64("Grain Directory Offset", color=hx.YELLOW)
        overhead_sec = hdr.u64("Overhead Size")
        
        # Unclean shutdown flag and newline character detection (VMDK specific feature)
        hdr.u8("Unclean Shutdown", color=hx.PURPLE, fmt=lambda v: "YES (Needs Check)" if v else "NO (Clean)")
        hdr.bytes("Newline Characters", 4, color=hx.GRAY, fmt=lambda v: repr(v))
        hdr.u16("Compression Algorithm", fmt=lambda v: "1 (Deflate)" if v == 1 else "0 (None)")
        
        hdr.region("Padding", hdr.tell(), 433, color=hx.GRAY)

    # =========================================================
    # 2. Core FOA Calculation
    # =========================================================
    desc_foa = desc_offset_sec * SECTOR_SIZE
    desc_size_bytes = desc_size_sec * SECTOR_SIZE
    
    gd_foa = gd_offset_sec * SECTOR_SIZE
    rgd_foa = rgd_offset_sec * SECTOR_SIZE
    
    # Overhead is where the pure data area (physical Grains) actually starts
    data_foa = overhead_sec * SECTOR_SIZE

    # =========================================================
    # 3. Parse the embedded plaintext descriptor (Embedded Descriptor)
    # =========================================================
    if 0 < desc_foa < file_size and desc_size_bytes > 0:
        with root.struct("Embedded Text Descriptor", color=hx.GREEN) as desc_node:
            desc_node.seek(desc_foa)
            try:
                # Sniff and display this plaintext script directly on the UI!
                raw_text = r.read(desc_foa, min(desc_size_bytes, 1024))
                text_preview = raw_text.decode('ascii', 'ignore').replace('\n', ' | ')
                desc_node.region(f"Text Payload: {text_preview[:150]}...", desc_foa, desc_size_bytes, color=hx.CYAN)
            except Exception:
                desc_node.region("Raw Descriptor Data", desc_foa, desc_size_bytes, color=hx.GRAY)

    # =========================================================
    # 4. Inject Hyperlinks: One-click direct access to dual-layer page tables and physical data area
    # =========================================================
    with root.struct("VMDK Layout Shortcuts (FOA Jumps)", color=hx.ORANGE) as links:
        links.u64("Jump to Embedded Descriptor", color=hx.RED, target=desc_foa if desc_foa < file_size else None,
                  fmt=lambda v, f=desc_foa: f"[FOA: 0x{f:X}] -> Read Plaintext Config")
                  
        links.u64("Jump to Grain Directory (L1 Table)", color=hx.RED, target=gd_foa if gd_foa < file_size else None,
                  fmt=lambda v, f=gd_foa: f"[FOA: 0x{f:X}] -> Double Click to Inspect L1 Translation")
                  
        if rgd_foa > 0:
            links.u64("Jump to Redundant GD (Backup L1)", color=hx.RED, target=rgd_foa if rgd_foa < file_size else None,
                      fmt=lambda v, f=rgd_foa: f"[FOA: 0x{f:X}] -> Inspect Backup Directory")
                      
        links.u64("Jump to Physical Data Grains", color=hx.RED, target=data_foa if data_foa < file_size else None,
                  fmt=lambda v, f=data_foa: f"[FOA: 0x{f:X}] -> Inspect Raw VM Sectors")

    # =========================================================
    # 5. Macro Block Mapping
    # =========================================================
    if gd_foa < file_size and gd_foa > 0:
        # Grain Directory (L1 Page Table) size calculation: (capacity_sectors / grain_sectors) / num_gtes_per_gt * 4
        # To prevent overflow, only marked on a macro level
        root.region("Grain Directory (L1 Translation Table)", gd_foa, min(file_size - gd_foa, 4096), color=hx.PURPLE)

    if data_foa < file_size and data_foa > 0:
        root.region("Physical Data Grains (Virtual Machine Data)", data_foa, file_size - data_foa, color=hx.GRAY)

hx.register("VMDK", detect, parse)
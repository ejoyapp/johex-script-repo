# exfat_parser.py

"""
JoHex Official Script: Extensible File Allocation Table (ExFAT) Parser
======================================================================
A modern parser tailored for high-capacity flash storage file systems.
Decodes shift-based sector/cluster mathematics and provides direct FOA
navigation to the FAT table and the continuous Cluster Heap data area.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.exfat"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # The ExFAT boot sector requires at least 512 bytes
    if r.size < 512:
        return False
        
    try:
        # Sniff using a safe buffer
        sector_0 = r.read(0, 512)
        
        # ExFAT exclusive magic number: offset 3 must be "EXFAT   "
        has_oem = sector_0[3:11] == b'EXFAT   '
        has_boot_sig = sector_0[510] == 0x55 and sector_0[511] == 0xAA
        return has_oem and has_boot_sig
    except Exception:
        return False

def parse(r, root):
    file_size = r.size

    try:
        vbr_buffer = r.read(0, 512)
    except Exception as e:
        print(f"[ExFAT Parser] Failed to read VBR: {str(e)}")
        return

    # =========================================================
    # 1. Core Mathematical Conversion (Shift-based addressing mechanism)
    # =========================================================
    # ExFAT uses an exponent of 2^n to record sizes
    bytes_per_sector_shift = vbr_buffer[108]
    sectors_per_cluster_shift = vbr_buffer[109]
    
    bytes_per_sector = 1 << bytes_per_sector_shift
    sectors_per_cluster = 1 << sectors_per_cluster_shift
    cluster_size = bytes_per_sector * sectors_per_cluster

    # =========================================================
    # 2. Core Layout Offset Reading (Little Endian)
    # =========================================================
    def read_u32(buf, offset):
        return int.from_bytes(buf[offset:offset+4], 'little')
        
    fat_offset_sectors = read_u32(vbr_buffer, 80)
    fat_length_sectors = read_u32(vbr_buffer, 84)
    cluster_heap_offset_sectors = read_u32(vbr_buffer, 88)
    root_dir_first_cluster = read_u32(vbr_buffer, 96)
    
    num_fats = vbr_buffer[110]

    # Calculate absolute physical offset (FOA) - Note: offsets in VBR are all in "sectors"!
    fat1_foa = fat_offset_sectors * bytes_per_sector
    fat_size_bytes = fat_length_sectors * bytes_per_sector
    
    cluster_heap_foa = cluster_heap_offset_sectors * bytes_per_sector
    
    # Root directory physical offset: Also follows the "minus 2" rule
    root_dir_foa = cluster_heap_foa + (root_dir_first_cluster - 2) * cluster_size

    # =========================================================
    # 3. Parse VBR and render on the UI tree
    # =========================================================
    with root.struct("ExFAT Volume Boot Record (Sector 0)", color=hx.BLUE) as vbr:
        vbr.bytes("Jump Boot Instruction", 3, fmt=lambda v: v.hex().upper())
        vbr.bytes("OEM Name", 8, color=hx.YELLOW, fmt=lambda v: v.decode('ascii', 'ignore'))
        
        vbr.region("Must Be Zero", vbr.tell(), 53, color=hx.GRAY)
        vbr.seek(64)
        
        with vbr.struct("ExFAT Parameter Block", color=hx.GREEN) as epb:
            epb.u64("Partition Offset", fmt=lambda v: f"{v} sectors")
            epb.u64("Volume Length", color=hx.CYAN, fmt=lambda v: f"{v} sectors ({(v * bytes_per_sector) / (1024**3):.2f} GB)")
            
            epb.u32("FAT Offset", fmt=lambda v: f"Sector {v}")
            epb.u32("FAT Length", fmt=lambda v: f"{v} sectors")
            epb.u32("Cluster Heap Offset", fmt=lambda v: f"Sector {v}")
            epb.u32("Cluster Count", color=hx.CYAN)
            
            epb.u32("Root Directory First Cluster", color=hx.YELLOW, fmt=lambda v: f"Cluster {v}")
            epb.u32("Volume Serial Number", fmt=lambda v: f"0x{v:08X}")
            
            epb.u16("File System Revision", fmt=lambda v: f"{v >> 8}.{v & 0xFF}")
            epb.u16("Volume Flags", fmt=lambda v: f"0x{v:04X} (Bit 0: Active FAT)")
            
            # Stunning exponential parameter display
            epb.u8("Bytes Per Sector Shift", color=hx.RED, 
                   fmt=lambda v, bps=bytes_per_sector: f"{v} -> (2^{v} = {bps} bytes)")
            epb.u8("Sectors Per Cluster Shift", color=hx.RED, 
                   fmt=lambda v, spc=sectors_per_cluster: f"{v} -> (2^{v} = {spc} sectors)")
            
            epb.u8("Number of FATs", fmt=lambda v: "1 (Standard)" if v == 1 else "2 (TexFAT)")
            epb.u8("Drive Select")
            epb.u8("Percent In Use", fmt=lambda v: "Unknown" if v == 255 else f"{v}%")
            epb.region("Reserved", epb.tell(), 7, color=hx.GRAY)

        vbr.region("Boot Code", vbr.tell(), 390, color=hx.GRAY)
        vbr.u16("Boot Sector Signature", color=hx.YELLOW, fmt=lambda v: f"0x{v:04X}")

    # =========================================================
    # 4. Inject Hyperlinks: One-click direct access to core data areas
    # =========================================================
    with root.struct("ExFAT Layout & Quick Jumps", color=hx.ORANGE) as links:
        links.u32("Calculated Cluster Size", fmt=lambda v, c=cluster_size: f"{c} bytes")
        
        links.u64("Jump to FAT Allocation Table", color=hx.RED, target=fat1_foa if fat1_foa < file_size else None,
                  fmt=lambda v, f=fat1_foa: f"[FOA: 0x{f:X}] -> Double Click to Inspect FAT")
                  
        links.u64("Jump to Cluster Heap (Data Area)", color=hx.RED, target=cluster_heap_foa if cluster_heap_foa < file_size else None,
                  fmt=lambda v, f=cluster_heap_foa: f"[FOA: 0x{f:X}] -> Double Click to Inspect User Data")
                  
        links.u64("Jump to Root Directory", color=hx.RED, target=root_dir_foa if root_dir_foa < file_size else None,
                  fmt=lambda v, f=root_dir_foa: f"[FOA: 0x{f:X}] -> Double Click to Inspect Root Files")

    # =========================================================
    # 5. Macro Block Mapping
    # =========================================================
    if fat1_foa < file_size and fat_size_bytes > 0:
        root.region("FAT (File Allocation Table)", fat1_foa, fat_size_bytes, color=hx.CYAN)
        
    if cluster_heap_foa < file_size:
        root.region("Cluster Heap (User Data & Directories)", cluster_heap_foa, file_size - cluster_heap_foa, color=hx.GRAY)

hx.register("EXFAT", detect, parse)
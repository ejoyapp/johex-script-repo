# vdi_parser.py

"""
JoHex Official Script: VirtualBox Disk Image (VDI) Parser
=========================================================
A structural parser for Oracle VM VirtualBox dynamic disk images.
Analyzes the Pre-header and Main Header, separating virtual capacity
from physical allocation, and provides jumps to the Block Map and raw sectors.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.vdi"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # VDI files must have at least a 72-byte pre-header and magic number
    if r.size < 72:
        return False
        
    # The VDI magic number is fixed at offset 64
    try:
        magic = r.u32(64, le=True)
        return magic == 0xBEDA107F
    except Exception:
        return False

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse Pre-header
    # =========================================================
    with root.struct("VDI Pre-header (72 bytes)", color=hx.BLUE) as pre:
        # VDI's extremely friendly plain text introduction: "<<< Oracle VM VirtualBox Disk Image >>>"
        pre.bytes("Text Description", 64, color=hx.YELLOW, fmt=lambda v: v.decode('ascii', 'ignore').strip())
        pre.u32("Signature (Magic)", color=hx.RED, fmt=lambda v: f"0x{v:08X} (Valid VDI)")
        pre.u32("Version", color=hx.CYAN, fmt=lambda v: f"{v >> 16}.{v & 0xFFFF} (Usually 1.1)")

    # =========================================================
    # 2. Parse Main Header (usually starts at offset 72, size is about 400 bytes)
    # =========================================================
    with root.struct("VDI Main Header", color=hx.GREEN) as hdr:
        hdr.seek(72)
        header_size = hdr.u32("Header Size", fmt=lambda v: f"{v} bytes")
        
        image_type = hdr.u32("Image Type", color=hx.RED, fmt=lambda v: "1 (Dynamic)" if v == 1 else "2 (Static/Fixed)" if v == 2 else str(v))
        hdr.u32("Image Flags")
        hdr.bytes("Description", 256, fmt=lambda v: v.decode('ascii', 'ignore').strip())
        
        # Extract the two core physical landing points!
        offset_blocks = hdr.u32("Offset to Block Map", color=hx.YELLOW)
        offset_data = hdr.u32("Offset to Image Data", color=hx.YELLOW)
        
        hdr.u32("Cylinders (Legacy)")
        hdr.u32("Heads (Legacy)")
        hdr.u32("Sectors (Legacy)")
        hdr.u32("Sector Size")
        
        # The "Virtual" and "Physical" of the disk
        disk_size = hdr.u64("Virtual Disk Size", color=hx.CYAN, fmt=lambda v: f"{v} bytes ({v / (1024**3):.2f} GB)")
        block_size = hdr.u32("Block Size", color=hx.RED, fmt=lambda v: f"{v} bytes ({v / (1024**2):.0f} MB)")
        hdr.u32("Block Extra Data")
        
        blocks_in_disk = hdr.u32("Total Blocks (Virtual Capacity)")
        blocks_allocated = hdr.u32("Allocated Blocks (Physical Usage)")
        
        # VirtualBox snapshots and differencing disk links rely on these UUIDs
        hdr.bytes("UUID Creation", 16, fmt=lambda v: v.hex().upper())
        hdr.bytes("UUID Modification", 16, fmt=lambda v: v.hex().upper())
        hdr.bytes("UUID Linkage", 16, fmt=lambda v: v.hex().upper())
        hdr.bytes("UUID Parent Modification", 16, fmt=lambda v: v.hex().upper())

    # =========================================================
    # 3. Inject Hyperlinks: One-click direct access to the block map and physical data area
    # =========================================================
    with root.struct("VDI Layout Shortcuts", color=hx.ORANGE) as links:
        # Block Map is an array of uint32, size is Total Blocks * 4
        map_size = blocks_in_disk * 4
        
        links.u64("Jump to Block Map (Translation Table)", color=hx.RED, target=offset_blocks if offset_blocks < file_size else None,
                  fmt=lambda v, f=offset_blocks: f"[FOA: 0x{f:X}] -> Inspect Virtual-to-Physical Map")
                  
        links.u64("Jump to Physical Image Data", color=hx.RED, target=offset_data if offset_data < file_size else None,
                  fmt=lambda v, f=offset_data: f"[FOA: 0x{f:X}] -> Inspect Raw Disk Sectors (e.g., MBR/NTFS inside VDI)")

    # =========================================================
    # 4. Macro Block Mapping
    # =========================================================
    # Block Map Area
    if 0 < offset_blocks < file_size and map_size > 0:
        root.region(f"Block Map (Array of {blocks_in_disk} uint32 entries)", offset_blocks, map_size, color=hx.PURPLE)

    # Actual physical payload area (the VM's OS resides here)
    if 0 < offset_data < file_size:
        root.region(f"Image Data ({blocks_allocated} Allocated Physical Blocks)", offset_data, file_size - offset_data, color=hx.GRAY)

hx.register("VDI", detect, parse)
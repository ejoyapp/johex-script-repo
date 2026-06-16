# ext4_parser.py

"""
JoHex Official Script: Fourth Extended Filesystem (ext4) Parser
===============================================================
A deep-dive parser for the standard Linux ext4 file system.
Exposes the 1024-byte Superblock, Block Group Descriptor Tables (BGDT),
and performs bit-shift offset calculations to locate the Root Directory (Inode 2).

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.ext4"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # The ext4 superblock is always fixed at the 1024-byte offset of the partition
    # And its internal offset 0x38 (i.e., absolute offset 1024 + 56 = 1080) must be the magic number 0xEF53
    if r.size < 2048:
        return False
        
    try:
        magic = r.u16(1080)
        return magic == 0xEF53
    except Exception:
        return False

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Safely read the Superblock
    # =========================================================
    try:
        # Superblock size is 1024 bytes
        sb_buffer = r.read(1024, 1024)
    except Exception as e:
        print(f"[ext4 Parser] Failed to read Superblock at 1024: {str(e)}")
        return

    # Little-endian integer extraction helper functions
    def read_u32(buf, offset):
        return int.from_bytes(buf[offset:offset+4], 'little')
    def read_u16(buf, offset):
        return int.from_bytes(buf[offset:offset+2], 'little')

    # Extract core parameters
    s_inodes_count = read_u32(sb_buffer, 0)
    s_blocks_count_lo = read_u32(sb_buffer, 4)
    s_log_block_size = read_u32(sb_buffer, 24)
    s_blocks_per_group = read_u32(sb_buffer, 32)
    s_inodes_per_group = read_u32(sb_buffer, 40)
    s_magic = read_u16(sb_buffer, 56)
    s_inode_size = read_u16(sb_buffer, 88)
    s_desc_size = read_u16(sb_buffer, 254)

    # [Core Mathematical Conversion]: Classic Linux kernel left-shift to calculate block size
    # Block size = 1024 * (2 ^ s_log_block_size)
    block_size = 1024 << s_log_block_size

    # =========================================================
    # 2. Calculate Block Group Descriptor Table (BGDT) physical address
    # =========================================================
    # The Block Group Descriptor Table immediately follows the block containing the superblock.
    # If block_size == 1024, the superblock is in Block 1, BGDT is in Block 2 (offset 2048)
    # If block_size > 1024 (usually 4096), the superblock is in Block 0, BGDT is in Block 1 (offset 4096)
    bgdt_foa = 2048 if block_size == 1024 else block_size

    # =========================================================
    # 3. Extract Group 0 descriptor to locate Inode 2 (Root Directory)
    # =========================================================
    try:
        # Read Group 0 descriptor (size usually determined by s_desc_size, ext4 default is 64 bytes)
        desc_size = s_desc_size if s_desc_size > 0 else 32
        bg0_buffer = r.read(bgdt_foa, desc_size)
        
        # Extract the block number where Group 0's Inode table is located (lower 32 bits)
        bg_inode_table_lo = read_u32(bg0_buffer, 8)
        
        # Calculate the absolute physical offset of the Inode table
        inode_table_foa = bg_inode_table_lo * block_size
        
        # The root directory is always Inode 2 (Inode index starts from 1, so subtract 1)
        root_inode_foa = inode_table_foa + (2 - 1) * s_inode_size
    except Exception:
        root_inode_foa = 0

    # =========================================================
    # 4. Render Superblock structure on the UI tree
    # =========================================================
    root.region("Boot Sector / Padding (1024 Bytes)", 0, 1024, color=hx.GRAY)

    with root.struct("ext4 Superblock", color=hx.BLUE) as sb:
        sb.seek(1024)
        sb.u32("Inodes Count", color=hx.CYAN)
        sb.u32("Blocks Count (Low)", fmt=lambda v: f"{v} blocks (Vol Size: {v * block_size / (1024**3):.2f} GB)")
        sb.u32("Reserved Blocks")
        sb.u32("Free Blocks Count")
        sb.u32("Free Inodes Count")
        sb.u32("First Data Block")
        
        sb.u32("Log Block Size", color=hx.RED, fmt=lambda v: f"{v} -> (1024 << {v} = {block_size} bytes)")
        sb.u32("Log Cluster Size")
        sb.u32("Blocks Per Group", color=hx.YELLOW)
        sb.u32("Clusters Per Group")
        sb.u32("Inodes Per Group", color=hx.YELLOW)
        
        sb.seek(1024 + 56)
        sb.u16("Magic Signature", color=hx.YELLOW, fmt=lambda v: f"0x{v:04X} (Valid ext4)")
        sb.u16("State", fmt=lambda v: "1 (Cleanly unmounted)" if v == 1 else "2 (Errors detected)" if v == 2 else str(v))
        sb.u16("Errors Behavior")
        sb.u16("Minor Revision Level")
        
        sb.seek(1024 + 88)
        sb.u16("Inode Size", color=hx.RED, fmt=lambda v: f"{v} bytes")
        sb.u16("Block Group # Hosting this Superblock")
        
        sb.seek(1024 + 112)
        sb.u32("First Inode", fmt=lambda v: f"{v} (Standard is 11)")
        
        sb.seek(1024 + 120)
        sb.u32("Incompatible Features", color=hx.GREEN, fmt=lambda v: f"0x{v:08X} (Bit 6 = extents, Bit 7 = 64bit)")
        
        sb.seek(1024 + 254)
        sb.u16("Group Descriptor Size", color=hx.CYAN, fmt=lambda v: f"{v} bytes")

    # =========================================================
    # 5. Inject Hyperlinks: One-click direct access to BGDT and root directory
    # =========================================================
    with root.struct("ext4 Navigation Links (FOA Shortcuts)", color=hx.ORANGE) as links:
        links.u32("Calculated Block Size", fmt=lambda v, c=block_size: f"{c} bytes")
        
        links.u64("Jump to Block Group Descriptors", color=hx.RED, target=bgdt_foa if bgdt_foa < file_size else None,
                  fmt=lambda v, f=bgdt_foa: f"[FOA: 0x{f:X}] -> Double Click to Inspect BGDT")
                  
        if root_inode_foa > 0:
            links.u64("Jump to Root Directory (Inode 2)", color=hx.RED, target=root_inode_foa if root_inode_foa < file_size else None,
                      fmt=lambda v, f=root_inode_foa: f"[FOA: 0x{f:X}] -> Double Click to Inspect Root '/' Inode")

    # =========================================================
    # 6. Macro Block Mapping
    # =========================================================
    padding = bgdt_foa - 2048
    if padding > 0:
        root.region("Superblock Padding", 2048, padding, color=hx.GRAY)

    if bgdt_foa < file_size:
        root.region("Block Group Descriptor Table (Group 0)", bgdt_foa, desc_size * 2, color=hx.CYAN)

    if 0 < root_inode_foa < file_size:
        with root.struct("Root Directory (Inode 2)", color=hx.PURPLE) as root_inode:
            root_inode.seek(root_inode_foa)
            root_inode.u16("Mode (Permissions)", color=hx.YELLOW, fmt=lambda v: f"0x{v:04X} (e.g., 0x41ED = drwxr-xr-x)")
            root_inode.u16("UID (Owner)")
            root_inode.u32("Size (Lower 32-bit)")
            root_inode.u32("Access Time")
            root_inode.u32("Creation Time")
            root_inode.u32("Modification Time")
            root_inode.u32("Deletion Time")
            root_inode.u16("GID (Group ID)")
            root_inode.u16("Links Count", color=hx.GREEN)
            root_inode.u32("Blocks Count (512-byte blocks)")
            root_inode.u32("Flags", color=hx.CYAN, fmt=lambda v: f"0x{v:08X} (Bit 19 = Extents)")
            
            # The core essence of ext4: Extents tree replaces ext3's indirect block pointers
            root_inode.region("Extents Tree Root (i_block)", root_inode.tell(), 60, color=hx.ORANGE)

hx.register("EXT4", detect, parse)
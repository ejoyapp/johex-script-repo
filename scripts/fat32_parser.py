# fat32_parser.py

"""
JoHex Official Script: File Allocation Table 32 (FAT32) Parser
==============================================================
A structural parser for the classic FAT32 file system.
Calculates exact physical offsets (FOA) for the Reserved Area, FSInfo sector,
Allocation Tables (FAT1/FAT2), and the dynamic Root Directory cluster chain.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.fat32"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
# The File System Type string "FAT32   " is typically located at offset 0x52
MAGIC_BYTES = b"FAT32   "
SUPPORTED_EXTS = [".img", ".dd", ".bin", ".vhd", ".vhdx", ".fat32", ".fat"]
FORMAT_NAME = "FAT32 File System Image"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. A standard FAT32 Volume Boot Record (VBR) is 512 bytes long.
    if len(hex_prefix) >= 512:
        
        # 2. Check for the standard boot sector signature (0x55 0xAA) at offset 0x1FE (510).
        # Use struct to unpack as a little-endian 16-bit unsigned integer (<H).
        boot_signature = struct.unpack_from("<H", hex_prefix, 510)[0]
        
        if boot_signature == 0xAA55:
            
            # 3. Differentiate FAT32 from FAT12/FAT16.
            # In FAT32, the 16-bit Sectors Per FAT (BPB_FATSz16) at offset 0x16 must be 0.
            # The 32-bit Sectors Per FAT (BPB_FATSz32) at offset 0x24 must be non-zero.
            bpb_fatsz16 = struct.unpack_from("<H", hex_prefix, 0x16)[0]
            bpb_fatsz32 = struct.unpack_from("<I", hex_prefix, 0x24)[0]
            
            if bpb_fatsz16 == 0 and bpb_fatsz32 > 0:
                
                # 4. Check the File System Type string at offset 0x52.
                # While technically informational according to specs, it is a very strong indicator when present.
                bs_filsystype = hex_prefix[0x52:0x52+8]
                
                if bs_filsystype == MAGIC_BYTES:
                    return 100  # 100% certainty that it is a FAT32 volume/image
                
                # It has FAT32 structural characteristics, but lacks the "FAT32   " string
                return 80
                
            # It has a boot signature, but structural fields don't match FAT32 (might be FAT16, NTFS, or MBR)
            return 20
            
    # The file is severely truncated (less than a single sector)
    return 0

def detect(r):
    if r.size < 512:
        return False
        
    # Read Sector 0
    sector_0 = r.read(0, 512)
    
    # Boot magic number validation
    if sector_0[510] != 0x55 or sector_0[511] != 0xAA:
        return False
        
    # FAT32 exclusive feature: Must have "FAT32   " string at offset 0x52 (82)
    fat_type_string = sector_0[82:90]
    return fat_type_string == b'FAT32   '

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse VBR (Volume Boot Record) and BPB
    # =========================================================
    with root.struct("FAT32 Volume Boot Record (Sector 0)", color=hx.BLUE) as vbr:
        vbr.bytes("Jump Code", 3, fmt=lambda v: v.hex().upper())
        vbr.bytes("OEM Name", 8, color=hx.YELLOW, fmt=lambda v: v.decode('ascii', 'ignore'))
        
        with vbr.struct("BIOS Parameter Block (BPB)", color=hx.GREEN) as bpb:
            bytes_per_sector = bpb.u16("Bytes Per Sector", color=hx.RED, fmt=lambda v: f"{v} bytes")
            sectors_per_cluster = bpb.u8("Sectors Per Cluster", color=hx.RED, fmt=lambda v: f"{v} sectors")
            
            cluster_size = bytes_per_sector * sectors_per_cluster
            
            reserved_sectors = bpb.u16("Reserved Sectors", color=hx.CYAN)
            num_fats = bpb.u8("Number of FATs", fmt=lambda v: f"{v} (Usually 2)")
            
            # The root directory size for FAT32 must be 0 here (the root directory becomes a standard cluster chain)
            bpb.u16("Root Dir Entries", fmt=lambda v: "0 (Valid for FAT32)" if v == 0 else str(v))
            bpb.u16("Total Sectors (16-bit)", fmt=lambda v: "0 (Use 32-bit field instead)" if v == 0 else str(v))
            bpb.u8("Media Descriptor")
            
            # In FAT32, the old 16-bit FAT size must be 0
            bpb.u16("Sectors Per FAT (16-bit)", fmt=lambda v: "0 (Valid for FAT32)" if v == 0 else str(v))
            
            bpb.u16("Sectors Per Track")
            bpb.u16("Number of Heads")
            bpb.u32("Hidden Sectors")
            total_sectors = bpb.u32("Total Sectors (32-bit)", color=hx.CYAN)
            
        with vbr.struct("FAT32 Extended BPB", color=hx.GREEN) as ebpb:
            sectors_per_fat = ebpb.u32("Sectors Per FAT (32-bit)", color=hx.CYAN)
            ebpb.u16("Extended Flags")
            ebpb.u16("FAT Version")
            
            # Starting cluster number of the root directory (usually 2)
            root_cluster = ebpb.u32("Root Directory Cluster", color=hx.YELLOW)
            
            fsinfo_sector = ebpb.u16("FSInfo Sector", fmt=lambda v: f"Sector {v}")
            ebpb.u16("Backup Boot Sector", fmt=lambda v: f"Sector {v}")
            ebpb.region("Reserved", ebpb.tell(), 12, color=hx.GRAY)
            
            ebpb.u8("Drive Number")
            ebpb.u8("Reserved1")
            ebpb.u8("Boot Signature", fmt=lambda v: f"0x{v:02X} (Should be 0x29)")
            ebpb.u32("Volume ID", fmt=lambda v: f"0x{v:08X}")
            ebpb.bytes("Volume Label", 11, fmt=lambda v: v.decode('ascii', 'ignore').strip())
            ebpb.bytes("File System Type", 8, color=hx.YELLOW, fmt=lambda v: v.decode('ascii', 'ignore'))
            
        vbr.region("Boot Code", vbr.tell(), 420, color=hx.GRAY)
        vbr.u16("Boot Sector Signature", color=hx.YELLOW, fmt=lambda v: f"0x{v:04X}")

    # =========================================================
    # 2. Core addressing calculation (FAT32 core algorithm)
    # =========================================================
    # 1. Absolute offset of the FAT table: Skip the reserved sectors
    fat1_foa = reserved_sectors * bytes_per_sector
    
    # 2. Absolute offset of FAT2: Skip FAT1
    fat2_foa = fat1_foa + (sectors_per_fat * bytes_per_sector)
    
    # 3. Absolute offset of the data area: Skip all FAT tables
    data_foa = fat1_foa + (num_fats * sectors_per_fat * bytes_per_sector)
    
    # 4. Absolute offset of the root directory: [Important] Cluster numbers start from 2!
    root_dir_foa = data_foa + (root_cluster - 2) * cluster_size

    # Inject FOA rapid jump hyperlinks
    with root.struct("FAT32 Global Layout & Shortcuts", color=hx.ORANGE) as links:
        links.u32("Cluster Size", fmt=lambda v, c=cluster_size: f"{c} bytes")
        
        links.u64("Jump to FAT1 Start", color=hx.RED, target=fat1_foa if fat1_foa < file_size else None,
                  fmt=lambda v, f=fat1_foa: f"[FOA: 0x{f:X}] -> The File Allocation Table")
                  
        if num_fats >= 2:
            links.u64("Jump to FAT2 Start", color=hx.RED, target=fat2_foa if fat2_foa < file_size else None,
                      fmt=lambda v, f=fat2_foa: f"[FOA: 0x{f:X}] -> FAT Backup")
                      
        links.u64("Jump to Data Area Start", color=hx.RED, target=data_foa if data_foa < file_size else None,
                  fmt=lambda v, f=data_foa: f"[FOA: 0x{f:X}] -> Raw Data / Cluster 2")
                  
        links.u64("Jump to Root Directory", color=hx.RED, target=root_dir_foa if root_dir_foa < file_size else None,
                  fmt=lambda v, f=root_dir_foa: f"[FOA: 0x{f:X}] -> Double Click to Inspect Files")

    # =========================================================
    # 3. Parse FSInfo sector (FAT32 exclusive feature)
    # =========================================================
    fsinfo_foa = fsinfo_sector * bytes_per_sector
    if 0 < fsinfo_foa < file_size:
        with root.struct("FSInfo Sector", color=hx.PURPLE) as fsinfo:
            fsinfo.seek(fsinfo_foa)
            fsinfo.u32("Lead Signature", color=hx.YELLOW, fmt=lambda v: "0x52526141 (Valid)" if v == 0x41615252 else f"0x{v:08X}")
            fsinfo.region("Reserved1", fsinfo.tell(), 480, color=hx.GRAY)
            fsinfo.u32("Struct Signature", color=hx.YELLOW, fmt=lambda v: "0x72724161 (Valid)" if v == 0x61417272 else f"0x{v:08X}")
            
            # Records how many free clusters are currently available (0xFFFFFFFF means it needs to be recalculated)
            fsinfo.u32("Free Cluster Count", color=hx.CYAN, fmt=lambda v: "Unknown (Needs Recalc)" if v == 0xFFFFFFFF else f"{v} clusters")
            
            # The cluster from which the OS will start looking the next time it allocates space
            fsinfo.u32("Next Free Cluster", fmt=lambda v: f"Cluster {v}")
            fsinfo.region("Reserved2", fsinfo.tell(), 12, color=hx.GRAY)
            fsinfo.u32("Trail Signature", fmt=lambda v: f"0x{v:08X}")

    # =========================================================
    # 4. Macro block annotation
    # =========================================================
    if fat1_foa < file_size:
        root.region("Reserved Area", 0, fat1_foa, color=hx.GRAY)
        
    fat1_size = sectors_per_fat * bytes_per_sector
    if fat1_foa < file_size and fat1_size > 0:
        root.region("FAT1 (File Allocation Table)", fat1_foa, fat1_size, color=hx.CYAN)
        
    if num_fats >= 2 and fat2_foa < file_size and fat1_size > 0:
        root.region("FAT2 (Backup Allocation Table)", fat2_foa, fat1_size, color=hx.GRAY)

    if data_foa < file_size:
        root.region("Data Area (Clusters)", data_foa, file_size - data_foa, color=hx.ORANGE)

hx.register("FAT32", detect, parse)
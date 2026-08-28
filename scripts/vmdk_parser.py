"""
JoHex Official Script: Virtual Machine Disk (VMDK) Parser
=========================================================
A forensic parser for VMware monolithic sparse virtual disks.
Extracts the embedded plaintext configuration descriptor and maps
the dual-layer Grain Directory (L1) and Grain Table (L2) paging structures.
Includes automatic heuristic carving for Modern Android (EROFS/F2FS) and Legacy Linux.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.vmdk"
__name__        = "VMDK Parser"
__version__     = "1.4.0" # Unified Carving Engine (Legacy + Modern)
__author__      = "EJoyApp Team"
__category__    = "Virtual Disk Parsers"
__description__ = '''
    "A forensic parser for VMware monolithic sparse virtual disks. "
    "Extracts the embedded plaintext configuration descriptor and maps "
    "the dual-layer Grain Directory (L1) and Grain Table (L2) structures. "
    "Features a unified Whole File Block Scanning engine for Android/Linux."
'''
__features__    = '''
    "• Embedded plaintext configuration descriptor extraction"
    "• Dual-layer Grain Directory (L1) and Grain Table (L2) mapping"
    "• Unified carving for Ext4, EROFS, F2FS, Android Sparse & Boot, SquashFS, ELF"
    "• Deflate compression detection"
'''
__formats__     = ".vmdk"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

MAGIC_BYTES = b"KDMV"
SUPPORTED_EXTS = [".vmdk"]
FORMAT_NAME = "VMware Virtual Disk (VMDK)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    if len(hex_prefix) >= 4 and hex_prefix.startswith(MAGIC_BYTES):
        if len(hex_prefix) >= 8:
            version = struct.unpack_from("<I", hex_prefix, 4)[0]
            if version in (1, 2, 3): return 100
            return 80
        return 50
    if hex_prefix.startswith(b"# Disk DescriptorFile"):
        return 100
    return 0

def detect(r):
    if r.size < 512: return False
    try: return r.read(0, 4) == b'KDMV'
    except Exception: return False

def parse(r, root):
    file_size = r.size
    SECTOR_SIZE = 512

    # =========================================================
    # 1. Parse VMDK Sparse Header
    # =========================================================
    with root.struct("VMDK Sparse Header", color=hx.BLUE) as hdr:
        hdr.bytes("Magic Number", 4, color=hx.YELLOW)
        version = hdr.u32("Version", color=hx.CYAN)
        hdr.u32("Flags")
        
        capacity_sectors = hdr.u64("Capacity (in sectors)")
        grain_sectors = hdr.u64("Grain Size (in sectors)")
        
        desc_offset_sec = hdr.u64("Descriptor Offset", color=hx.YELLOW)
        desc_size_sec = hdr.u64("Descriptor Size")
        num_gtes_per_gt = hdr.u32("GTEs per GT")
        rgd_offset_sec = hdr.u64("Redundant Grain Directory Offset")
        gd_offset_sec = hdr.u64("Grain Directory Offset", color=hx.YELLOW)
        overhead_sec = hdr.u64("Overhead Size")
        
        hdr.u8("Unclean Shutdown")
        hdr.bytes("Newline Characters", 4)
        comp_alg = hdr.u16("Compression Algorithm", fmt=lambda v: "1 (Deflate)" if v == 1 else "0 (None)")
        hdr.region("Padding", hdr.tell(), 433, color=hx.GRAY)

    desc_foa = desc_offset_sec * SECTOR_SIZE
    desc_size_bytes = desc_size_sec * SECTOR_SIZE
    gd_foa = gd_offset_sec * SECTOR_SIZE
    data_foa = overhead_sec * SECTOR_SIZE

    if 0 < desc_foa < file_size and desc_size_bytes > 0:
        with root.struct("Embedded Text Descriptor", color=hx.GREEN) as desc_node:
            desc_node.seek(desc_foa)
            try:
                desc_node.region(f"[EXTRACT:raw]vmdk_descriptor.txt", desc_foa, desc_size_bytes, color=hx.CYAN)
            except Exception:
                pass

    # =========================================================
    # 2. Unified Robust Heuristic Carving (Deep Scan + Deduplication)
    # =========================================================
    if 0 < data_foa < file_size:
        if comp_alg == 1:
            with root.struct("Heuristic Carving (Disabled)", color=hx.GRAY) as carve_node:
                carve_node.region("VMDK is compressed (Deflate). Raw scanning disabled.", data_foa, file_size - data_foa, color=hx.GRAY)
        else:
            with root.struct("Embedded Android/Linux Images (Extracted)", color=hx.ORANGE) as carve_node:
                chunk_size = 16 * 1024 * 1024
                overlap = 4096
                cursor = data_foa
                img_count = 0
                
                found_types = set()

                def add_extract(name, abs_offset, type_key):
                    nonlocal img_count
                    if type_key in found_types: return
                    found_types.add(type_key)
                    
                    extract_size = file_size - abs_offset
                    carve_node.region(f"[EXTRACT:raw]{name}_{img_count}.img", abs_offset, extract_size, color=hx.RED)
                    img_count += 1

                while cursor < file_size:
                    read_size = min(chunk_size + overlap, file_size - cursor)
                    chunk = r.read(cursor, read_size)
                    if not chunk: break

                    # 1. Android Sparse Image
                    if "sparse" not in found_types:
                        idx = chunk.find(b"\x3A\xFF\x26\xED")
                        if idx != -1: add_extract("android_sparse", cursor + idx, "sparse")

                    # 2. Modern Android EROFS (\xE2\xE1\xF5\xE0 at 0x400)
                    if "erofs" not in found_types:
                        idx = chunk.find(b"\xE2\xE1\xF5\xE0")
                        if idx != -1 and idx >= 0x400: add_extract("android_erofs", cursor + idx - 0x400, "erofs")

                    # 3. Modern Android F2FS (\x10\x20\xF5\xF2 at 0x400)
                    if "f2fs" not in found_types:
                        idx = chunk.find(b"\x10\x20\xF5\xF2")
                        if idx != -1 and idx >= 0x400: add_extract("android_f2fs_data", cursor + idx - 0x400, "f2fs")

                    # 4. Legacy Ext4 (\x53\xEF at 0x438)
                    if "ext4" not in found_types:
                        idx = chunk.find(b"\x53\xEF")
                        if idx != -1 and idx >= 0x438: add_extract("android_ext4", cursor + idx - 0x438, "ext4")

                    # 5. Android Boot
                    if "boot" not in found_types:
                        idx = chunk.find(b"ANDROID!")
                        if idx != -1: add_extract("android_boot", cursor + idx, "boot")

                    # 6. Legacy SquashFS
                    if "squashfs" not in found_types:
                        sq_idx = chunk.find(b"hsqs")
                        if sq_idx == -1: sq_idx = chunk.find(b"sqsh")
                        if sq_idx != -1: add_extract("linux_squashfs", cursor + sq_idx, "squashfs")

                    # 7. Linux ELF Kernel
                    if "elf" not in found_types:
                        idx = chunk.find(b"\x7FELF")
                        if idx != -1:
                            carve_node.region(f"[EXTRACT:raw]linux_kernel_{img_count}.elf", cursor + idx, min(file_size - (cursor + idx), 50 * 1024 * 1024), color=hx.RED)
                            found_types.add("elf")
                            img_count += 1

                    # 8. Linux bzImage
                    if "bzimage" not in found_types:
                        idx = chunk.find(b"HdrS")
                        if idx != -1 and idx >= 0x202:
                            carve_node.region(f"[EXTRACT:raw]linux_bzImage_{img_count}.bin", cursor + idx - 0x202, min(file_size - (cursor + idx - 0x202), 30 * 1024 * 1024), color=hx.RED)
                            found_types.add("bzimage")
                            img_count += 1

                    if len(found_types) >= 8:
                        break

                    cursor += chunk_size

                if img_count == 0:
                    carve_node.seek(data_foa)
                    carve_node.region(f"[EXTRACT:raw]raw_vmdk_payload.bin", data_foa, file_size - data_foa, color=hx.GRAY)

    if gd_foa < file_size and gd_foa > 0:
        root.region("Grain Directory (L1 Translation Table)", gd_foa, min(file_size - gd_foa, 4096), color=hx.PURPLE)

hx.register("VMDK", detect, parse)

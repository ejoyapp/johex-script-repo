"""
JoHex Official Script: Linux Kernel (bzImage) Parser
====================================================
A forensic parser for Linux Kernel images (x86/x86_64 bzImage).
Parses the boot protocol headers, isolates the decompressor stub, and 
locates the embedded compressed payload (GZIP, XZ, ZSTD, etc.) for extraction.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.linux_kernel"
__name__        = "Linux Kernel Parser"
__version__     = "1.0.0"
__author__      = "EJoyApp Team"
__category__    = "Firmware & System"
__description__ = '''
    "A structural parser for Linux Kernel images (bzImage). "
    "Parses the real-mode setup header and automatically locates "
    "the embedded compressed payload (GZIP/XZ/LZMA/ZSTD) for extraction."
'''
__features__    = '''
    "• Linux Boot Protocol header parsing (HdrS)"
    "• Real-mode setup and Protected-mode isolation"
    "• Automated extraction for embedded compressed payloads"
    "• Heuristic fallback scanning for older kernel versions"
'''
__formats__     = ".bzImage, vmlinuz, .bin"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

MAGIC_BYTES = b"HdrS"
SUPPORTED_EXTS = ["bzimage", "vmlinuz"]
FORMAT_NAME = "Linux Kernel (bzImage)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. Standard x86/x86_64 bzImage magic 'HdrS' is at offset 0x0202
    if len(hex_prefix) >= 0x0206:
        if hex_prefix[0x0202:0x0206] == MAGIC_BYTES:
            return 100
            
    # 2. Check for pure compressed payloads often named as vmlinuz
    # GZIP (\x1F\x8B\x08), XZ (\xFD\x37\x7A\x58\x5A\x00), ZSTD (\x28\xB5\x2F\xFD)
    if hex_prefix.startswith(b"\x1F\x8B\x08") or hex_prefix.startswith(b"\xFD\x37\x7A\x58") or hex_prefix.startswith(b"\x28\xB5\x2F\xFD"):
        if file_ext.lower().replace('.', '') in SUPPORTED_EXTS:
            return 90 # High certainty if extension matches
            
    return 0

def detect(r):
    if r.size < 0x206:
        return False
    # Check for 'HdrS' magic
    return r.read(0x0202, 4) == b'HdrS'

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse Real-mode Setup Header (Boot Sector & Setup)
    # =========================================================
    # According to Linux Boot Protocol:
    # setup_sects is at 0x01F1. If it's 0, it defaults to 4.
    setup_sects = r.u8(0x01F1)
    if setup_sects == 0: 
        setup_sects = 4
        
    # The real-mode code consists of the boot sector (512 bytes) plus setup_sects * 512
    setup_size = (setup_sects + 1) * 512

    with root.struct("Real-Mode Code (Boot Sector & Setup)", color=hx.BLUE) as setup:
        setup.region("Legacy Boot Sector Code", 0, 0x01F1, color=hx.GRAY)
        
        setup.seek(0x01F1)
        setup.u8("Setup Sectors", color=hx.YELLOW, fmt=lambda v: f"{v} sectors" if v != 0 else "0 (Defaults to 4)")
        setup.u16("Root Flags")
        setup.u32("SysSize (16-byte paras)")
        setup.u16("RAM Disk Image (Offset)")
        setup.u16("RAM Disk Size")
        setup.u16("Video Mode")
        setup.u16("Root Device")
        setup.u16("Boot Flag (0xAA55)")
        
        setup.seek(0x0202)
        setup.bytes("Magic Signature", 4, color=hx.YELLOW, fmt=lambda v: v.decode('ascii') + " (Valid bzImage)")
        version = setup.u16("Protocol Version", color=hx.CYAN, fmt=lambda v: f"0x{v:04X} ({v>>8}.{v&0xFF})")
        
        setup.u32("Real-mode Switch")
        setup.u16("Start SYS_SEG")
        setup.u16("Kernel Version Offset")
        
        # In Protocol 2.08+, payload offset and length are explicitly provided!
        payload_offset = 0
        payload_length = 0
        
        if version >= 0x0208:
            setup.seek(0x0248)
            payload_offset = setup.u32("Payload Offset", color=hx.YELLOW)
            payload_length = setup.u32("Payload Length")
            
        # Jump over the rest of the setup sectors
        setup.region("Remaining Setup Data", setup.tell(), setup_size - setup.tell(), color=hx.GRAY)

    # =========================================================
    # 2. Map Protected-Mode Kernel & Extract Payload
    # =========================================================
    pm_code_size = file_size - setup_size
    if pm_code_size > 0:
        with root.struct("Protected-Mode Kernel Code", color=hx.GREEN) as pm:
            
            abs_payload_start = 0
            abs_payload_size = 0
            
            # A. If the header gave us explicit coordinates (Modern Kernels)
            if payload_offset > 0 and payload_length > 0:
                abs_payload_start = setup_size + payload_offset
                abs_payload_size = payload_length
                
            # B. If older kernel or coordinates missing, fallback to Heuristic Carving
            else:
                pm.seek(setup_size)
                # Scan the first 5MB of Protected-Mode code for compression signatures
                scan_limit = min(file_size, setup_size + 5 * 1024 * 1024)
                chunk = r.read(setup_size, scan_limit - setup_size)
                
                sigs = {
                    b"\x1F\x8B\x08": ".gz",                 # GZIP
                    b"\xFD\x37\x7A\x58\x5A\x00": ".xz",     # XZ
                    b"\x28\xB5\x2F\xFD": ".zst",            # ZSTD
                    b"\x42\x5A\x68": ".bz2",                # BZIP2
                    b"\x5D\x00\x00": ".lzma"                # LZMA (heuristic)
                }
                
                best_idx = -1
                for sig in sigs.keys():
                    idx = chunk.find(sig)
                    if idx != -1:
                        if best_idx == -1 or idx < best_idx:
                            best_idx = idx
                            
                if best_idx != -1:
                    abs_payload_start = setup_size + best_idx
                    abs_payload_size = file_size - abs_payload_start # Assume it goes to EOF

            # C. Extract the payload and tag it for ArchiveBrowserDlg
            if abs_payload_start > 0:
                
                magic = r.read(abs_payload_start, 6)
                ext = ".bin"
                method = "raw"
                
                if magic.startswith(b"\x1F\x8B\x08"): 
                    ext = ".elf"
                    method = "gzip"
                elif magic.startswith(b"\xFD\x37\x7A\x58\x5A\x00"): 
                    ext = ".xz"
                elif magic.startswith(b"\x28\xB5\x2F\xFD"): 
                    ext = ".zst"
                
                extract_name = f"vmlinux_payload{ext}"
                
                if abs_payload_start > setup_size:
                    pm.region("Decompressor Stub (Assembly Code)", setup_size, abs_payload_start - setup_size, color=hx.GRAY)
                    
                pm.seek(abs_payload_start)
                pm.region(f"[EXTRACT:{method}]{extract_name}", abs_payload_start, abs_payload_size, color=hx.RED)
                
            else:
                # If no payload found, map the whole area
                pm.region("Unrecognized Kernel Code", setup_size, pm_code_size, color=hx.GRAY)

hx.register("LinuxKernel", detect, parse)
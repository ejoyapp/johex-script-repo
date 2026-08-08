"""
JoHex Official Script: Windows Imaging Format (WIM) Parser
==========================================================
A high-performance parser for modern Windows deployment images.
Provides deep visibility into the WIM header, decodes 56-bit resource flags,
and features one-click FOA routing to the Metadata XML and SHA-1 Lookup Tables.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.wim"
__name__        = "WIM Parser"
__version__     = "1.3.1"
__author__      = "EJoyApp Team"
__category__    = "Archive Parsers"
__description__ = '''
    "A high-performance parser for modern Windows deployment images. "
    "Provides deep visibility into the WIM header, decodes 56-bit resource flags, "
    "and features one-click FOA routing to the Metadata XML and SHA-1 Lookup Tables."
'''
__features__    = '''
    "• WIM Header parsing\n"
    "• 56-bit resource flags decoding\n"
    "• FOA routing to Metadata XML and SHA-1 Lookup Tables\n"
    "• LZMS/LZX/XPRESS compression detection"
'''
__formats__     = ".wim, .esd, .swm"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
# WIM files always start with the 8-byte signature "MSWIM\0\0\0"
MAGIC_BYTES = b"MSWIM\x00\x00\x00"
SUPPORTED_EXTS = [".wim", ".swm", ".esd"]
FORMAT_NAME = "Windows Imaging Format (WIM)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. Check for the 8-byte MSWIM signature.
    if len(hex_prefix) >= 8 and hex_prefix.startswith(MAGIC_BYTES):
        
        # 2. To ensure higher certainty, check the header size and WIM version.
        # Header size is at offset 0x08 (4 bytes), Version is at offset 0x0C (4 bytes).
        if len(hex_prefix) >= 16:
            # Use struct to unpack two little-endian 32-bit unsigned integers (<II).
            cbSize, dwVersion = struct.unpack_from("<II", hex_prefix, 8)
            
            # The standard WIM header size is usually 208 bytes (0x000000D0) 
            # and the typical version is 1.13 (0x00010D00).
            if cbSize == 208 and dwVersion == 0x00010D00:
                return 100  # 100% certainty that it is a standard WIM/ESD file
                
            # Magic bytes match exactly, but it has an unusual header size or newer version
            return 80
            
        # File is severely truncated and only contains the 8-byte signature
        return 50
        
    return 0

def detect(r):
    # WIM file header size is fixed at 208 bytes (0xD0)
    if r.size < 208:
        return False
    # WIM magic number: "MSWIM\0\0\0" (contains three \x00)
    return r.read(0, 8) == b'MSWIM\x00\x00\x00'

def parse(r, root):
    file_size = r.size

    # =========================================================
    # Helper parser: WIM's exclusive 24-byte physical resource pointer (WIM_RESHEAD_DISK)
    # Structure: Size (7 bytes) + Flags (1 byte) + Offset (8 bytes) + OrigSize (8 bytes)
    # =========================================================
    def parse_reshdr(node, name, offset):
        with node.struct(name, color=hx.PURPLE) as res:
            res.seek(offset)
            
            # Read the first 8 bytes and perform 56-bit disassembly
            raw_size_flags = r.u64(offset)
            res_size = raw_size_flags & 0x00FFFFFFFFFFFFFF
            res_flags = raw_size_flags >> 56
            
            # Use lambda to show the magical bitwise separation
            res.u64("Size & Flags", color=hx.YELLOW, 
                    fmt=lambda v, s=res_size, f=res_flags: f"Size: {s} bytes | Flags: 0x{f:02X}")
            
            # Extract Flags meaning (0x02=Metadata, 0x04=Compressed, 0x08=Spanned)
            is_compressed = (res_flags & 0x04) != 0
            
            # Extract absolute physical offset (FOA)
            foa = r.u64(offset + 8)
            
            # [Inject Hyperlink]: Instantly leap across GBs of system image, straight to the target physical table!
            res.u64("Offset (FOA)", color=hx.RED, target=foa if (0 < foa < file_size) else None,
                    fmt=lambda v, o=foa: f"0x{v:016X} -> [Double Click to Jump FOA: 0x{o:X}]")
            
            orig_size = r.u64(offset + 16)
            res.u64("Original Size", fmt=lambda v: f"{v} bytes")
            
        return foa, res_size, is_compressed

    # =========================================================
    # 1. Parse WIM Header (fixed 208 bytes)
    # =========================================================
    with root.struct("WIM Header (208 bytes)", color=hx.BLUE) as hdr:
        hdr.bytes("Signature", 8, color=hx.YELLOW, fmt=lambda v: "MSWIM")
        hdr.u32("Header Size", fmt=lambda v: f"{v} bytes")
        hdr.u32("Version", color=hx.CYAN, fmt=lambda v: "1.13 (Standard)" if v == 0x00010D00 else f"0x{v:08X}")
        
        # Core compression and attribute Flags
        flags = hdr.u32("Flags", color=hx.GREEN)
        is_lzx = (flags & 0x00040000) != 0
        is_xpress = (flags & 0x00020000) != 0
        is_lzms = (flags & 0x20000000) != 0 # ESD format
        
        comp_type = "None"
        if is_lzx: comp_type = "LZX (Standard)"
        elif is_xpress: comp_type = "XPRESS (Fast)"
        elif is_lzms: comp_type = "LZMS (Solid/ESD)"
        hdr.region(f"Compression Type: {comp_type}", hdr.tell() - 4, 4, color=hx.GREEN)

        hdr.u32("Chunk Size", color=hx.CYAN, fmt=lambda v: f"{v} bytes (0x{v:X})")
        hdr.bytes("WIM GUID", 16, fmt=lambda v: "{" + v.hex().upper() + "}")
        
        hdr.u16("Part Number")
        hdr.u16("Total Parts", fmt=lambda v: f"{v} (Spanned WIM)" if v > 1 else "1 (Single WIM)")
        hdr.u32("Image Count", color=hx.RED, fmt=lambda v: f"Contains {v} OS Images")

        # =========================================================
        # 2. Parse the four core physical pointers (WIM_RESHEAD_DISK)
        # =========================================================
        offset_table_foa, offset_table_size, _ = parse_reshdr(hdr, "Offset Table Pointer (Lookup Table)", 0x30)
        xml_data_foa, xml_data_size, xml_compressed = parse_reshdr(hdr, "XML Data Pointer (Image Metadata)", 0x48)
        boot_meta_foa, boot_meta_size, _ = parse_reshdr(hdr, "Boot Metadata Pointer", 0x60)
        
        hdr.seek(0x78)
        hdr.u32("Boot Index (Default Boot Image)", color=hx.YELLOW)
        
        integrity_foa, integrity_size, _ = parse_reshdr(hdr, "Integrity Table Pointer", 0x7C)
        
        hdr.seek(0x94)
        hdr.region("Unused / Padding", 0x94, 60, color=hx.GRAY)

    # =========================================================
    # 3. Mark the actual regions (using FOA extracted from the Header)
    # =========================================================
    
    # [File Body]: Blob data blocks, potentially up to several GBs
    first_block = 208
    last_block = min(offset_table_foa, xml_data_foa) if offset_table_foa > 0 else file_size
    if last_block > first_block:
        root.region("WIM Blobs & Streams (Compressed File Data)", first_block, last_block - first_block, color=hx.GRAY)

    # [Offset Table]: Deduplication table, recording the mapping of all files' SHA-1 to physical addresses
    if 0 < offset_table_foa < file_size and offset_table_size > 0:
        root.region("Lookup Table (Offset Table & SHA-1 Hashes)", offset_table_foa, offset_table_size, color=hx.CYAN)

    # [XML Data]: Extremely important WIM core intelligence repository
    if 0 < xml_data_foa < file_size and xml_data_size > 0:
        with root.struct("WIM XML Data (System Metadata)", color=hx.ORANGE) as xml_node:
            xml_node.seek(xml_data_foa)
            
            # WIM's XML is highly likely stored in plaintext UTF-16LE format
            if not xml_compressed:
                # Sniff and decode some XML text to display to the user
                preview_size = min(xml_data_size, 512)
                raw_text = r.read(xml_data_foa, preview_size)
                try:
                    dec_text = raw_text.decode('utf-16le', 'ignore').replace('\r', '').replace('\n', ' ')
                    xml_node.region(f"XML Preview: {dec_text[:100]}...", xml_data_foa, preview_size, color=hx.GREEN)
                except:
                    pass
                
                # Gray out the rest
                if xml_data_size > preview_size:
                    xml_node.region("Remaining XML Payload", xml_data_foa + preview_size, xml_data_size - preview_size, color=hx.GRAY)
            else:
                xml_node.region("Compressed XML Payload", xml_data_foa, xml_data_size, color=hx.GRAY)

    # [Integrity Table]: File checksum tail table
    if 0 < integrity_foa < file_size and integrity_size > 0:
        root.region("Integrity Table (Checksums)", integrity_foa, integrity_size, color=hx.PURPLE)

hx.register("WIM", detect, parse)
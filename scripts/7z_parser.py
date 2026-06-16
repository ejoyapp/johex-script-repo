# 7z_parser.py

"""
JoHex Official Script: 7-Zip Archive (7z) Parser
================================================
An advanced structural parser for the 7-Zip archive format.
Decodes the Signature Header and provides precise FOA routing to the Next Header, 
seamlessly isolating complex LZMA/LZMA2 compressed streams and encoded metadata properties.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.7z"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # The 7z file header must be at least 32 bytes
    if r.size < 32:
        return False
    # 7z fixed 6-byte magic number: 37 7A BC AF 27 1C
    sig = r.read(0, 6)
    return sig == b'37\x7A\xBC\xAF\x27\x1C' or sig == b'7z\xbc\xaf\x27\x1c'

def parse(r, root):
    # The physical base offset of the 7z file (all NextHeaderOffsets are calculated based on this value)
    BASE_OFFSET = 32
    file_size = r.size

    # =========================================================
    # 1. 7z Signature Header (fixed 32 bytes)
    # =========================================================
    with root.struct("7z Signature Header", color=hx.BLUE) as hdr:
        hdr.bytes("Signature", 6, color=hx.YELLOW, fmt=lambda v: "37 7A BC AF 27 1C ('7z')")
        
        # Archive version number
        hdr.u8("ArchiveVersion Major")
        hdr.u8("ArchiveVersion Minor")
        
        # CRC check for the 20 bytes of StartHeader below
        hdr.u32("StartHeader CRC", color=hx.RED, fmt=lambda v: f"0x{v:08X}")

        with hdr.struct("StartHeader", color=hx.GREEN) as sh:
            
            # [Addressing Core]: Peek ahead at the relative offset of the NextHeader
            rel_offset = r.u64(sh.tell())
            # The absolute physical offset of 7z = 32 + Relative Offset
            foa_offset = BASE_OFFSET + rel_offset
            
            # Inject target! Double-click this line, the cursor instantly leaps across GBs to the metadata area at the end of the file
            sh.u64("NextHeader Offset", color=hx.YELLOW, target=foa_offset if foa_offset < file_size else None,
                   fmt=lambda v, f=foa_offset: f"0x{v:016X} -> [FOA: 0x{f:X}]")
            
            next_size = sh.u64("NextHeader Size")
            sh.u32("NextHeader CRC", color=hx.RED, fmt=lambda v: f"0x{v:08X}")

    # =========================================================
    # 2. Packed Streams (Solid compressed data streams)
    # =========================================================
    # The area from 32 bytes to right before the NextHeader is the actual compressed file data
    if rel_offset > 0:
        root.region("Packed Data Streams (Solid Compressed Block)", BASE_OFFSET, rel_offset, color=hx.GRAY)

    # =========================================================
    # 3. Next Header (Metadata / Directory area)
    # =========================================================
    if next_size > 0 and foa_offset < file_size:
        
        # Try to probe the first byte of NextHeader (Property ID)
        # 0x17 (kEncodedHeader) means the following metadata is entirely compressed
        # 0x01 (kHeader) means the metadata is plaintext (extremely rare)
        tag_byte = r.u8(foa_offset)
        
        if tag_byte == 0x17:
            # Metadata is compressed, static analysis stops here, marking the boundary
            root.region(f"Encoded Header (kEncodedHeader 0x17) [LZMA Compressed]", foa_offset, next_size, color=hx.PURPLE)
        
        elif tag_byte == 0x01:
            # Plaintext Header with an extremely low probability of appearance
            with root.struct("Header (kHeader 0x01)", color=hx.PURPLE) as meta:
                # Force a jump to render
                meta.seek(foa_offset)
                meta.u8("Property ID: kHeader", color=hx.RED, fmt=lambda v: "0x01")
                # Subsequent parsing requires writing an extremely complex variable-length integer decoder (7z Variable-Length Int)
                # For stability here, treat the remaining part as a Region
                meta.region("Header Payload (Variable-Length Encoded)", meta.tell(), next_size - 1, color=hx.ORANGE)
        else:
            # Unknown identifier
            root.region(f"Unknown Metadata Block (ID: 0x{tag_byte:02X})", foa_offset, next_size, color=hx.PURPLE)

hx.register("7z", detect, parse)
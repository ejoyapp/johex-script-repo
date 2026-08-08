"""
JoHex Official Script: Portable Network Graphics (PNG) Parser
=============================================================
A chunk-based parser for the lossless PNG image format.
Validates the magic signature and iterates through all critical and ancillary chunks 
(IHDR, tEXt, IDAT, IEND) while visually isolating the Deflate-compressed image data.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.png"
__name__        = "PNG Parser"
__version__     = "1.3.1"
__author__      = "EJoyApp Team"
__category__    = "Media Parsers"
__description__ = '''
    "A chunk-based parser for the lossless PNG image format. Validates the "
    "magic signature and iterates through all critical and ancillary chunks "
    "(IHDR, tEXt, IDAT, IEND) while visually isolating the Deflate-compressed image data."
'''
__features__    = '''
    "• Magic signature validation\n"
    "• Critical and ancillary chunks (IHDR, tEXt, IDAT, IEND) iteration\n"
    "• Deflate-compressed image data isolation"
'''
__formats__     = ".png"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
# The PNG signature is exactly 8 bytes long, designed to detect transmission errors
MAGIC_BYTES = b"\x89PNG\r\n\x1a\n"
SUPPORTED_EXTS = [".png"]
FORMAT_NAME = "Portable Network Graphics (PNG)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. A standard PNG file always begins with an 8-byte signature.
    if len(hex_prefix) >= 8 and hex_prefix.startswith(MAGIC_BYTES):
        
        # 2. Immediately following the signature is the first chunk, 
        # which must be the Image Header (IHDR) chunk.
        # A chunk header consists of a 4-byte length followed by a 4-byte chunk type.
        # Therefore, the chunk type string starts at offset 12 (8-byte sig + 4-byte length).
        if len(hex_prefix) >= 16:
            chunk_type = hex_prefix[12:16]
            
            if chunk_type == b"IHDR":
                return 100  # 100% certainty that it is a standard PNG file
                
            # Magic bytes match, but the first chunk is not IHDR (corrupted or non-standard PNG)
            return 80
            
        # Magic bytes match exactly, but the file is severely truncated (no chunks present)
        return 50
        
    return 0

def detect(r):
    if r.size < 8:
        return False
    # PNG fixed 8-byte magic number: 89 50 4E 47 0D 0A 1A 0A
    # Note: Use le=False to read in big-endian order
    sig1 = r.u32(0, le=False)
    sig2 = r.u32(4, le=False)
    return sig1 == 0x89504E47 and sig2 == 0x0D0A1A0A

def parse(r, root):
    # =========================================================
    # 1. Verify and parse PNG magic number (Signature)
    # =========================================================
    root.bytes("PNG Signature", 8, color=hx.BLUE, fmt=lambda v: "89 50 4E 47 0D 0A 1A 0A")
    
    cursor = 8
    file_size = r.size

    # =========================================================
    # 2. Iterate through all Chunks (Data blocks)
    # =========================================================
    # A Chunk is at least 12 bytes (Length:4 + Type:4 + CRC:4)
    while cursor <= file_size - 12: 
        root.seek(cursor)
        
        # Read length and type in advance using Reader to dynamically name the UI node
        length = r.u32(cursor, le=False)
        chunk_type_bytes = r.read(cursor + 4, 4)
        chunk_type = chunk_type_bytes.decode('ascii', 'ignore')

        with root.struct(f"Chunk: {chunk_type}", color=hx.PURPLE) as chunk:
            # 1. Chunk Length (Big Endian)
            chunk.u32("Length", le=False, color=hx.YELLOW)
            
            # 2. Chunk Type (4-byte ASCII characters)
            chunk.bytes("Type", 4, color=hx.CYAN, fmt=lambda v: v.decode('ascii', 'ignore'))

            # 3. Chunk Data (Data area)
            if length > 0:
                data_start = chunk.tell()
                
                # [Deep Parse]: If it is IHDR (Image Header Block), expand its specific attributes
                if chunk_type == "IHDR" and length == 13:
                    with chunk.struct("IHDR Data", color=hx.GREEN) as ihdr:
                        ihdr.u32("Width", le=False)
                        ihdr.u32("Height", le=False)
                        ihdr.u8("Bit Depth")
                        
                        # Color type enumeration mapping
                        color_fmt = lambda v: f"{v} " + {
                            0: "(Grayscale)", 2: "(Truecolor)", 3: "(Indexed-color)",
                            4: "(Grayscale with alpha)", 6: "(Truecolor with alpha)"
                        }.get(v, "(Unknown)")
                        ihdr.u8("Color Type", fmt=color_fmt)
                        
                        ihdr.u8("Compression Method", fmt=lambda v: f"{v} (Deflate)" if v == 0 else str(v))
                        ihdr.u8("Filter Method", fmt=lambda v: f"{v} (Adaptive)" if v == 0 else str(v))
                        ihdr.u8("Interlace Method", fmt=lambda v: "1 (Adam7)" if v == 1 else "0 (No Interlace)")
                
                # Other blocks (such as IDAT image data, PLTE palette) are temporarily treated as opaque Regions
                else:
                    chunk.region(f"{chunk_type} Data", data_start, length, color=hx.GRAY)
                    chunk.seek(data_start + length)

            # 4. Chunk CRC (Big Endian Cyclic Redundancy Check code)
            chunk.u32("CRC-32", le=False, color=hx.RED, fmt=lambda v: f"0x{v:08X}")

        # Cursor step: Length(4) + Type(4) + Data(length) + CRC(4)
        cursor += 8 + length + 4

        # IEND is the absolute endpoint defined by the PNG format
        if chunk_type == "IEND":
            break

hx.register("PNG", detect, parse)
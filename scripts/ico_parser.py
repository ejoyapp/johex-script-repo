# icon_parser.py

"""
JoHex Official Script: Windows Icon (ICO) Parser
================================================
A precise parser for the Windows Icon resource format.
Decodes the global ICONDIR header and provides one-click FOA routing from 
directory entries directly to the embedded BMP or PNG image payloads.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.ico"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
MAGIC_BYTES = b"\x00\x00\x01\x00"
SUPPORTED_EXTS = [".ico"]
FORMAT_NAME = "Windows Icon (ICO)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. An ICO file always starts with a 6-byte ICONDIR header:
    # idReserved (2 bytes, must be 0) + idType (2 bytes, must be 1 for ICO).
    # Thus, the magic signature is exactly \x00\x00\x01\x00.
    if len(hex_prefix) >= 6 and hex_prefix.startswith(MAGIC_BYTES):
        
        # 2. Read idCount (number of images in the file) at offset 0x04.
        # Use struct to unpack as a little-endian 16-bit unsigned integer (<H).
        idCount = struct.unpack_from("<H", hex_prefix, 4)[0]
        
        # A valid ICO file must contain at least one image
        if idCount > 0:
            
            # 3. The ICONDIR header is immediately followed by ICONDIRENTRY structures.
            # Each entry is 16 bytes long. To validate, we ensure the file is at least 
            # large enough to hold the 6-byte header and the first 16-byte entry (22 bytes).
            if len(hex_prefix) >= 22:
                return 100  # 100% certainty that it is a standard ICO file
                
            # Magic bytes match and image count is valid, but the file is highly truncated
            return 80
            
        # Magic bytes match, but it declares 0 images (corrupted or invalid ICO)
        return 20
        
    return 0

def detect(r):
    if r.size < 6:
        return False
    # ICON/CUR header features: Reserved(0), Type(1 for ICO, 2 for CUR)
    res = r.u16(0)
    typ = r.u16(2)
    return res == 0 and typ in (1, 2)

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse ICONDIR (Global Header)
    # =========================================================
    with root.struct("ICON Header (ICONDIR)", color=hx.BLUE) as hdr:
        hdr.u16("Reserved", fmt=lambda v: "0 (Valid)" if v == 0 else str(v))
        
        # Extract type to determine subsequent parsing strategy
        id_type = hdr.u16("Type", color=hx.YELLOW, fmt=lambda v: "1 (ICO Icon)" if v == 1 else "2 (CUR Cursor)" if v == 2 else str(v))
        id_count = hdr.u16("Image Count", color=hx.RED)

    # =========================================================
    # 2. Parse ICONDIRENTRY (Image Directory Entry) and inject FOA hyperlink
    # =========================================================
    entries = []
    
    if id_count > 0:
        with root.struct(f"Image Directory Entries ({id_count} items)", color=hx.CYAN) as dirs:
            for i in range(id_count):
                with dirs.struct(f"Entry [{i}]", color=hx.GREEN) as entry:
                    # Width/Height handling: 0 represents 256 pixels
                    w = entry.u8("Width", fmt=lambda v: "256 px (0)" if v == 0 else f"{v} px")
                    h = entry.u8("Height", fmt=lambda v: "256 px (0)" if v == 0 else f"{v} px")
                    
                    entry.u8("Color Count", fmt=lambda v: "No Palette (0)" if v == 0 else str(v))
                    entry.u8("Reserved")
                    
                    # Dual-state structure: ICO stores color parameters, CUR stores cursor hotspots
                    if id_type == 1:
                        entry.u16("Color Planes")
                        entry.u16("Bits Per Pixel")
                    else:
                        entry.u16("X Hotspot")
                        entry.u16("Y Hotspot")
                        
                    data_size = entry.u32("Size of Image Data")
                    
                    # Peek ahead at FOA physical offset
                    offset_val = r.u32(entry.tell())
                    
                    # [Inject Hyperlink]: Double-click this line, the cursor instantly jumps to the actual image block at the end of the file
                    entry.u32("Image Offset (FOA)", color=hx.YELLOW, target=offset_val if offset_val > 0 else None,
                              fmt=lambda v, o=offset_val: f"0x{v:08X} -> [Double Click to Jump FOA: 0x{o:X}]")
                              
                    entries.append({"offset": offset_val, "size": data_size, "idx": i})

    # =========================================================
    # 3. Parse the actual Image Data (DIB or PNG)
    # =========================================================
    for ent in entries:
        off = ent["offset"]
        size = ent["size"]
        i = ent["idx"]
        
        if off == 0 or size == 0 or off >= file_size:
            continue
            
        # Probe: Read the first 4 bytes of this block to determine the image format
        # PNG uses big-endian magic numbers, if it's 89 50 4E 47 then it's PNG
        magic = r.u32(off, le=False)
        
        if magic == 0x89504E47:
            # This is a modern PNG compressed icon (Vista+)
            root.region(f"Image [{i}] Data (Modern PNG)", off, size, color=hx.PURPLE)
            
        else:
            # This is a classic DIB (Device Independent Bitmap) block
            # Note: DIB in ICON does not have the 14-byte BITMAPFILEHEADER, it starts directly from BITMAPINFOHEADER
            with root.struct(f"Image [{i}] Data (Classic DIB)", color=hx.ORANGE) as dib:
                dib.seek(off)
                
                # Read the size of the DIB structure header (usually 40 bytes)
                dib_hdr_size = dib.u32("DIB Header Size", color=hx.YELLOW)
                
                if dib_hdr_size == 40:
                    dib.u32("Width")
                    # DIB height in ICO is doubled (contains both the XOR mask and AND mask of the image)
                    dib.u32("Height (XOR + AND Mask)", fmt=lambda v: f"{v} (Real Image Height = {v//2})")
                    dib.u16("Color Planes", fmt=lambda v: "1 (Must be 1)" if v == 1 else str(v))
                    dib.u16("Bits Per Pixel")
                    dib.u32("Compression Method", fmt=lambda v: "0 (BI_RGB)" if v == 0 else str(v))
                    dib.u32("Image Size")
                    dib.u32("X Pixels Per Meter")
                    dib.u32("Y Pixels Per Meter")
                    dib.u32("Colors Used")
                    dib.u32("Colors Important")
                    
                    # The remaining part is the actual pixel array and palette, gray it out
                    rem = size - 40
                    if rem > 0:
                        dib.region("Pixel Array & Palette & Mask", dib.tell(), rem, color=hx.GRAY)
                else:
                    # Handle other uncommon versions of DIB Header (V4/V5)
                    rem = size - 4
                    if rem > 0:
                        dib.region("DIB Body & Pixels", dib.tell(), rem, color=hx.GRAY)

hx.register("ICON", detect, parse)
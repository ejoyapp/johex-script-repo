# bmp_parser.py

"""
JoHex Official Script: Windows Bitmap (BMP) Parser
==================================================
A structural parser for the uncompressed Windows Bitmap image format.
Extracts the BITMAPFILEHEADER and BITMAPINFOHEADER, and maps exact physical 
offsets to the color palette and the raw pixel data array.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.bmp"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # BMP file header must be at least 14 bytes
    if r.size < 14:
        return False
    # Classic Windows BMP magic number: 42 4D ('BM')
    return r.read(0, 2) == b'BM'

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. BITMAPFILEHEADER (Fixed 14 bytes)
    # =========================================================
    with root.struct("BITMAPFILEHEADER", color=hx.BLUE) as bfh:
        bfh.bytes("bfType (Signature)", 2, color=hx.YELLOW, fmt=lambda v: "42 4D ('BM')")
        bfh.u32("bfSize (File Size)")
        bfh.u16("bfReserved1", fmt=lambda v: "0 (Valid)" if v == 0 else str(v))
        bfh.u16("bfReserved2", fmt=lambda v: "0 (Valid)" if v == 0 else str(v))
        
        # Extract absolute FOA offset in advance to prepare for the hyperlink
        pixel_offset = r.u32(bfh.tell())
        
        # [Inject Hyperlink]: Double-click here to instantly jump over potentially huge color palettes straight to the pure pixel data area!
        bfh.u32("bfOffBits (Pixel Data Offset)", color=hx.RED, target=pixel_offset if pixel_offset < file_size else None,
                fmt=lambda v, o=pixel_offset: f"0x{v:08X} -> [Double Click to Jump FOA: 0x{o:X}]")

    # =========================================================
    # 2. DIB Header / BITMAPINFOHEADER (Variable length)
    # =========================================================
    # The first item of the DIB header is always its own size, used to determine the version
    dib_size = r.u32(14)
    dib_end = 14 + dib_size
    
    # Infer DIB version based on size
    dib_version = "Unknown"
    if dib_size == 12: dib_version = "BITMAPCOREHEADER (OS/2)"
    elif dib_size == 40: dib_version = "BITMAPINFOHEADER (Windows NT)"
    elif dib_size == 52: dib_version = "BITMAPV2INFOHEADER"
    elif dib_size == 56: dib_version = "BITMAPV3INFOHEADER"
    elif dib_size == 108: dib_version = "BITMAPV4HEADER"
    elif dib_size == 124: dib_version = "BITMAPV5HEADER"

    with root.struct(f"DIB Header [{dib_version}]", color=hx.CYAN) as dib:
        dib.u32("biSize (Header Size)", color=hx.YELLOW)

        # Most modern BMPs contain at least 40 bytes of core information
        if dib_size >= 40:
            dib.u32("biWidth (Image Width)")
            
            # [BMP specific height pitfall]: If the height is negative, the image is stored Top-Down
            # If the height is positive, the image is stored Bottom-Up (classic behavior)
            # Use a small uint to int conversion trick in the lambda for evaluation
            dib.u32("biHeight (Image Height)", color=hx.GREEN, 
                    fmt=lambda v: f"{v - 0x100000000} (Top-Down)" if v > 0x7FFFFFFF else f"{v} (Bottom-Up)")
            
            dib.u16("biPlanes", fmt=lambda v: "1 (Must be 1)" if v == 1 else str(v))
            dib.u16("biBitCount (Color Depth)", color=hx.YELLOW, fmt=lambda v: f"{v}-bit")
            
            comp_fmt = lambda v: {
                0: "0 (BI_RGB - Uncompressed)",
                1: "1 (BI_RLE8)",
                2: "2 (BI_RLE4)",
                3: "3 (BI_BITFIELDS)",
                4: "4 (BI_JPEG)",
                5: "5 (BI_PNG)",
                6: "6 (BI_ALPHABITFIELDS)"
            }.get(v, f"{v} (Unknown)")
            dib.u32("biCompression", fmt=comp_fmt)
            
            dib.u32("biSizeImage", fmt=lambda v: f"{v} bytes" if v > 0 else "0 (Dummy for BI_RGB)")
            dib.u32("biXPelsPerMeter")
            dib.u32("biYPelsPerMeter")
            dib.u32("biClrUsed", fmt=lambda v: "0 (Use max available)" if v == 0 else str(v))
            dib.u32("biClrImportant", fmt=lambda v: "0 (All are important)" if v == 0 else str(v))
            
            # If it is V4/V5 or other headers containing more fields, gray out the remaining parts
            rem_dib = dib_end - dib.tell()
            if rem_dib > 0:
                dib.region("Extended DIB Fields (Color Space / Gamma etc.)", dib.tell(), rem_dib, color=hx.GRAY)
                dib.seek(dib_end)
                
        elif dib_size == 12:
            # Ancient OS/2 format, fields are 16-bit
            dib.u16("bcWidth")
            dib.u16("bcHeight")
            dib.u16("bcPlanes")
            dib.u16("bcBitCount")
        else:
            # Unknown DIB structure, safely grayed out
            dib.region("Unknown DIB Body", dib.tell(), dib_size - 4, color=hx.GRAY)
            dib.seek(dib_end)

    # =========================================================
    # 3. Color Table (Palette) & Bitfields Mask
    # =========================================================
    # The area between the end of the DIB Header and the start of the actual pixel data is the color palette or bitfields mask
    gap_size = pixel_offset - dib_end
    if gap_size > 0:
        root.region("Color Table (Palette) / Bitfields Mask", dib_end, gap_size, color=hx.ORANGE)

    # =========================================================
    # 4. Pixel Array (Actual Pixel Array)
    # =========================================================
    if pixel_offset > 0 and pixel_offset < file_size:
        pixel_size = file_size - pixel_offset
        root.region("Pixel Array (Raw Image Data)", pixel_offset, pixel_size, color=hx.PURPLE)

hx.register("BMP", detect, parse)
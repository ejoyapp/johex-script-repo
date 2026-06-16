# jpg_parser.py

"""
JoHex Official Script: Joint Photographic Experts Group (JPEG) Parser
=====================================================================
A marker-based parser for the JPEG image format.
Traverses the segment chain to visually isolate APPn metadata (including EXIF), 
quantization tables (DQT), and the compressed entropy-coded image stream (SOS).

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.jpg"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # Classic magic number for JPG: FF D8 (Start of Image)
    if r.size < 2:
        return False
    return r.u16(0, le=False) == 0xFFD8

def parse(r, root):
    file_size = r.size
    cursor = 0

    # Predefine the core JPG marker dictionary for UI-friendly display
    MARKERS = {
        0xFFD8: "SOI (Start of Image)",
        0xFFE0: "APP0 (JFIF Header)",
        0xFFE1: "APP1 (Exif / XMP)",
        0xFFE2: "APP2 (ICC Profile)",
        0xFFDB: "DQT (Quantization Table)",
        0xFFC0: "SOF0 (Baseline DCT)",
        0xFFC2: "SOF2 (Progressive DCT)",
        0xFFC4: "DHT (Huffman Table)",
        0xFFDA: "SOS (Start of Scan)",
        0xFFD9: "EOI (End of Image)",
        0xFFFE: "COM (Comment)",
    }

    while cursor < file_size - 1:
        # Read 2-byte Marker (Big Endian)
        marker = r.u16(cursor, le=False)

        # Fault tolerance: If it doesn't align to FF, parsing is misaligned or entered a garbage data area
        if marker >> 8 != 0xFF:
            root.region("Out of Sync / Unknown Data", cursor, file_size - cursor, color=hx.GRAY)
            break

        # Smart matching of Marker names
        marker_name = MARKERS.get(marker)
        if not marker_name:
            if 0xFFE0 <= marker <= 0xFFEF:
                marker_name = f"APP{marker & 0x0F} (Application Data)"
            else:
                marker_name = f"Unknown Marker (0x{marker:04X})"

        # =========================================================
        # 1. Process Standalone Markers - No Length field
        # =========================================================
        if marker == 0xFFD8:  # SOI
            root.bytes(marker_name, 2, color=hx.BLUE, fmt=lambda v: "FF D8")
            cursor += 2
            continue
        elif marker == 0xFFD9:  # EOI
            root.bytes(marker_name, 2, color=hx.ORANGE, fmt=lambda v: "FF D9")
            break
        elif 0xFFD0 <= marker <= 0xFFD7:  # RSTn (Restart Markers)
            root.bytes(f"RST{marker & 0x07} (Restart Marker)", 2, color=hx.GRAY)
            cursor += 2
            continue

        # =========================================================
        # 2. Process regular marker segments (Segments with Length)
        # =========================================================
        # The length field is 2-byte big-endian, and this length *includes* the 2 bytes of the length field itself!
        length = r.u16(cursor + 2, le=False)

        with root.struct(marker_name, color=hx.PURPLE) as node:
            node.seek(cursor)
            node.u16("Marker", le=False, color=hx.YELLOW, fmt=lambda v: f"0x{v:04X}")
            node.u16("Length", le=False, color=hx.CYAN)

            payload_len = length - 2
            if payload_len > 0:
                # --- Deep Parse A: SOF (Image physical resolution) ---
                if marker in (0xFFC0, 0xFFC2):
                    node.u8("Precision (Bit Depth)")
                    node.u16("Image Height", le=False, color=hx.GREEN)
                    node.u16("Image Width", le=False, color=hx.GREEN)
                    node.u8("Number of Components")
                    rem = payload_len - 6
                    if rem > 0:
                        node.region("Component Details", node.tell(), rem, color=hx.GRAY)
                
                # --- Deep Parse B: APP0 (JFIF standard header) ---
                elif marker == 0xFFE0:
                    node.bytes("Identifier", 5, color=hx.CYAN, fmt=lambda v: v.decode('ascii', 'ignore').strip('\x00'))
                    node.u16("Version", le=False, fmt=lambda v: f"{v >> 8}.{v & 0xFF:02d}")
                    node.u8("Density Units", fmt=lambda v: "0 (No units)" if v==0 else "1 (Pixels/inch)" if v==1 else "2 (Pixels/cm)")
                    node.u16("X Density", le=False)
                    node.u16("Y Density", le=False)
                    node.u8("X Thumbnail")
                    node.u8("Y Thumbnail")
                    rem = payload_len - 14
                    if rem > 0:
                        node.region("Thumbnail RGB Data", node.tell(), rem, color=hx.GRAY)
                
                # --- Other segments treated as gray regions ---
                else:
                    node.region(f"{marker_name} Payload", node.tell(), payload_len, color=hx.GRAY)

            cursor += 2 + length

        # =========================================================
        # 3. Special handling: Compressed image data after SOS (Start of Scan)
        # =========================================================
        if marker == 0xFFDA:
            # The Length of SOS only refers to the size of the SOS Header.
            # The actual compressed image data (Entropy Coded Data) follows immediately, and has no length identifier!
            scan_start = cursor
            scan_cursor = scan_start
            
            # Brute-force scan forward until the next valid Marker is encountered
            while scan_cursor < file_size - 1:
                b1 = r.u8(scan_cursor)
                if b1 == 0xFF:
                    b2 = r.u8(scan_cursor + 1)
                    # JPG Spec: If FF actually appears in the image data, it must be written as FF 00 (this is called Byte Stuffing)
                    # FF D0 ~ FF D7 are RST restart markers, which are also part of the scan data
                    if b2 != 0x00 and not (0xD0 <= b2 <= 0xD7):
                        # Encountered a brand new Marker (e.g., FF D9 EOI), break out of the scan
                        break
                scan_cursor += 1
            
            scan_len = scan_cursor - scan_start
            if scan_len > 0:
                root.region("Entropy Coded Data (Raw Image Stream)", scan_start, scan_len, color=hx.GREEN)
            
            cursor = scan_cursor

hx.register("JPG", detect, parse)
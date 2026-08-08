"""
JoHex Official Script: MPEG-4 Part 14 (MP4 / ISOBMFF) Parser
============================================================
A hierarchical parser for the MP4 multimedia container.
Recursively unwraps the Box/Atom architecture, providing deep visibility into 
the 'moov' metadata tree and instantly isolating the massive 'mdat' media payload.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.mp4"
__name__        = "MP4 Parser"
__version__     = "1.0.0"
__author__      = "EJoyApp Team"
__category__    = "Media Parsers"
__description__ = (
    "A hierarchical parser for the MP4 multimedia container. "
    "Recursively unwraps the Box/Atom architecture, providing deep visibility into "
    "the 'moov' metadata tree and instantly isolating the massive 'mdat' media payload."
)
__features__    = (
    "• Recursive Box/Atom architecture unwrapping\n"
    "• Deep visibility into the 'moov' metadata tree\n"
    "• 'mdat' media payload isolation"
)
__formats__     = ".mp4, .m4a, .m4v, .mov"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
# The true identifier is the 'ftyp' box type located at offset 4
MAGIC_BYTES = b"ftyp"
SUPPORTED_EXTS = [".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".heic", ".avif"]
FORMAT_NAME = "ISO Base Media File Format (MP4/MOV)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. An MP4 file consists of a sequence of boxes (or atoms).
    # It typically starts with an 'ftyp' (File Type) box.
    # We need at least 12 bytes to read the size, type, and major brand.
    if len(hex_prefix) >= 12:
        
        # 2. Check the box type at offset 4.
        box_type = hex_prefix[4:8]
        
        if box_type == MAGIC_BYTES:
            
            # 3. Read the box size at offset 0.
            # Use struct to unpack as a big-endian 32-bit unsigned integer (>I).
            box_size = struct.unpack_from(">I", hex_prefix, 0)[0]
            
            # A valid 'ftyp' box must be at least 8 bytes (size + type), 
            # but usually includes a major brand and minor version (>= 16 bytes total).
            if box_size >= 8:
                
                # 4. Check the major brand at offset 8 to confirm the specific format.
                major_brand = hex_prefix[8:12]
                
                # Common ISOBMFF major brands (Standard MP4, QuickTime, Apple Audio/Video, etc.)
                known_brands = [
                    b"isom", b"mp41", b"mp42", b"m4a ", 
                    b"m4v ", b"qt  ", b"dash", b"avc1", 
                    b"heic", b"avif", b"3gp4"
                ]
                
                if major_brand in known_brands:
                    return 100  # 100% certainty that it is a recognized MP4/ISOBMFF file
                    
                # It has a valid 'ftyp' box structure, but an uncommon or proprietary brand
                return 80
                
        # 5. Fallback check:
        # Very rarely, or in older/fragmented files, it might start directly 
        # with a 'moov' (Movie) or 'mdat' (Media Data) box instead of 'ftyp'.
        elif box_type in (b"moov", b"mdat"):
            return 60
            
    return 0

def detect(r):
    # The first 8 bytes of an MP4 file are usually: 00 00 00 XX 66 74 79 70 (ftyp)
    if r.size < 8:
        return False
    # Read the 4-byte Box type, the first one is usually 'ftyp'
    return r.read(4, 4) == b'ftyp'

def parse(r, root):
    file_size = r.size

    # The officially defined list of "Container Boxes". When encountering these, we must recursively drill down to parse child boxes.
    CONTAINERS = [b'moov', b'trak', b'mdia', b'minf', b'stbl', b'edts', b'dinf', b'mvex', b'moof', b'traf']

    # =========================================================
    # Core Recursive Parsing Engine
    # =========================================================
    def parse_boxes(node, start_offset, end_offset):
        cursor = start_offset
        while cursor < end_offset:
            if cursor + 8 > end_offset:
                break

            # 1. Base header: 4-byte size + 4-byte type (Big Endian)
            box_size = r.u32(cursor, le=False)
            box_type = r.read(cursor + 4, 4)
            header_size = 8
            
            # 2. Extremely critical boundary handling
            if box_size == 1:
                # If length is 1, 32 bits are insufficient, 64-bit Extended Size is enabled
                if cursor + 16 > end_offset: break
                box_size = r.u64(cursor + 8, le=False)
                header_size = 16
            elif box_size == 0:
                # If length is 0, the Box extends to the very end of the file (usually mdat)
                box_size = file_size - cursor
            
            if box_size < header_size:
                break # Prevent infinite loops caused by maliciously constructed files

            box_end = cursor + box_size
            box_type_str = box_type.decode('ascii', 'ignore')

            # 3. Construct the UI tree node
            with node.struct(f"Box: '{box_type_str}'", color=hx.PURPLE) as box_node:
                box_node.seek(cursor)
                
                if header_size == 8:
                    box_node.u32("Size", le=False, color=hx.YELLOW)
                else:
                    box_node.u32("Size (Trigger)", le=False, color=hx.YELLOW, fmt=lambda v: "1 (Extended Enabled)")
                    
                box_node.bytes("Type", 4, color=hx.CYAN, fmt=lambda v: box_type_str)
                
                if header_size == 16:
                    box_node.u64("Extended Size", le=False, color=hx.YELLOW)

                payload_start = cursor + header_size
                payload_size = box_size - header_size

                if payload_size > 0:
                    
                    # =======================================================
                    # Branch 1: If it's a container Box, dive in recursively!
                    # =======================================================
                    if box_type in CONTAINERS:
                        parse_boxes(box_node, payload_start, box_end)
                    
                    # =======================================================
                    # Branch 2: Deep parsing of specific characteristic Boxes
                    # =======================================================
                    elif box_type == b'ftyp':
                        box_node.bytes("Major Brand", 4, color=hx.GREEN, fmt=lambda v: v.decode('ascii', 'ignore'))
                        box_node.u32("Minor Version", le=False)
                        rem_size = payload_size - 8
                        if rem_size > 0:
                            box_node.bytes("Compatible Brands", rem_size, fmt=lambda v: repr(v))
                            
                    elif box_type == b'mvhd': # Movie metadata header
                        version = r.u8(payload_start)
                        box_node.u8("Version")
                        box_node.region("Flags", box_node.tell(), 3)
                        box_node.seek(box_node.tell() + 3)
                        
                        # Determine if the timestamp is 32-bit or 64-bit based on the version
                        if version == 1:
                            box_node.u64("Creation Time", le=False)
                            box_node.u64("Modification Time", le=False)
                            box_node.u32("Timescale", le=False, color=hx.RED)
                            box_node.u64("Duration", le=False, color=hx.GREEN)
                        else:
                            box_node.u32("Creation Time", le=False)
                            box_node.u32("Modification Time", le=False)
                            box_node.u32("Timescale", le=False, color=hx.RED)
                            box_node.u32("Duration", le=False, color=hx.GREEN)
                        
                        box_node.u32("Preferred Rate", le=False, fmt=lambda v: f"{v / 65536.0:.2f}")
                        box_node.u16("Preferred Volume", le=False, fmt=lambda v: f"{v / 256.0:.2f}")
                        box_node.region("Reserved / Matrices", box_node.tell(), box_end - box_node.tell(), color=hx.GRAY)

                    # =======================================================
                    # Branch 3: [Hyperlink Highlight] Parse Chunk Offset (Absolute physical pointers)
                    # =======================================================
                    elif box_type in (b'stco', b'co64'):
                        is_64 = (box_type == b'co64')
                        box_node.u8("Version")
                        box_node.region("Flags", box_node.tell(), 3)
                        box_node.seek(box_node.tell() + 3)
                        
                        entry_count = box_node.u32("Entry Count", le=False, color=hx.RED)
                        
                        # Video file chunk tables often have tens of thousands of entries. To prevent UI lag from rendering massive nodes,
                        # when parsing the static offset table, usually only expand the first 200 and fold the rest.
                        max_display = min(entry_count, 200) 
                        for i in range(max_display):
                            current_cursor = box_node.tell()
                            # Read the absolute offset (FOA)
                            offset_val = r.u64(current_cursor, le=False) if is_64 else r.u32(current_cursor, le=False)
                            
                            # Inject target = offset_val! Double click to jump into the mdat area to view raw audio/video frame data
                            if is_64:
                                box_node.u64(f"Chunk [{i}] Offset", le=False, color=hx.YELLOW, target=offset_val,
                                             fmt=lambda v, o=offset_val: f"0x{v:016X} -> [Double Click to Jump FOA: 0x{o:X}]")
                            else:
                                box_node.u32(f"Chunk [{i}] Offset", le=False, color=hx.YELLOW, target=offset_val,
                                             fmt=lambda v, o=offset_val: f"0x{v:08X} -> [Double Click to Jump FOA: 0x{o:X}]")
                        
                        rem = entry_count - max_display
                        if rem > 0:
                            bytes_per_entry = 8 if is_64 else 4
                            box_node.region(f"... and {rem} more absolute chunk offsets", box_node.tell(), rem * bytes_per_entry, color=hx.GRAY)

                    elif box_type == b'mdat':
                        # mdat is where the actual audio/video data stream is stored, extremely huge, marked directly as Region
                        box_node.region("Media Data Stream (Raw Audio/Video Frames)", payload_start, payload_size, color=hx.ORANGE)

                    else:
                        # For unparsed Boxes, directly assign their data area to a gray Region
                        box_node.region(f"'{box_type_str}' Payload", payload_start, payload_size, color=hx.GRAY)

            cursor = box_end

    # =========================================================
    # Start top-level recursion from offset 0
    # =========================================================
    parse_boxes(root, 0, file_size)

hx.register("MP4", detect, parse)
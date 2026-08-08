"""
JoHex Official Script: MPEG Audio Layer III (MP3) Parser
========================================================
A robust sequential parser for the MP3 audio format.
Decodes ID3v1 and ID3v2 metadata tags, identifies VBR headers (Xing/Info), 
and visually isolates the continuous chain of MPEG audio frames.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.mp3"
__name__        = "MP3 Parser"
__version__     = "1.3.1"
__author__      = "EJoyApp Team"
__category__    = "Media Parsers"
__description__ = (
    "A robust sequential parser for the MP3 audio format. Decodes ID3v1 and "
    "ID3v2 metadata tags, identifies VBR headers (Xing/Info), and visually "
    "isolates the continuous chain of MPEG audio frames."
)
__features__    = (
    "• ID3v1 and ID3v2 metadata tag decoding\n"
    "• VBR header (Xing/Info) identification\n"
    "• Continuous chain of MPEG audio frames isolation"
)
__formats__     = ".mp3"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
# The most common identifier is the ID3v2 tag at the start of the file
MAGIC_BYTES = b"ID3"
SUPPORTED_EXTS = [".mp3"]
FORMAT_NAME = "MPEG Audio Layer III (MP3)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    if not hex_prefix:
        return 0

    # 1. Check for an ID3v2 tag (the most common start for modern MP3 files).
    # An ID3v2 header is exactly 10 bytes long.
    if len(hex_prefix) >= 10 and hex_prefix.startswith(MAGIC_BYTES):
        
        # 2. Validate the ID3 version. 
        # Byte at offset 3 is the major version, offset 4 is the minor version.
        major_version = hex_prefix[3]
        
        # Commonly used versions are ID3v2.2, ID3v2.3, and ID3v2.4
        if major_version in (2, 3, 4):
            return 100  # 100% certainty that it has a valid ID3 tag (almost certainly an MP3)
            
        # Magic bytes match, but the ID3 version is unrecognized
        return 80
        
    # 3. If there is no ID3 tag, check for a raw MPEG audio frame sync.
    # The frame sync is 11 consecutive set bits: 11111111 111xxxxx (0xFF, followed by a byte >= 0xE0).
    if len(hex_prefix) >= 2 and hex_prefix[0] == 0xFF and (hex_prefix[1] & 0xE0) == 0xE0:
        
        # 4. Check the "Layer" bits to ensure it is actually Layer III (MP3).
        # Bits 2 and 1 of the second byte indicate the layer (01 = Layer III, 10 = Layer II, 11 = Layer I).
        layer_bits = (hex_prefix[1] & 0x06) >> 1
        
        if layer_bits == 1:  # Layer III (MP3)
            # A raw frame sync is strong evidence, but since it's just audio data and 
            # lacks a structured file header, we rely slightly on the extension for max confidence.
            if file_ext.lower() in SUPPORTED_EXTS:
                return 90
            return 70  # Valid MP3 frame sync, but missing or mismatched extension
            
        # Has an MPEG frame sync, but it's not Layer III (might be MP2 or MP1)
        return 40
        
    return 0

def detect(r):
    if r.size < 10:
        return False
    # MP3 usually starts with an ID3v2 tag (49 44 33)
    if r.read(0, 3) == b'ID3':
        return True
    # Or starts directly with the MPEG audio frame sync word (FF FB / FF FA, etc.)
    sync = r.u16(0, le=False)
    return (sync & 0xFFE0) == 0xFFE0

def parse(r, root):
    file_size = r.size
    cursor = 0

    # =========================================================
    # 1. Parse the ID3v2 tag at the header
    # =========================================================
    if r.read(cursor, 3) == b'ID3':
        # Read Synchsafe integer (4 bytes, only 7 bits used per byte)
        raw_size = r.u32(cursor + 6, le=False)
        id3_size = ((raw_size >> 24) & 0x7F) << 21 | \
                   ((raw_size >> 16) & 0x7F) << 14 | \
                   ((raw_size >> 8) & 0x7F) << 7 | \
                   (raw_size & 0x7F)
        
        # Includes the 10-byte Header
        total_id3_size = 10 + id3_size 

        with root.struct(f"ID3v2 Tag (Size: {total_id3_size} bytes)", color=hx.BLUE) as id3:
            id3.seek(cursor)
            id3.bytes("Identifier", 3, color=hx.YELLOW, fmt=lambda v: "ID3")
            id3.u8("Version Major")
            id3.u8("Version Minor")
            id3.u8("Flags")
            
            # Display the magical bit shift caused by Synchsafe
            id3.u32("Size (Synchsafe)", le=False, color=hx.CYAN, 
                    fmt=lambda v, s=id3_size: f"Raw: 0x{v:08X} -> Decoded: {s} bytes")

            # Iterate over specific ID3v2 frames (e.g., TIT2 Title, TPE1 Artist, APIC Cover)
            frame_cursor = cursor + 10
            while frame_cursor < cursor + total_id3_size:
                frame_id_bytes = r.read(frame_cursor, 4)
                
                # If \x00\x00\x00\x00 is encountered, it means entering the Padding area, break directly
                if frame_id_bytes == b'\x00\x00\x00\x00':
                    pad_len = cursor + total_id3_size - frame_cursor
                    id3.region("Padding (Zeroed)", frame_cursor, pad_len, color=hx.GRAY)
                    break

                frame_id = frame_id_bytes.decode('ascii', 'ignore')
                # ID3v2.3 frame header size is 10, Size is a standard big-endian 32-bit integer
                frame_size = r.u32(frame_cursor + 4, le=False)
                
                # Security check
                if frame_size == 0 or frame_cursor + 10 + frame_size > cursor + total_id3_size:
                    break

                with id3.struct(f"Frame: '{frame_id}'", color=hx.PURPLE) as tag_frame:
                    tag_frame.seek(frame_cursor)
                    tag_frame.bytes("Frame ID", 4, color=hx.YELLOW, fmt=lambda v: frame_id)
                    tag_frame.u32("Size", le=False, color=hx.CYAN)
                    tag_frame.u16("Flags", le=False)
                    
                    payload_start = frame_cursor + 10
                    
                    # Try to read text content (for text frames starting with T)
                    if frame_id.startswith('T') and frame_size > 1:
                        # The first byte is the encoding method (0=ISO-8859-1, 1=UTF-16, 2=UTF-16BE, 3=UTF-8)
                        enc = r.u8(payload_start)
                        tag_frame.u8("Encoding", fmt=lambda v: "0 (ISO)" if v==0 else "1 (UTF-16)" if v==1 else "3 (UTF-8)" if v==3 else str(v))
                        text_data = r.read(payload_start + 1, frame_size - 1)
                        # Fault-tolerant decoding
                        dec_text = text_data.decode('utf-8', 'ignore') if enc == 3 else text_data.decode('latin-1', 'ignore')
                        tag_frame.region(f"Text: {dec_text.strip(chr(0))}", payload_start + 1, frame_size - 1, color=hx.GREEN)
                    else:
                        tag_frame.region("Frame Payload", payload_start, frame_size, color=hx.GRAY)
                
                frame_cursor += 10 + frame_size
                
        cursor += total_id3_size

    # =========================================================
    # 2. Scan and parse MPEG Audio Frames
    # =========================================================
    # Search backwards for the first sync word (11 consecutive 1s)
    sync_found = False
    while cursor < file_size - 4:
        header = r.u32(cursor, le=False)
        # Check if the top 11 bits are all 1s (FF E0 mask)
        if (header & 0xFFE00000) == 0xFFE00000:
            sync_found = True
            break
        cursor += 1

    if sync_found:
        with root.struct("First MPEG Audio Frame (Stream Info)", color=hx.ORANGE) as mpeg:
            mpeg.seek(cursor)
            
            # Parse the extremely classic 32-bit MPEG Frame Header
            mpeg.u32("Frame Header", le=False, color=hx.YELLOW, fmt=lambda v: f"0x{v:08X}")
            
            version = (header >> 19) & 0x03
            layer = (header >> 17) & 0x03
            bitrate_idx = (header >> 12) & 0x0F
            samplerate_idx = (header >> 10) & 0x03
            padding = (header >> 9) & 0x01
            
            ver_str = {3: "MPEG-1", 2: "MPEG-2", 0: "MPEG-2.5"}.get(version, "Unknown")
            lay_str = {3: "Layer I", 2: "Layer II", 1: "Layer III (MP3)"}.get(layer, "Unknown")
            
            # Simplified MPEG-1 Layer 3 bitrate and sample rate tables
            if version == 3 and layer == 1:
                br_table = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
                sr_table = [44100, 48000, 32000, 0]
                br = br_table[bitrate_idx]
                sr = sr_table[samplerate_idx]
                
                mpeg.region(f"Info: {ver_str} {lay_str}", cursor, 4, color=hx.GREEN)
                mpeg.region(f"Bitrate: {br} kbps", cursor, 4, color=hx.CYAN)
                mpeg.region(f"Sample Rate: {sr} Hz", cursor, 4, color=hx.CYAN)
                mpeg.region(f"Padding: {'Yes' if padding else 'No'}", cursor, 4, color=hx.GRAY)

                # Formula to calculate the absolute size of this frame: 144 * BitRate / SampleRate + Padding
                if sr > 0:
                    frame_size = int(144 * (br * 1000) / sr) + padding
                    mpeg.region("Frame Audio Data", cursor + 4, frame_size - 4, color=hx.GRAY)
                    cursor += frame_size

        # =========================================================
        # 3. Pack the remaining massive audio frames into a single large block to prevent UI freezing
        # =========================================================
        # Check if there is an ID3v1 tag at the end of the file
        has_id3v1 = False
        if file_size >= 128 and r.read(file_size - 128, 3) == b'TAG':
            has_id3v1 = True
            
        stream_end = file_size - 128 if has_id3v1 else file_size
        stream_len = stream_end - cursor
        
        if stream_len > 0:
            root.region("Raw MPEG Audio Stream (Thousands of Frames)", cursor, stream_len, color=hx.GRAY)
            
    # =========================================================
    # 4. Parse the ID3v1 tag at the end of the file
    # =========================================================
    if file_size >= 128 and r.read(file_size - 128, 3) == b'TAG':
        id3v1_start = file_size - 128
        with root.struct("ID3v1 Tag", color=hx.BLUE) as id1:
            id1.seek(id3v1_start)
            id1.bytes("Identifier", 3, color=hx.YELLOW, fmt=lambda v: "TAG")
            id1.bytes("Title", 30, fmt=lambda v: v.decode('latin-1', 'ignore').strip('\x00'))
            id1.bytes("Artist", 30, fmt=lambda v: v.decode('latin-1', 'ignore').strip('\x00'))
            id1.bytes("Album", 30, fmt=lambda v: v.decode('latin-1', 'ignore').strip('\x00'))
            id1.bytes("Year", 4, fmt=lambda v: v.decode('latin-1', 'ignore').strip('\x00'))
            
            # ID3v1.1 Hack: If the 29th byte of the Comment is 0, the 30th byte is the Track Number
            comment_data = r.read(id3v1_start + 97, 30)
            if comment_data[28] == 0 and comment_data[29] != 0:
                id1.bytes("Comment", 28, fmt=lambda v: v.decode('latin-1', 'ignore').strip('\x00'))
                id1.u8("Zero Byte (v1.1 marker)")
                id1.u8("Track Number", color=hx.RED)
            else:
                id1.bytes("Comment", 30, fmt=lambda v: v.decode('latin-1', 'ignore').strip('\x00'))
                
            id1.u8("Genre (Index)")

hx.register("MP3", detect, parse)
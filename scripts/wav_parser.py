# wav_parser.py

"""
JoHex Official Script: Waveform Audio File Format (WAV) Parser
==============================================================
A chunk-based parser for the RIFF/WAV uncompressed audio format.
Decodes the main RIFF header, analyzes the 'fmt ' audio specification block, 
and perfectly maps the boundaries of the raw PCM 'data' payload.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.wav"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # A WAV file requires at least a 12-byte header
    if r.size < 12:
        return False
    # RIFF magic number + WAVE identifier
    is_riff = r.read(0, 4) == b'RIFF'
    is_wave = r.read(8, 4) == b'WAVE'
    return is_riff and is_wave

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse RIFF/WAVE root file header (fixed 12 bytes)
    # =========================================================
    with root.struct("RIFF/WAVE Header", color=hx.BLUE) as hdr:
        # Although the value is little-endian, the FourCC (4-Character Code) is read in ASCII order
        hdr.bytes("Chunk ID", 4, color=hx.YELLOW, fmt=lambda v: v.decode('ascii', 'ignore'))
        
        # The size of the entire file minus the first 8 bytes
        hdr.u32("Chunk Size", color=hx.CYAN)
        
        hdr.bytes("Format", 4, color=hx.GREEN, fmt=lambda v: v.decode('ascii', 'ignore'))

    # =========================================================
    # 2. Iterate through all Sub-Chunks
    # =========================================================
    cursor = 12

    while cursor < file_size - 8:
        root.seek(cursor)
        
        # Extract the Chunk identifier (FourCC)
        chunk_id_bytes = r.read(cursor, 4)
        chunk_id = chunk_id_bytes.decode('ascii', 'ignore')
        
        # Extract the Chunk size (little-endian)
        chunk_size = r.u32(cursor + 4)

        with root.struct(f"Chunk: '{chunk_id}'", color=hx.PURPLE) as chunk:
            chunk.bytes("Subchunk ID", 4, color=hx.YELLOW, fmt=lambda v: chunk_id)
            chunk.u32("Subchunk Size", color=hx.CYAN, fmt=lambda v: f"{v} bytes")

            payload_start = cursor + 8
            
            if chunk_size > 0:
                # =========================================================
                # Deep Parse A: 'fmt ' chunk (core audio format parameters)
                # =========================================================
                if chunk_id == "fmt ":
                    with chunk.struct("Audio Format Specifications", color=hx.GREEN) as fmt:
                        fmt.seek(payload_start)
                        
                        # Common audio encoding format mapping
                        audio_formats = {
                            1: "PCM (Uncompressed)",
                            3: "IEEE Float",
                            6: "A-Law",
                            7: "mu-Law",
                            0xFFFE: "Extensible"
                        }
                        
                        fmt.u16("Audio Format", color=hx.RED, fmt=lambda v: f"{v} - {audio_formats.get(v, 'Compressed/Unknown')}")
                        fmt.u16("Num Channels", color=hx.YELLOW, fmt=lambda v: "Mono (1)" if v == 1 else "Stereo (2)" if v == 2 else f"{v} Channels")
                        
                        fmt.u32("Sample Rate", color=hx.CYAN, fmt=lambda v: f"{v} Hz")
                        fmt.u32("Byte Rate", fmt=lambda v: f"{v} bytes/sec")
                        
                        fmt.u16("Block Align", fmt=lambda v: f"{v} bytes/sample slice")
                        fmt.u16("Bits Per Sample", color=hx.RED, fmt=lambda v: f"{v}-bit")
                        
                        # If it's a compressed or Extensible format, the fmt chunk might be larger than 16 bytes
                        rem_size = chunk_size - 16
                        if rem_size > 0:
                            fmt.u16("Extra Param Size")
                            if rem_size - 2 > 0:
                                fmt.region("Extra Format Parameters", fmt.tell(), rem_size - 2, color=hx.GRAY)

                # =========================================================
                # Deep Parse B: 'data' chunk (actual audio waveform data)
                # =========================================================
                elif chunk_id == "data":
                    chunk.region("Raw Audio Samples (Waveform Data)", payload_start, chunk_size, color=hx.ORANGE)

                # =========================================================
                # Deep Parse C: 'LIST' chunk (usually contains INFO metadata, e.g., artist, album)
                # =========================================================
                elif chunk_id == "LIST":
                    list_type = r.read(payload_start, 4).decode('ascii', 'ignore')
                    chunk.bytes("List Type", 4, color=hx.YELLOW, fmt=lambda v: list_type)
                    
                    if list_type == "INFO":
                        # Simple INFO chunk traversal
                        info_cursor = payload_start + 4
                        while info_cursor < payload_start + chunk_size:
                            tag = r.read(info_cursor, 4).decode('ascii', 'ignore')
                            length = r.u32(info_cursor + 4)
                            
                            # Extract string and strip trailing \x00
                            val = r.read(info_cursor + 8, length).decode('ascii', 'ignore').strip('\x00')
                            
                            chunk.region(f"Tag: {tag} = {val}", info_cursor, 8 + length, color=hx.CYAN)
                            
                            info_cursor += 8 + length
                            if length % 2 != 0: info_cursor += 1 # INFO subchunks also follow 2-byte alignment
                    else:
                        chunk.region("LIST Payload", payload_start + 4, chunk_size - 4, color=hx.GRAY)

                # =========================================================
                # All other unknown chunks (e.g., 'fact', 'cue ', 'smpl') are treated as gray regions
                # =========================================================
                else:
                    chunk.region(f"'{chunk_id}' Payload", payload_start, chunk_size, color=hx.GRAY)

        # Step cursor: Header(8) + Payload(chunk_size)
        cursor += 8 + chunk_size
        
        # [The ultimate RIFF pitfall]: Word Alignment (Padding)
        # If chunk_size is odd, an extra 0x00 byte is stuffed into the actual file stream to ensure the next Chunk starts at an even address
        if chunk_size % 2 != 0:
            root.region("Padding Byte (Word Alignment)", cursor, 1, color=hx.GRAY)
            cursor += 1

hx.register("WAV", detect, parse)
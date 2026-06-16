# rar_parser.py

"""
JoHex Official Script: Roshal Archive (RAR5) Parser
===================================================
An advanced parser for the modern RAR5 archive format.
Features a custom VINT (Variable Length Integer) decoding engine to seamlessly
separate variable-length headers, metadata, and compressed file data blocks.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.rar"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    if r.size < 7:
        return False
    # Classic magic number for RAR4 (7 bytes): 52 61 72 21 1A 07 00
    # Modern magic number for RAR5 (8 bytes): 52 61 72 21 1A 07 01 00
    magic = r.read(0, 7)
    if magic == b'Rar!\x1A\x07\x00': return True
    if r.read(0, 8) == b'Rar!\x1A\x07\x01\x00': return True
    return False

def parse(r, root):
    file_size = r.size
    
    # Determine version
    is_rar5 = r.read(0, 8) == b'Rar!\x1A\x07\x01\x00'
    
    if not is_rar5:
        # Simple annotation for RAR4 legacy format (for script robustness)
        root.bytes("RAR 4.x Signature", 7, color=hx.BLUE, fmt=lambda v: "Rar!\\x1A\\x07\\x00")
        root.region("RAR 4.x Legacy Blocks (Not Fully Parsed)", 7, file_size - 7, color=hx.GRAY)
        return

    # =========================================================
    # RAR5 Parsing Engine: VINT (Variable Length Integer) Decoder
    # Principle: The highest bit (8th bit) of each byte being 1 indicates there is a next byte, the lower 7 bits are the actual data. Assembled in little-endian.
    # =========================================================
    def read_vint(offset):
        val = 0
        shift = 0
        bytes_read = 0
        while offset + bytes_read < file_size:
            b = r.u8(offset + bytes_read)
            bytes_read += 1
            val += (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                break
        return val, bytes_read

    # =========================================================
    # 1. RAR5 Signature Parsing
    # =========================================================
    with root.struct("RAR5 Signature Header", color=hx.BLUE) as sig:
        sig.bytes("Magic Number", 8, color=hx.YELLOW, fmt=lambda v: "Rar!\\x1A\\x07\\x01\\x00")
    
    cursor = 8

    # =========================================================
    # 2. Iterate through the stream of RAR5 variable-length blocks
    # =========================================================
    # RAR5 block structure: [Header CRC (4)] + [Header Size (VINT)] + [Header Payload] + [Optional Data]
    
    while cursor < file_size:
        # Safe boundary check
        if cursor + 5 > file_size:
            break
            
        header_start = cursor
        header_crc = r.u32(cursor)
        
        # Use custom engine to read Header size
        header_size, vsize_len = read_vint(cursor + 4)
        
        # Calculate the total span of the physical block
        total_header_bytes = 4 + vsize_len + header_size
        
        if header_size == 0 or cursor + total_header_bytes > file_size:
            root.region("Malformed/Truncated Block", cursor, file_size - cursor, color=hx.GRAY)
            break

        # Continue using VINT inside Header Payload to read Type and Flags
        payload_start = cursor + 4 + vsize_len
        block_type, type_len = read_vint(payload_start)
        block_flags, flags_len = read_vint(payload_start + type_len)
        
        # Block Type dictionary mapping
        type_names = {
            1: "Main Archive Header",
            2: "File Header",
            3: "Service Header",
            4: "Archive Encryption",
            5: "End of Archive"
        }
        b_name = type_names.get(block_type, f"Unknown (Type {block_type})")

        with root.struct(f"Block: {b_name}", color=hx.PURPLE) as blk:
            blk.seek(header_start)
            blk.u32("Header CRC32", color=hx.RED, fmt=lambda v: f"0x{v:08X}")
            
            # [Magical Visualization]: Map the raw bytes occupied by VINT to the UI and display the decoded real size
            blk.region(f"Header Size (VINT Encoded)", blk.tell(), vsize_len, color=hx.YELLOW)
            
            blk.region(f"Block Type ({block_type})", payload_start, type_len, color=hx.CYAN)
            blk.region(f"Flags (0x{block_flags:X})", payload_start + type_len, flags_len, color=hx.CYAN)
            
            # --- Deep Parsing: Extract the hidden Data Size (if any) ---
            # If the 0x0001 bit of Flags is set, it means this Header is followed by a compressed file data section (Data Area)
            has_data = (block_flags & 0x0001) != 0
            data_size = 0
            
            v_cursor = payload_start + type_len + flags_len
            
            # If there is an Extra Area (0x0002)
            if (block_flags & 0x0002) != 0:
                extra_size, elen = read_vint(v_cursor)
                blk.region(f"Extra Area Size: {extra_size}", v_cursor, elen, color=hx.CYAN)
                v_cursor += elen
                
            if has_data:
                data_size, dlen = read_vint(v_cursor)
                blk.region(f"Data Area Size: {data_size} bytes", v_cursor, dlen, color=hx.GREEN)
                v_cursor += dlen
                
            # Remaining metadata area of the Header (e.g., filename, timestamps, OS attributes, etc.)
            rem_header = header_start + total_header_bytes - v_cursor
            if rem_header > 0:
                blk.region("Header Metadata (Name/Time/Attr)", v_cursor, rem_header, color=hx.GRAY)

        # =========================================================
        # 3. Strip and annotate the actual compressed file data (Data Area)
        # =========================================================
        data_start = header_start + total_header_bytes
        
        if has_data and data_size > 0:
            if data_start + data_size <= file_size:
                # Assign target hyperlink! (If doing decompression preview later, can jump directly here)
                root.region(f"Compressed File Data Area", data_start, data_size, color=hx.ORANGE)
            else:
                root.region("Truncated Data Area", data_start, file_size - data_start, color=hx.GRAY)
                
        # Step cursor: Total physical size of Header + size of the Data block if present
        cursor = data_start + data_size
        
        # Jump out directly when encountering End of Archive to prevent parsing appended garbage data
        if block_type == 5:
            break

hx.register("RAR", detect, parse)
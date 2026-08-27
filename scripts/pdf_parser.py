"""
JoHex Official Script: Portable Document Format (PDF) Parser
============================================================
A structural parser for Adobe's Portable Document Format.
Identifies the file header, isolates raw binary streams, and maps the 
Cross-Reference (xref) table to provide FOA navigation to internal objects and the trailer.
Includes automated internal stream extraction tagging for Archive Browser.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.pdf"
__name__        = "PDF Parser"
__version__     = "1.4.0" # Bumped version for Archive Browser extraction support
__author__      = "EJoyApp Team"
__category__    = "Document Parsers"
__description__ = '''
    "A structural parser for Adobe's Portable Document Format. Identifies the "
    "file header, isolates raw binary streams, and maps the Cross-Reference (xref) "
    "table to provide FOA navigation to internal objects and the trailer. "
    "Now includes automated stream extraction capabilities."
'''
__features__    = '''
    "• File header identification"
    "• Raw binary stream isolation & automated extraction"
    "• Cross-Reference (xref) table mapping"
    "• FOA navigation to internal objects and trailer"
'''
__formats__     = ".pdf"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import re
import struct

# Register static features (for AI or other static scanning tools)
MAGIC_BYTES = b"%PDF-"
SUPPORTED_EXTS = [".pdf"]
FORMAT_NAME = "Portable Document Format (PDF)"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    if not hex_prefix:
        return 0

    if hex_prefix.startswith(MAGIC_BYTES):
        if len(hex_prefix) >= 8:
            return 100 
        return 80
        
    search_area = hex_prefix[:1024]
    
    if MAGIC_BYTES in search_area:
        if file_ext.lower() in SUPPORTED_EXTS:
            return 90
        return 70 
        
    return 0

def detect(r):
    if r.size < 8:
        return False
    return r.read(0, 5) == b'%PDF-'

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse PDF Header (Header Declaration)
    # =========================================================
    header_len = 0
    while header_len < 20 and r.read(header_len, 1) not in (b'\r', b'\n'):
        header_len += 1
    root.bytes("PDF Header", header_len, color=hx.BLUE, fmt=lambda v: v.decode('ascii', 'ignore'))

    # =========================================================
    # 2. Tail scan: Look for startxref and Trailer
    # =========================================================
    search_size = min(4096, file_size)
    tail_data = r.read(file_size - search_size, search_size)
    
    startxref_idx = tail_data.rfind(b'startxref')
    if startxref_idx == -1:
        root.region("PDF Body (No startxref found)", header_len, file_size - header_len, color=hx.GRAY)
        return

    abs_startxref = file_size - search_size + startxref_idx
    
    tail_end = tail_data[startxref_idx:]
    match = re.search(rb'startxref\s+(\d+)', tail_end)
    xref_offset = int(match.group(1)) if match else 0

    # =========================================================
    # 3. Core: Parse XREF & Extract Internal Streams
    # =========================================================
    if 0 < xref_offset < file_size:
        
        xref_data = r.read(xref_offset, min(file_size - xref_offset, 65536))
        
        if xref_data.startswith(b'xref'):
            lines = xref_data.splitlines()
            
            with root.struct("XREF Table (Cross-Reference)", color=hx.GREEN) as xref_node:
                xref_node.seek(xref_offset)
                xref_node.bytes("Marker", 4, color=hx.YELLOW, fmt=lambda v: "xref")
                
                cursor = xref_offset + 4
                current_obj_id = 0
                
                for line in lines[1:]:
                    line_len = len(line) + 1 
                    line_str = line.strip()
                    
                    if not line_str:
                        cursor += line_len
                        continue
                    if line_str == b'trailer':
                        break 
                        
                    parts = line_str.split()
                    
                    if len(parts) == 2:
                        current_obj_id = int(parts[0])
                        xref_node.region(f"Subsection [Obj {current_obj_id} - {current_obj_id + int(parts[1]) - 1}]", cursor, line_len, color=hx.PURPLE)
                    
                    elif len(parts) == 3:
                        obj_offset = int(parts[0])
                        obj_gen = int(parts[1])
                        obj_state = parts[2]
                        
                        if obj_state == b'n' and obj_offset > 0:
                            with xref_node.struct(f"Obj {current_obj_id} (Gen {obj_gen})", color=hx.CYAN, target=obj_offset) as entry:
                                entry.seek(cursor)
                                entry.bytes("Raw Text", line_len, fmt=lambda v, o=obj_offset: f"{v.decode('ascii', 'ignore').strip()} -> [FOA: 0x{o:X}]")
                                
                                peek_data = r.read(obj_offset, min(file_size - obj_offset, 1024))
                                stream_idx = peek_data.find(b'stream')
                                
                                if stream_idx != -1:
                                    data_start = obj_offset + stream_idx + 6
                                    while data_start < file_size:
                                        b = r.read(data_start, 1)
                                        if b in (b'\r', b'\n'):
                                            data_start += 1
                                        else:
                                            break
                                    
                                    length = 0
                                    len_match = re.search(rb'/Length\s+(\d+)', peek_data[:stream_idx])
                                    if len_match:
                                        length = int(len_match.group(1))
                                    else:
                                        chunk_size = min(file_size - data_start, 1024 * 1024 * 10)
                                        chunk = r.read(data_start, chunk_size)
                                        end_idx = chunk.find(b'endstream')
                                        if end_idx != -1:
                                            while end_idx > 0 and chunk[end_idx - 1] in (13, 10):
                                                end_idx -= 1
                                            length = end_idx

                                    if length > 0:
                                        ext = ".bin"
                                        
                                        if b'/Subtype /Image' in peek_data or b'/Subtype/Image' in peek_data:
                                            if b'/Filter /DCTDecode' in peek_data or b'/Filter/DCTDecode' in peek_data:
                                                ext = ".jpg"
                                            elif b'/Filter /FlateDecode' in peek_data or b'/Filter/FlateDecode' in peek_data:
                                                ext = ".raw_pixels.zlib"
                                            else:
                                                ext = ".raw_pixels"
                                                
                                        elif b'/Filter /FlateDecode' in peek_data or b'/Filter/FlateDecode' in peek_data:
                                            ext = ".zlib"
                                            
                                        extract_name = f"obj_{current_obj_id}_{obj_gen}{ext}"
                                        entry.seek(data_start)
                                        entry.region(f"[EXTRACT:raw]{extract_name}", data_start, length, color=hx.ORANGE)

                        else:
                            xref_node.region(f"Obj {current_obj_id} (Free/Ignored)", cursor, line_len, color=hx.GRAY)
                            
                        current_obj_id += 1
                        
                    cursor += line_len
    else:
        root.region("PDF Body", header_len, file_size - header_len, color=hx.GRAY)

    # =========================================================
    # 4. Mark Trailer and EOF areas
    # =========================================================
    with root.struct("PDF Trailer & EOF", color=hx.ORANGE) as tail:
        tail.seek(abs_startxref)
        tail_len = file_size - abs_startxref
        tail.bytes("Raw Data", tail_len, fmt=lambda v: "startxref ... %%EOF")

hx.register("PDF", detect, parse)
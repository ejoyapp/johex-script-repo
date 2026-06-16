# pdf_parser.py

"""
JoHex Official Script: Portable Document Format (PDF) Parser
============================================================
A structural parser for Adobe's Portable Document Format.
Identifies the file header, isolates raw binary streams, and maps the 
Cross-Reference (xref) table to provide FOA navigation to internal objects and the trailer.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.pdf"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx
import re

def detect(r):
    # PDF standard magic number
    if r.size < 8:
        return False
    return r.read(0, 5) == b'%PDF-'

def parse(r, root):
    file_size = r.size

    # =========================================================
    # 1. Parse PDF Header (Header Declaration)
    # =========================================================
    # Header is usually "%PDF-1.x\r\n", length is variable, we scan until a newline
    header_len = 0
    while header_len < 20 and r.read(header_len, 1) not in (b'\r', b'\n'):
        header_len += 1
    root.bytes("PDF Header", header_len, color=hx.BLUE, fmt=lambda v: v.decode('ascii', 'ignore'))

    # =========================================================
    # 2. Tail scan: Look for startxref and Trailer
    # =========================================================
    # PDF allows incremental updates, so there might be multiple %%EOF markers; we only look for the very last one
    search_size = min(4096, file_size)
    tail_data = r.read(file_size - search_size, search_size)
    
    startxref_idx = tail_data.rfind(b'startxref')
    if startxref_idx == -1:
        # If not found, it might be an extremely special or corrupted PDF
        root.region("PDF Body (No startxref found)", header_len, file_size - header_len, color=hx.GRAY)
        return

    # Calculate the absolute physical offset of startxref in the file
    abs_startxref = file_size - search_size + startxref_idx
    
    # Use regex to extract the offset number below startxref
    tail_end = tail_data[startxref_idx:]
    match = re.search(rb'startxref\s+(\d+)', tail_end)
    xref_offset = int(match.group(1)) if match else 0

    # =========================================================
    # 3. Core: Parse XREF (Cross-Reference Table) and inject hyperlinks
    # =========================================================
    # If the offset is valid, jump over to parse that plaintext table
    if 0 < xref_offset < file_size:
        
        # Pre-read a portion of data for plaintext parsing
        xref_data = r.read(xref_offset, min(file_size - xref_offset, 65536))
        
        if xref_data.startswith(b'xref'):
            lines = xref_data.splitlines()
            
            # Use the struct target support we extended in the previous section
            # Treat the entire table as a large folder
            with root.struct("XREF Table (Cross-Reference)", color=hx.GREEN) as xref_node:
                # Force the cursor to the actual position of XREF
                xref_node.seek(xref_offset)
                
                # The first line is usually "xref"
                xref_node.bytes("Marker", 4, color=hx.YELLOW, fmt=lambda v: "xref")
                
                cursor = xref_offset + 4
                current_obj_id = 0
                
                # Iterate through text lines
                for line in lines[1:]:
                    line_len = len(line) + 1 # Roughly add the step for the newline character
                    line_str = line.strip()
                    
                    if not line_str:
                        cursor += line_len
                        continue
                    if line_str == b'trailer':
                        break # Encountered trailer, end of table
                        
                    parts = line_str.split()
                    
                    if len(parts) == 2:
                        # Subsection declaration: e.g., "0 15" means starting from Object 0, 15 consecutive objects
                        current_obj_id = int(parts[0])
                        # As an un-jumpable normal identifier
                        xref_node.region(f"Subsection [Obj {current_obj_id} - {current_obj_id + int(parts[1]) - 1}]", cursor, line_len, color=hx.PURPLE)
                    
                    elif len(parts) == 3:
                        # Specific entry: e.g., "0000000015 00000 n"
                        obj_offset = int(parts[0])
                        obj_gen = int(parts[1])
                        obj_state = parts[2]
                        
                        if obj_state == b'n' and obj_offset > 0:
                            # [Linked Hyperlink]: This is an in-use object, assign a target to it!
                            # We wrap the entire entry as a struct, giving it jump capability
                            with xref_node.struct(f"Obj {current_obj_id} (Gen {obj_gen})", color=hx.CYAN, target=obj_offset) as entry:
                                entry.seek(cursor)
                                entry.bytes("Raw Text", line_len, fmt=lambda v, o=obj_offset: f"{v.decode('ascii', 'ignore').strip()} -> [FOA: 0x{o:X}]")
                        else:
                            # Freed object (f) or object 0
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
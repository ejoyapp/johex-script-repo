# docx_parser.py

"""
JoHex Official Script: Word Open XML (DOCX) Parser
==================================================
A semantic parser for modern Microsoft Word documents (OOXML).
Features regex-based boundary detection and color-coded structural analysis
to instantly isolate document text, media, and potentially malicious payloads.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.docx"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx
import re

def detect(r):
    # DOCX is essentially a ZIP, the magic number must be PK\x03\x04
    if r.size < 4:
        return False
    if r.u32(0) != 0x04034B50:
        return False
        
    # Look-ahead sniffing: confirm it is OOXML, and ideally has Word-specific features
    name_len = r.u16(26)
    if r.size > 30 + name_len:
        first_file_name = r.read(30, name_len)
        # As long as it contains one of these three features, we take over the parsing
        if b'[Content_Types].xml' in first_file_name or b'_rels' in first_file_name or b'word/' in first_file_name:
            return True
            
    return False

def parse(r, root):
    cursor = 0
    file_size = r.size

    # =========================================================
    # DOCX (Word) specific business path semantic recognition engine
    # =========================================================
    def get_docx_color(filename):
        if "word/document.xml" in filename: return hx.GREEN    # Core payload: all body text is here
        if "word/media/" in filename: return hx.ORANGE         # Media resources: inserted images, videos
        if "word/styles.xml" in filename: return hx.PURPLE     # Stylesheet: fonts, colors, layout rules
        if "word/embeddings/" in filename: return hx.RED       # Danger zone: embedded OLE objects (e.g., malicious macros/scripts)
        if "_rels" in filename: return hx.GRAY                 # Relationship mapping table
        if "[Content_Types].xml" in filename: return hx.CYAN   # Global content types
        return hx.BLUE

    while cursor <= file_size - 4:
        root.seek(cursor)
        sig = r.u32(cursor)

        # =========================================================
        # 1. Local File Header
        # =========================================================
        if sig == 0x04034B50:
            name_len = r.u16(cursor + 26)
            
            # Sniff the file name in advance to color the entire Block
            file_name = "Unknown"
            if name_len > 0 and cursor + 30 + name_len <= file_size:
                file_name = r.read(cursor + 30, name_len).decode('utf-8', 'ignore')
                
            block_color = get_docx_color(file_name)

            with root.struct(f"Local File Header [{file_name}]", color=block_color) as lfh:
                lfh.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x03\\x04 (Local Header)")
                lfh.u16("Version Needed To Extract")
                
                flags = lfh.u16("General Purpose Bit Flag", fmt=lambda v: f"0x{v:04X}")
                lfh.u16("Compression Method", fmt=lambda v: "Store (0)" if v == 0 else f"Deflate (8)" if v == 8 else str(v))
                
                lfh.u16("Last Mod File Time")
                lfh.u16("Last Mod File Date")
                lfh.u32("CRC-32", fmt=lambda v: f"0x{v:08X}")
                
                comp_size = lfh.u32("Compressed Size")
                lfh.u32("Uncompressed Size")
                lfh.u16("File Name Length")
                extra_len = lfh.u16("Extra Field Length")

                if name_len > 0:
                    lfh.bytes("File Name", name_len, color=hx.CYAN, fmt=lambda v: v.decode('utf-8', 'ignore'))
                if extra_len > 0:
                    lfh.region("Extra Field", lfh.tell(), extra_len, color=hx.GRAY)
                    lfh.seek(lfh.tell() + extra_len)

                data_start = lfh.tell()

                # =========================================================
                # [Performance Nuke Fix]: Regex rapid scanning of Data Descriptor boundaries
                # =========================================================
                if (flags & 0x0008) != 0 and comp_size == 0:
                    search_len = min(file_size - data_start, 20 * 1024 * 1024) # Max search 20MB
                    raw_bytes = r.read(data_start, search_len)
                    # Concurrently match the magic number of the next block
                    match = re.search(b'PK\x07\x08|PK\x01\x02|PK\x03\x04|PK\x05\x06', raw_bytes)
                    if match:
                        comp_size = match.start()
                    else:
                        comp_size = search_len

                if comp_size > 0:
                    lfh.region(f"Compressed Data ({file_name})", data_start, comp_size, color=block_color)

                cursor = data_start + comp_size

        # =========================================================
        # 2. Central Directory Header - [Note: FOA Hyperlink Engine]
        # =========================================================
        elif sig == 0x02014B50:
            name_len = r.u16(cursor + 28)
            file_name = "Unknown"
            if name_len > 0 and cursor + 46 + name_len <= file_size:
                file_name = r.read(cursor + 46, name_len).decode('utf-8', 'ignore')
                
            block_color = get_docx_color(file_name)

            with root.struct(f"Central Directory [{file_name}]", color=hx.BLUE) as cdh:
                cdh.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x01\\x02 (Central Directory)")
                cdh.u16("Version Made By")
                cdh.u16("Version Needed To Extract")
                cdh.u16("General Purpose Bit Flag")
                cdh.u16("Compression Method")
                
                # Skip some unimportant time and CRC attribute displays to keep the interface clean
                cdh.seek(cdh.tell() + 12) 
                
                cdh.u32("Compressed Size")
                cdh.u32("Uncompressed Size")
                cdh.u16("File Name Length")
                extra_len = cdh.u16("Extra Field Length")
                com_len = cdh.u16("File Comment Length")
                
                cdh.seek(cdh.tell() + 8) # Skip Disk Number and Attributes

                # [Inject Hyperlink]: Absolute physical offset for precision jumping
                offset_val = r.u32(cdh.tell())
                cdh.u32("Relative Offset of Local Header", color=hx.RED, target=offset_val,
                        fmt=lambda v: f"0x{v:08X} -> [Double Click to Jump FOA]")

                if name_len > 0:
                    cdh.bytes("File Name", name_len, color=hx.CYAN, fmt=lambda v: v.decode('utf-8', 'ignore'))
                if extra_len > 0:
                    cdh.region("Extra Field", cdh.tell(), extra_len, color=hx.GRAY)
                    cdh.seek(cdh.tell() + extra_len)
                if com_len > 0:
                    cdh.bytes("File Comment", com_len, fmt=lambda v: v.decode('utf-8', 'ignore'))

                cursor = cdh.tell()

        # =========================================================
        # 3. End of Central Directory (EOCD)
        # =========================================================
        elif sig == 0x06054B50:
            with root.struct("End of Central Directory (EOCD)", color=hx.ORANGE) as eocd:
                eocd.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x05\\x06")
                eocd.seek(eocd.tell() + 12) # Quickly skip Disk count information
                
                # [Inject Hyperlink]: One-click direct access to the central directory group behind the file
                cd_offset = r.u32(eocd.tell())
                eocd.u32("Offset of Central Directory", color=hx.RED, target=cd_offset,
                         fmt=lambda v: f"0x{v:08X} -> [Double Click to Jump CD]")

                com_len = eocd.u16("ZIP File Comment Length")
                if com_len > 0:
                    eocd.bytes("Comment", com_len, fmt=lambda v: v.decode('utf-8', 'ignore'))

                cursor = eocd.tell()
            break 

        # =========================================================
        # 4. Data Descriptor
        # =========================================================
        elif sig == 0x08074B50:
            with root.struct("Data Descriptor", color=hx.GRAY) as dd:
                dd.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x07\\x08")
                dd.u32("CRC-32", fmt=lambda v: f"0x{v:08X}")
                dd.u32("Compressed Size")
                dd.u32("Uncompressed Size")
                cursor = dd.tell()
        else:
            cursor += 1

hx.register("DOCX", detect, parse)
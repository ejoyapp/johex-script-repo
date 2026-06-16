# pptx_parser.py

"""
JoHex Official Script: PowerPoint Open XML (PPTX) Parser
========================================================
A semantic parser for modern Microsoft PowerPoint documents (OOXML).
Leverages high-speed regex boundary scanning and FOA hyperlinking to
expose internal ZIP structures, isolating slides, media, and embedded OLE objects.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.pptx"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # PPTX is essentially a ZIP, the magic number must be PK\x03\x04
    if r.size < 4:
        return False
    if r.u32(0) != 0x04034B50:
        return False
        
    # To distinguish it from a normal ZIP, we further probe whether its first file is an OOXML specification characteristic file
    # Usually, the first file of OOXML is "[Content_Types].xml" or "_rels/.rels"
    name_len = r.u16(26)
    if r.size > 30 + name_len:
        first_file_name = r.read(30, name_len)
        if b'[Content_Types].xml' in first_file_name or b'_rels' in first_file_name or b'ppt/' in first_file_name:
            return True
            
    return False

def parse(r, root):
    cursor = 0
    file_size = r.size

    # OOXML core business path features
    def get_ooxml_color(filename):
        if "ppt/slides/slide" in filename: return hx.GREEN     # Core slides
        if "ppt/media/" in filename: return hx.ORANGE          # Media resources (images/videos)
        if "ppt/presentation.xml" in filename: return hx.RED   # Presentation main entry
        if "_rels" in filename: return hx.GRAY                 # Relationship mapping table
        if "[Content_Types].xml" in filename: return hx.CYAN   # Global content types
        return hx.PURPLE

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
                
            block_color = get_ooxml_color(file_name)

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

                # Handle Data Descriptor (undetermined size issue in streaming compression)
                if (flags & 0x0008) != 0 and comp_size == 0:
                    scan_cursor = data_start
                    while scan_cursor <= file_size - 4:
                        if r.u32(scan_cursor) in (0x08074B50, 0x02014B50, 0x04034B50, 0x06054B50):
                            break
                        scan_cursor += 1
                    comp_size = scan_cursor - data_start

                if comp_size > 0:
                    lfh.region(f"Compressed Data ({file_name})", data_start, comp_size, color=block_color)

                cursor = data_start + comp_size

        # =========================================================
        # 2. Central Directory Header
        # =========================================================
        elif sig == 0x02014B50:
            name_len = r.u16(cursor + 28)
            file_name = "Unknown"
            if name_len > 0 and cursor + 46 + name_len <= file_size:
                file_name = r.read(cursor + 46, name_len).decode('utf-8', 'ignore')
                
            block_color = get_ooxml_color(file_name)

            with root.struct(f"Central Directory [{file_name}]", color=hx.BLUE) as cdh:
                cdh.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x01\\x02 (Central Directory)")
                cdh.u16("Version Made By")
                cdh.u16("Version Needed To Extract")
                cdh.u16("General Purpose Bit Flag")
                cdh.u16("Compression Method")
                cdh.u16("Last Mod File Time")
                cdh.u16("Last Mod File Date")
                cdh.u32("CRC-32", fmt=lambda v: f"0x{v:08X}")
                cdh.u32("Compressed Size")
                cdh.u32("Uncompressed Size")
                cdh.u16("File Name Length")
                extra_len = cdh.u16("Extra Field Length")
                com_len = cdh.u16("File Comment Length")
                cdh.u16("Disk Number Start")
                cdh.u16("Internal File Attributes")
                cdh.u32("External File Attributes")

                # [Inject Hyperlink]: Use ZIP's absolute offset mechanism to jump to the slide position
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
                eocd.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x05\\x06 (EOCD)")
                eocd.u16("Number of this Disk")
                eocd.u16("Disk where CD starts")
                eocd.u16("Number of CD records on disk")
                eocd.u16("Total number of CD records")
                eocd.u32("Size of Central Directory")

                # [Inject Hyperlink]: Point to the start of the Central Directory group
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

hx.register("PPTX", detect, parse)
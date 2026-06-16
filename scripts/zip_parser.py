# zip_parser.py

"""
JoHex Official Script: ZIP Archive Parser
=========================================
A high-performance structural parser for the standard ZIP archive format.
Parses Local File Headers and provides reverse-engineered FOA routing from the 
End of Central Directory (EOCD) back to the Central Directory records.

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.zip"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import johexedit as hx

def detect(r):
    # Standard file header signature for ZIP files (PK\x03\x04) or EOCD signature for empty ZIPs (PK\x05\x06)
    if r.size < 4:
        return False
    sig = r.u32(0)
    # 50 4B 03 04 in memory becomes 0x04034B50 when read in little-endian
    return sig in (0x04034B50, 0x06054B50)

def parse(r, root):
    cursor = 0
    file_size = r.size

    # Use sequential scanning mode to parse the building-block-like ZIP structure
    while cursor <= file_size - 4:
        root.seek(cursor)
        sig = r.u32(cursor)

        # =========================================================
        # 1. Local File Header
        # =========================================================
        if sig == 0x04034B50:
            with root.struct("Local File Header", color=hx.BLUE) as lfh:
                lfh.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x03\\x04 (Local File Header)")
                lfh.u16("Version Needed To Extract")
                
                # General Purpose Bit Flag
                flags = lfh.u16("General Purpose Bit Flag", fmt=lambda v: f"0x{v:04X}")
                
                lfh.u16("Compression Method", fmt=lambda v: "Store (0)" if v == 0 else f"Deflate (8)" if v == 8 else str(v))
                lfh.u16("Last Mod File Time")
                lfh.u16("Last Mod File Date")
                lfh.u32("CRC-32", fmt=lambda v: f"0x{v:08X}")
                
                comp_size = lfh.u32("Compressed Size")
                lfh.u32("Uncompressed Size")
                name_len = lfh.u16("File Name Length")
                extra_len = lfh.u16("Extra Field Length")

                # Parse the file name (use fmt to display the decoded text directly on the UI tree)
                file_name = "Unknown"
                if name_len > 0:
                    raw_name = lfh.bytes("File Name", name_len, fmt=lambda v: v.decode('utf-8', 'ignore'))
                    file_name = raw_name.decode('utf-8', 'ignore')

                if extra_len > 0:
                    lfh.region("Extra Field", lfh.tell(), extra_len, color=hx.GRAY)
                    lfh.seek(lfh.tell() + extra_len)

                data_start = lfh.tell()

                # [Advanced Detection Mechanism]: Handle unknown data stream lengths
                # If Bit 3 of Flags is set, it means the size is recorded in the following Data Descriptor
                if (flags & 0x0008) != 0 and comp_size == 0:
                    scan_cursor = data_start
                    while scan_cursor <= file_size - 4:
                        nxt_sig = r.u32(scan_cursor)
                        # Scan for the next known block signature
                        if nxt_sig in (0x08074B50, 0x02014B50, 0x04034B50, 0x06054B50):
                            break
                        scan_cursor += 1
                    comp_size = scan_cursor - data_start

                # Mount the actual compressed file data block on the UI tree
                if comp_size > 0:
                    root.region(f"File Data [{file_name}]", data_start, comp_size, color=hx.GREEN)

                # Jump the outer loop cursor directly past the data block
                cursor = data_start + comp_size

        # =========================================================
        # 2. Central Directory Header
        # =========================================================
        elif sig == 0x02014B50:
            with root.struct("Central Directory Header", color=hx.PURPLE) as cdh:
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
                name_len = cdh.u16("File Name Length")
                extra_len = cdh.u16("Extra Field Length")
                com_len = cdh.u16("File Comment Length")
                cdh.u16("Disk Number Start")
                cdh.u16("Internal File Attributes")
                cdh.u32("External File Attributes")

                # [Linked Hyperlink]: Apply the target mechanism
                # Read the absolute offset in advance using r
                offset_val = r.u32(cdh.tell())
                
                # Inject target! Double-click this line, and the main view instantly leaps back to the Local File Header at the beginning of the file
                cdh.u32("Relative Offset of Local Header", color=hx.RED, target=offset_val,
                        fmt=lambda v: f"0x{v:08X} -> [Double Click to Jump LFH]")

                if name_len > 0:
                    cdh.bytes("File Name", name_len, fmt=lambda v: v.decode('utf-8', 'ignore'))
                if extra_len > 0:
                    cdh.region("Extra Field", cdh.tell(), extra_len, color=hx.GRAY)
                    cdh.seek(cdh.tell() + extra_len)
                if com_len > 0:
                    cdh.bytes("File Comment", com_len, fmt=lambda v: v.decode('utf-8', 'ignore'))

                cursor = cdh.tell()

        # =========================================================
        # 3. End of Central Directory (EOCD - ZIP end signature)
        # =========================================================
        elif sig == 0x06054B50:
            with root.struct("End of Central Directory", color=hx.ORANGE) as eocd:
                eocd.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x05\\x06 (EOCD)")
                eocd.u16("Number of this Disk")
                eocd.u16("Disk where CD starts")
                eocd.u16("Number of CD records on disk")
                eocd.u16("Total number of CD records")
                eocd.u32("Size of Central Directory")

                # [Linked Hyperlink]: Points to the absolute offset of the start of the entire Central Directory
                cd_offset = r.u32(eocd.tell())
                eocd.u32("Offset of Central Directory", color=hx.RED, target=cd_offset,
                         fmt=lambda v: f"0x{v:08X} -> [Double Click to Jump CD]")

                com_len = eocd.u16("ZIP File Comment Length")
                if com_len > 0:
                    eocd.bytes("Comment", com_len, fmt=lambda v: v.decode('utf-8', 'ignore'))

                cursor = eocd.tell()
            
            # Encountering EOCD usually represents the logical end of the ZIP file, break the loop
            break 

        # =========================================================
        # 4. Data Descriptor
        # =========================================================
        elif sig == 0x08074B50:
            with root.struct("Data Descriptor", color=hx.GRAY) as dd:
                dd.u32("Signature", color=hx.YELLOW, fmt=lambda v: "PK\\x07\\x08 (Data Descriptor)")
                dd.u32("CRC-32", fmt=lambda v: f"0x{v:08X}")
                dd.u32("Compressed Size")
                dd.u32("Uncompressed Size")
                cursor = dd.tell()

        # If an unrecognized signature block is encountered, safely move the cursor forward byte by byte (enhances robustness)
        else:
            cursor += 1

hx.register("ZIP", detect, parse)
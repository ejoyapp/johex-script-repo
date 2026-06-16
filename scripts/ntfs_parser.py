# ntfs_parser.py

"""
JoHex Official Script: New Technology File System (NTFS) Parser
===============================================================
An industrial-grade forensic parser for raw NTFS volumes and disk images.
Features intelligent MBR/GPT partition routing, BIOS Parameter Block (BPB) decoding,
and LCN-to-FOA translation for instant jumps to the Master File Table ($MFT).

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

__module_id__  = "johex.parser.ntfs"
__version__    = "1.3.0"
__author__     = "EJoyApp Team"
__copyright__  = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__     = "Official / Built-in"

import hexedit as hx

def get_vbr_sector(r):
    """
    Sniffer function: Dynamically parses MBR and GPT partition tables to precisely locate the NTFS payload
    """
    try:
        # Read sector 0 (MBR)
        sector_0 = r.read(0, 512)
        if len(sector_0) < 512:
            return None, 0
            
        # 1. Attempt: The device itself has no partition table (Superfloppy mode)
        if sector_0[3:11] == b'NTFS    ':
            print("[Detector] [INFO] NTFS found directly at Sector 0 (Superfloppy layout).")
            return sector_0, 0
            
        # =========================================================
        # 2. Miniature MBR partition table parsing engine (located at byte 446 of sector 0)
        # =========================================================
        # MBR has 4 primary partition table entries, each 16 bytes
        for i in range(4):
            entry_offset = 446 + i * 16
            part_type = sector_0[entry_offset + 4]
            
            # Type 0x07 represents NTFS or exFAT
            if part_type == 0x07:
                # Extract Starting LBA (4 bytes, little-endian, offset is 8)
                lba_bytes = sector_0[entry_offset+8 : entry_offset+12]
                start_lba = int.from_bytes(lba_bytes, 'little')
                
                part_offset = start_lba * 512
                if part_offset > 0 and r.size > part_offset + 512:
                    sec_x = r.read(part_offset, 512)
                    if sec_x[3:11] == b'NTFS    ':
                        print(f"[Detector] [INFO] MBR Parsed: Found NTFS partition at LBA {start_lba} (Offset: 0x{part_offset:X})")
                        return sec_x, part_offset

            # Type 0xEE indicates a protective GPT partition, meaning the real partition table is in GPT
            elif part_type == 0xEE:
                print("[Detector] [INFO] Protective MBR detected. Switching to GPT parsing engine...")
                
                # =========================================================
                # 3. Miniature GPT partition table parsing engine (located at sector 1)
                # =========================================================
                # Read LBA 1 (GPT Header)
                gpt_hdr = r.read(512, 512)
                if len(gpt_hdr) == 512 and gpt_hdr[:8] == b'EFI PART':
                    # Extract the starting LBA of the partition table entry array (8 bytes, offset 72)
                    part_array_lba = int.from_bytes(gpt_hdr[72:80], 'little')
                    
                    # For performance, we only scan the first 8 partition entries of GPT (NTFS is usually in there)
                    # Each GPT partition entry is 128 bytes long
                    for p in range(8):
                        entry_pos = part_array_lba * 512 + p * 128
                        if entry_pos + 128 > r.size: break
                        
                        part_entry = r.read(entry_pos, 128)
                        
                        # Starting LBA in GPT partition entry (8 bytes, offset 32)
                        gpt_start_lba = int.from_bytes(part_entry[32:40], 'little')
                        
                        if gpt_start_lba > 0:
                            part_offset = gpt_start_lba * 512
                            if part_offset < r.size:
                                sec_x = r.read(part_offset, 512)
                                if len(sec_x) == 512 and sec_x[3:11] == b'NTFS    ':
                                    print(f"[Detector] [INFO] GPT Parsed: Found NTFS partition at LBA {gpt_start_lba} (Offset: 0x{part_offset:X})")
                                    return sec_x, part_offset

        # 4. Brute-force heuristic scan (Fallback mechanism, specifically for corrupted partition tables)
        print("[Detector] [WARN] Partition tables failed. Attempting heuristic alignment scan...")
        # Common aligned sectors: 63(XP), 2048(Win7+), 8192(4MB aligned), 262144(128MB offset)
        for lba in [2048, 8192, 63, 262144]:
            ofs = lba * 512
            if r.size > ofs + 512:
                sec_x = r.read(ofs, 512)
                if len(sec_x) == 512 and sec_x[3:11] == b'NTFS    ':
                    print(f"[Detector] [INFO] Heuristic Match: Found NTFS at LBA {lba} (Offset: 0x{ofs:X})")
                    return sec_x, ofs

    except Exception as e:
        print(f"[Detector] [ERROR] Exception during partition parsing: {str(e)}")
        
    return None, 0

def detect(r):
    print(f"\n[Detector] Opening Volume Size: {r.size / (1024**3):.2f} GB (0x{r.size:X})\r")
    vbr_buffer, base_offset = get_vbr_sector(r)
    
    if vbr_buffer is None:
        print("[Detector] [FAILED] Could not find valid 'NTFS    ' signature in any standard partition entry headers.")
        return False
        
    boot_sig = vbr_buffer[510] | (vbr_buffer[511] << 8)
    if boot_sig != 0xAA55:
        print(f"[Detector] [FAILED] Found NTFS magic but boot sector signature 0x{boot_sig:04X} is broken.")
        return False
        
    print(f"[Detector] [SUCCESS] Target confirmed! NTFS File System parsed via base FOA offset: 0x{base_offset:X}")
    return True

def parse(r, root):
    file_size = r.size
    vbr_buffer, BASE_OFFSET = get_vbr_sector(r)
    
    if vbr_buffer is None:
        return

    # =========================================================
    # 1. Dynamic basic parameter conversion
    # =========================================================
    bytes_per_sector = vbr_buffer[11] | (vbr_buffer[12] << 8)
    sectors_per_cluster = vbr_buffer[13]
    cluster_size = bytes_per_sector * sectors_per_cluster
    
    def parse_u64(buf, offset):
        val = 0
        for i in range(8): val |= buf[offset + i] << (i * 8)
        return val

    total_sectors = parse_u64(vbr_buffer, 40)
    mft_lcn = parse_u64(vbr_buffer, 48)
    mft_mirr_lcn = parse_u64(vbr_buffer, 56)
    
    # Core physical landing offset = Partition absolute base address + Logical cluster physical span
    mft_foa = BASE_OFFSET + (mft_lcn * cluster_size)
    mft_mirr_foa = BASE_OFFSET + (mft_mirr_lcn * cluster_size)
    
    clusters_per_mft = vbr_buffer[64]
    mft_record_size = 1024
    if clusters_per_mft > 0x7F:
        mft_record_size = 1 << (256 - clusters_per_mft)
    else:
        mft_record_size = clusters_per_mft * cluster_size

    # If MBR exists, encapsulate and display the preceding 1MB area independently
    if BASE_OFFSET > 0:
        root.region("Master Boot Record (MBR) & Unallocated Sectors", 0, BASE_OFFSET, color=hx.GRAY)

    # Draw VBR tree
    with root.struct("NTFS Volume Boot Record", color=hx.BLUE) as vbr:
        vbr.seek(BASE_OFFSET)
        vbr.bytes("Jump Instruction", 3)
        vbr.bytes("OEM ID", 8, color=hx.YELLOW)
        
        with vbr.struct("BIOS Parameter Block", color=hx.GREEN) as bpb:
            bpb.u16("Bytes Per Sector", fmt=lambda v, val=bytes_per_sector: f"{val} bytes")
            bpb.u8("Sectors Per Cluster", fmt=lambda v, val=sectors_per_cluster: f"{val} sectors")
            bpb.u16("Reserved Sectors")
            bpb.bytes("Media Descriptor", 3)
            bpb.seek(bpb.tell() + 7)
            bpb.u64("Total Sectors", fmt=lambda v, val=total_sectors: f"{val} sectors ({val * bytes_per_sector / (1024**3):.2f} GB)")
            bpb.u64("$MFT Logical Cluster Number", fmt=lambda v, val=mft_lcn: f"{val} (FOA: 0x{mft_foa:X})")
            bpb.u64("$MFTMirr Logical Cluster Number", fmt=lambda v, val=mft_mirr_lcn: f"{val}")

        with vbr.struct("NTFS Data Pointer Jump Shortcuts", color=hx.ORANGE) as links:
            links.u64("Calculated Cluster Size", fmt=lambda v, c=cluster_size: f"{c} bytes")
            links.u64("Calculated MFT Record Size", fmt=lambda v, m=mft_record_size: f"{m} bytes")
            
            # Perfect crossover hyperlink! Double-click to instantly flash to the first byte of the Master File Table!
            links.u64("Jump to $MFT Start", color=hx.RED, target=mft_foa if mft_foa < file_size else None,
                      fmt=lambda v: f"[FOA: 0x{mft_foa:X}] -> Double Click to Jump Master File Table")

        vbr.seek(BASE_OFFSET + 510)
        vbr.u16("Signature", color=hx.YELLOW)

    if BASE_OFFSET + 512 < mft_foa < file_size:
        root.region("Partition Free Cluster Space", BASE_OFFSET + 512, mft_foa - (BASE_OFFSET + 512), color=hx.GRAY)

    # =========================================================
    # 2. Dynamic guided landing point: Master File Table ($MFT)
    # =========================================================
    if mft_foa < file_size:
        try:
            mft_magic = r.read(mft_foa, 4)
            print(f"[Parser] Successfully jumped to $MFT FOA: 0x{mft_foa:X}. Inspected Magic: {repr(mft_magic)}")
        except Exception as e:
            print(f"[Parser] [FAILED] Reading $MFT target error: {str(e)}")
            return

        if mft_magic == b'FILE':
            with root.struct("Master File Table: FILE0 Record ($MFT)", color=hx.PURPLE) as mft_node:
                mft_node.seek(mft_foa)
                mft_node.bytes("Magic Header", 4, color=hx.YELLOW)
                mft_node.region("Attributes Streams", mft_node.tell(), mft_record_size - 4, color=hx.GRAY)
        else:
            root.region("Master File Table Area (Raw)", mft_foa, mft_record_size, color=hx.GRAY)

hx.register("NTFS", detect, parse)
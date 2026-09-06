"""
JoHex Official Script: New Technology File System (NTFS) Parser
===============================================================
An industrial-grade forensic parser for raw NTFS volumes and disk images.
Features intelligent MBR/GPT partition routing, BIOS Parameter Block (BPB) decoding,
and LCN-to-FOA translation for instant jumps to the Master File Table ($MFT).

This is an officially maintained script distributed with JoHex.
Modification of this core script may affect built-in analysis features.
"""

# =================================================================
# Manifest Metadata (Used for auto-generating manifest.json)
# =================================================================
__id__          = "johex.parser.ntfs"
__name__        = "NTFS Parser"
__version__     = "1.4.1"
__author__      = "EJoyApp Team"
__category__    = "File System Parsers"
__description__ = '''
    "An industrial-grade forensic parser for raw NTFS volumes and disk images. "
    "Features intelligent MBR/GPT partition routing, BIOS Parameter Block (BPB) decoding, "
    "and LCN-to-FOA translation for instant jumps to the Master File Table ($MFT)."
'''
__features__    = '''
    "• Intelligent MBR/GPT partition routing"
    "• BIOS Parameter Block (BPB) decoding"
    "• LCN-to-FOA translation"
    "• Instant jumps to the Master File Table ($MFT)"
'''
__formats__     = ".ntfs, .img, .dd, .vhd, .vhdx"
__copyright__   = "Copyright (c) 2026 EJoyApp. All rights reserved."
__status__      = "Official / Built-in"
# =================================================================

import johexedit as hx
import struct

# Register static features (for AI or other static scanning tools)
# The true identifier is the OEM Name "NTFS    " at offset 0x03
MAGIC_BYTES = b"NTFS    "
SUPPORTED_EXTS = [".img", ".dd", ".bin", ".vhd", ".vhdx", ".ntfs"]
FORMAT_NAME = "NTFS File System Image"

def identify(hex_prefix: bytes, file_ext: str) -> int:
    """
    Detection function called by the C++ engine.
    Receives the first 4KB byte stream (hex_prefix) and the file extension.
    """
    # 1. An NTFS Boot Sector requires at least 11 bytes to read the OEM name,
    # but a full boot sector is typically 512 bytes.
    if len(hex_prefix) >= 11:
        
        # 2. Extract the OEM Name field at offset 0x03 (8 bytes long).
        # For NTFS, this must be exactly 'NTFS    ' (with four trailing spaces).
        oem_name = hex_prefix[3:11]
        
        if oem_name == MAGIC_BYTES:
            
            # 3. Check for the standard boot sector signature (0x55 0xAA) at offset 0x1FE (510).
            # Use struct to unpack as a little-endian 16-bit unsigned integer (<H).
            if len(hex_prefix) >= 512:
                boot_signature = struct.unpack_from("<H", hex_prefix, 510)[0]
                
                if boot_signature == 0xAA55:
                    
                    # 4. (Optional but good) Validate the Bytes Per Sector at offset 0x0B
                    # Usually 512 (0x0200) or 4096 (0x1000).
                    bps = struct.unpack_from("<H", hex_prefix, 0x0B)[0]
                    if bps in (512, 1024, 2048, 4096):
                        return 100  # 100% certainty that it is an NTFS volume/image
                    
                    # Magic bytes match, but bytes per sector is unusual
                    return 90
                
                # OEM Name matches, but the end-of-sector signature is missing or corrupted
                return 80
                
            # The file is severely truncated (less than a single sector), but has the NTFS OEM name
            return 50
            
    return 0

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
    # 2. OPTIMIZED MFT CARVING (Fast Deleted Files Recovery)
    # =========================================================
    if mft_foa < file_size:
        with root.struct("Recovered Deleted Files (Fast Carving)", color=hx.ORANGE) as recovery_node:
            # Starting directly from the $MFT physical starting point, only scan 50MB (enough to cover the MFT table of 50,000 files)
            chunk_size = 16 * 1024 * 1024
            overlap = mft_record_size
            
            cursor = mft_foa
            scan_limit = min(file_size, mft_foa + 50 * 1024 * 1024) # <--- 只扫 50MB
            
            deleted_count = 0
            scanned_records = 0
            total_scan_size = scan_limit - mft_foa
            
            while cursor < scan_limit:
                if hasattr(r, 'update_status'):
                    progress = int(((cursor - mft_foa) / total_scan_size) * 100)
                    r.update_status(f"Deep scanning MFT: {progress}% (Recovered: {deleted_count})...")
                read_size = min(chunk_size + overlap, scan_limit - cursor)
                if read_size <= 0: break
                
                chunk = r.read(cursor, read_size)
                if not chunk: break
                
                idx = 0
                while True:
                    idx = chunk.find(b'FILE', idx)
                    if idx == -1: break
                    
                    if idx + mft_record_size <= len(chunk):
                        record = chunk[idx : idx + mft_record_size]
                        
                        usa_off = struct.unpack_from("<H", record, 0x04)[0]
                        attr_off = struct.unpack_from("<H", record, 0x14)[0]
                        flags = struct.unpack_from("<H", record, 0x16)[0]
                        
                        if usa_off in (0x28, 0x30) and attr_off in (0x30, 0x38):
                            scanned_records += 1
                            
                            if scanned_records % 5000 == 0 and hasattr(r, 'update_status'):
                                r.update_status(f"Analyzing MFT records... ({scanned_records} scanned)")
                                
                            # (flags & 1) == 0 This indicates that the file has been deleted.
                            if (flags & 1) == 0:
                                file_name = f"recovered_{deleted_count}.bin"
                                data_foa = 0
                                data_length = 0
                                
                                p = attr_off
                                while p + 8 <= mft_record_size:
                                    attr_type = struct.unpack_from("<I", record, p)[0]
                                    if attr_type == 0xFFFFFFFF: break
                                    
                                    attr_len = struct.unpack_from("<I", record, p+4)[0]
                                    if attr_len <= 0 or p + attr_len > mft_record_size: break
                                    non_resident = record[p+8]
                                    
                                    if attr_type == 0x30 and non_resident == 0:
                                        name_len = record[p+0x58]
                                        if name_len > 0 and p + 0x5A + name_len*2 <= mft_record_size:
                                            try:
                                                decoded = record[p+0x5A : p+0x5A + name_len*2].decode('utf-16le', 'ignore')
                                                if decoded: file_name = decoded
                                            except: pass
                                            
                                    elif attr_type == 0x80:
                                        if non_resident == 0:
                                            res_len = struct.unpack_from("<I", record, p+0x10)[0]
                                            res_off = struct.unpack_from("<H", record, p+0x14)[0]
                                            if p + res_off + res_len <= mft_record_size:
                                                data_foa = (cursor + idx) + p + res_off
                                                data_length = res_len
                                        else:
                                            runlist_off = struct.unpack_from("<H", record, p+0x20)[0]
                                            actual_size = struct.unpack_from("<Q", record, p+0x30)[0]
                                            run_p = p + runlist_off
                                            if run_p < p + attr_len:
                                                header = record[run_p]
                                                if header != 0:
                                                    len_len = header & 0x0F
                                                    off_len = header >> 4
                                                    if 0 < len_len <= 8 and 0 < off_len <= 8:
                                                        run_len_bytes = record[run_p+1 : run_p+1+len_len] + b'\x00'*8
                                                        run_len = struct.unpack_from("<Q", run_len_bytes, 0)[0]
                                                        
                                                        run_off_bytes = record[run_p+1+len_len : run_p+1+len_len+off_len]
                                                        lcn = int.from_bytes(run_off_bytes, 'little', signed=True)
                                                        
                                                        data_foa = BASE_OFFSET + lcn * cluster_size
                                                        data_length = min(actual_size, run_len * cluster_size)
                                    p += attr_len
                                    
                                if data_length > 0 and data_foa > 0:
                                    safe_name = "".join(c for c in file_name if c.isalnum() or c in ".-_ ")
                                    recovery_node.seek(data_foa)
                                    recovery_node.region(f"[EXTRACT:raw]RECOVER_{safe_name}", data_foa, data_length, color=hx.RED)
                                    deleted_count += 1
                                    
                            idx += mft_record_size
                            continue
                            
                    idx += 4
                    
                cursor += chunk_size
                if deleted_count >= 150: break
                
            if hasattr(r, 'update_status'):
                r.update_status("Ready")
            if deleted_count == 0:
                recovery_node.region(f"Scanned {scanned_records} MFT records. No recoverable files found.", 0, 0, color=hx.GRAY)

hx.register("NTFS", detect, parse)
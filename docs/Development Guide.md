
# JoHex HexEditor Parsing Script Development Official Guide

[**English**](./Development%20Guide.md) | [简体中文](./Development%20Guide.zh_CN.md)

The core logic of writing a parsing script is to convert tedious binary data into a human-readable Tree UI structure. Our engine utilizes a hybrid architecture of **"Python-scripted detection/parsing + C++ underlying ultra-fast rendering"**, striking a perfect balance between high extensibility and outstanding performance.

## 1. The Script Skeleton

Every valid parsing script must contain three core components: a **Detector (detect)**, a **Parser (parse)**, and a **Registration Hook (register)**.

```python
import johexedit as hx

def detect(r):
    # 'r' is a Reader object used for physical offset probing.
    # Return True if the script claims the file, False to skip.
    if r.size < 4:
        return False
    return r.u32(0) == 0x04034B50  # e.g., checking ZIP magic number

def parse(r, root):
    # 'r' is a Reader object for fetching data.
    # 'root' is a Scope object for building the UI tree.
    with root.struct("My File Header", color=hx.BLUE) as hdr:
        hdr.u32("Signature", color=hx.YELLOW)

# Register the script to the C++ engine
hx.register("MyFormat", detect, parse)
```

## 2. API Reference

The engine exports two primary classes to the Python environment: **Reader** (for reading data) and **Scope** (for drawing the interface), along with a set of preset color constants.

### 🎨 Color System

Built-in constants used to highlight the hex view and tree nodes, accessed directly via `hx.`:

- `hx.RED`, `hx.GREEN`, `hx.BLUE`
- `hx.YELLOW`, `hx.PURPLE`, `hx.GRAY`

### 🔎 Reader Class (Absolute Physical Accessor)

The Reader maintains no cursor state and is dedicated to reading from an **Absolute Physical Offset (FOA)**. It is ideal for use during the `detect` phase or for "peeking" at distant data within `parse`.

| Method / Property | Description |
| --- | --- |
| `r.size` | (Property) Gets the total byte size of the file (supports ultra-large files). |
| `r.read(offset, len)` | Reads a specified length of bytes, returning a native Python `bytes` object. |
| `r.u8(offset)` | Reads a 1-byte unsigned integer. |
| `r.u16(offset, le=True)` | Reads a 2-byte integer. `le=True` for Little-Endian (default), `le=False` for Big-Endian. |
| `r.u32(offset, le=True)` | Reads a 4-byte integer. |
| `r.u64(offset, le=True)` | Reads an 8-byte integer. |

### 🌳 Scope Class (UI Tree Builder)

The Scope is a stateful object with a built-in **Cursor**. Each time a field parsing function is called, the cursor automatically advances by the corresponding number of bytes.

**Basic Properties and Cursor Control:**

- `s.tell()`: Gets the current position of the parsing cursor.
- `s.seek(offset)`: Forces the cursor to jump to a new position.

**UI Node Insertion (Auto-advances cursor):**

- `s.u8(name, color=None, fmt=None)`
- `s.u16(name, le=True, color=None, fmt=None)`
- `s.u32(name, le=True, color=None, fmt=None)`
- `s.field(name, nbytes, le=True, color=None, fmt=None)`: Universal integer reading (supports 1–8 bytes).
- `s.raw(name, len, color=None)`: Reads a sequence of raw bytes and displays it as a distinct node.

**Structures and Regions (Hierarchy Management):**

- `s.struct(name, color=None)`: Context Manager. Used to create collapsible tree node folders.
- `s.region(name, offset, len, color=None)`: Creates an independent data block marker without affecting the current cursor. Often used to encapsulate massive unparsed data or compressed streams.
- `s.lazy(name, offset, len, maker, color=None)`: Lazy Loading Node. For structures containing massive amounts of child items (e.g., millions), the `maker` callback function to render the internal tree is only triggered when the user clicks the "+" icon on the UI to expand it, greatly improving interface loading performance.

## 3. File Stream Processing & Advanced Techniques

### Technique A: Powerful Dynamic Formatting (fmt)

A hex editor shouldn't just display numbers; it needs to explain what they mean. By passing a lambda expression to the `fmt` parameter, you can dynamically translate dry integers into readable text:

```python
# Original display: 1 (0x01)
# Display with fmt: 1 (Read-Only)
node.u8("File Attribute", fmt=lambda v: "Read-Only" if v == 1 else "Normal")

# Display as Hex with explanation attached
node.u32("Magic", fmt=lambda v: f"0x{v:08X} (Valid Signature)")
```

### Technique B: Large File Safety (Python Memory Buffer Stream)

When dealing with disk image files ranging from tens of GBs to TBs, frequent cross-language single-byte reads (like `r.u8()`) will cause severe performance degradation and may even trigger underlying integer overflows. **Recommended approach: Read bulk slices into memory.**

```python
# Recommended: Read the required block into Python memory all at once
try:
    buf = r.read(0, 512)
    # Perform native, ultra-fast bitwise operations in pure Python memory
    boot_signature = buf[510] | (buf[511] << 8)
except Exception as e:
    return False
```

### Technique C: Preventing Infinite Loops & Pointer Overflows (Defensive Programming)

When reverse-engineering maliciously crafted files (or corrupted disks), the size field of a file record might be 0 or maliciously exceed the total file size, causing the parser to fall into an infinite loop or memory out-of-bounds. You must use the standard defensive paradigm when parsing variable-length lists:

```python
while cursor < file_size:
    item_size = r.u32(cursor)

    # 1. Prevent Infinite Loops: Size must be strictly greater than 0
    # 2. Prevent Overflows: Current cursor + declared size must not exceed physical bounds
    if item_size == 0 or cursor + item_size > file_size:
        root.region("Malformed Data", cursor, file_size - cursor, color=hx.GRAY)
        break

    cursor += item_size
```


# JoHex 十六进制解析脚本开发官方指南

[**English**](./Development%20Guide.md) | [简体中文](./Development%20Guide.zh_CN.md)

编写解析脚本的核心逻辑是将枯燥的二进制数据转换为人类可读的树状结构 UI。我们的引擎采用了 **“Python 脚本化探测与解析 + C++ 底层极速渲染”** 的混合架构，兼顾了极高的扩展性与卓越的性能。

## 1. 脚本基础骨架

每一个合法的解析脚本都必须包含三个核心部分：**探测器 (detect)**、**解析器 (parse)** 以及 **注册钩子 (register)**。

```python
import johexedit as hx

def detect(r):
    # r 是 Reader 对象，用于物理寻址探测
    # 返回 True 表示该脚本认领此文件，False 则跳过
    if r.size < 4:
        return False
    return r.u32(0) == 0x04034B50  # 例如检查 ZIP 魔数

def parse(r, root):
    # r 是 Reader 对象，用于获取数据
    # root 是 Scope 对象，用于构建 UI 树
    with root.struct("My File Header", color=hx.BLUE) as hdr:
        hdr.u32("Signature", color=hx.YELLOW)

# 将脚本注册到 C++ 引擎
hx.register("MyFormat", detect, parse)
```

## 2. API 参考手册

引擎向 Python 环境导出了两个最重要的类：**Reader**（负责读数据）和 **Scope**（负责画界面），以及一系列预设颜色常量。

### 🎨 颜色系统 (Colors)

内置常量，用于高亮十六进制视图和树节点，直接通过 `hx.` 调用：

- `hx.RED`, `hx.GREEN`, `hx.BLUE`
- `hx.YELLOW`, `hx.PURPLE`, `hx.GRAY`

### 🔎 Reader 类 (绝对物理访问器)

Reader 不保存任何游标状态，专门用于**绝对物理偏移 (FOA)** 的定点读取。非常适合在 `detect` 阶段使用，或在 `parse` 中“偷看”远端数据。

| 方法 / 属性 | 说明 |
| --- | --- |
| `r.size` | （属性）获取文件总字节数（支持超大文件）。 |
| `r.read(offset, len)` | 读取指定长度的字节，返回 Python 原生 `bytes` 对象。 |
| `r.u8(offset)` | 读取 1 字节无符号整数。 |
| `r.u16(offset, le=True)` | 读取 2 字节整数。`le=True` 为小端序（默认），`le=False` 为大端序。 |
| `r.u32(offset, le=True)` | 读取 4 字节整数。 |
| `r.u64(offset, le=True)` | 读取 8 字节整数。 |

### 🌳 Scope 类 (UI 树构建器)

Scope 是带有内置**游标 (Cursor)** 的有状态对象。每次调用字段解析函数，游标都会自动向下移动相应的字节数。

**基础属性与游标控制：**

- `s.tell()`：获取当前解析游标的位置。
- `s.seek(offset)`：强制将游标跳转到新位置。

**UI 节点插入（自动移动游标）：**

- `s.u8(name, color=None, fmt=None)`
- `s.u16(name, le=True, color=None, fmt=None)`
- `s.u32(name, le=True, color=None, fmt=None)`
- `s.field(name, nbytes, le=True, color=None, fmt=None)`：通用整型读取（支持 1–8 字节）。
- `s.raw(name, len, color=None)`：读取一串原始字节并作为独立节点展示。

**结构与区块（层级管理）：**

- `s.struct(name, color=None)`：上下文管理器。用于创建可折叠的树节点文件夹。
- `s.region(name, offset, len, color=None)`：创建一个独立的数据区块标记，不影响当前游标。常用于打包海量未解析数据或压缩流。
- `s.lazy(name, offset, len, maker, color=None)`：延迟加载节点。针对包含海量（如百万级）子项的结构，只有在用户点击 UI 上的“+”号展开时，才会触发 `maker` 回调函数去渲染内部树，极大提升界面加载性能。

## 3. 文件流处理与高级技巧

### 技巧 A：强大的 fmt 动态格式化

十六进制编辑器不仅需要展示数字，更需要解释数字的含义。通过传入 lambda 表达式给 `fmt` 参数，你可以将枯燥的整数动态翻译为易读的文本：

```python
# 原始展示: 1 (0x01)
# 使用 fmt 后展示: 1 (Read-Only)
node.u8("File Attribute", fmt=lambda v: "Read-Only" if v == 1 else "Normal")

# 展示为十六进制并携带解释
node.u32("Magic", fmt=lambda v: f"0x{v:08X} (Valid Signature)")
```

### 技巧 B：大文件安全防御 (Python 内存缓冲流)

当面对几十 GB 甚至 TB 级别的磁盘镜像文件时，频繁进行跨语言的单字节读取（如 `r.u8()`）会导致严重的性能损耗，甚至触发底层溢出。**推荐做法：批量切片放入内存处理。**

```python
# 推荐做法：一次性将所需的块读入 Python 内存
try:
    buf = r.read(0, 512)
    # 在纯 Python 内存中进行原生极速位运算，脱离 C++ 跨界调用
    boot_signature = buf[510] | (buf[511] << 8)
except Exception as e:
    return False
```

### 技巧 C：防死循环与指针飞坡 (防御性编程)

在逆向恶意构造的文件（或损坏的磁盘）时，文件记录的大小字段可能为 0 或恶意超出文件总大小，这会导致解析器陷入死循环或内存越界。解析变长列表时必须使用标准防御范式：

```python
while cursor < file_size:
    item_size = r.u32(cursor)

    # 1. 防死循环：大小必须大于 0
    # 2. 防溢出：当前游标 + 声明大小 不能超过文件总物理边界
    if item_size == 0 or cursor + item_size > file_size:
        root.region("Malformed Data", cursor, file_size - cursor, color=hx.GRAY)
        break

    cursor += item_size
```

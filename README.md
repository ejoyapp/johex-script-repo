# JoHex Official Script Repository

Welcome to the **JoHex Script Repository**! This is the centralized hosting library for Python auxiliary analysis scripts designed specifically for the advanced hex editor, **JoHex**.

Through these Python scripts, JoHex greatly expands its core parsing capabilities, helping users intuitively deep-dive, visualize, and map various complex binary data structures and low-level storage systems directly within the editor.

---

## 🔗 Links and Resources
| Type                            | Links                               |
| ------------------------------- | --------------------------------------- |
| 💼 **Documentation**              | [Development Guide](https://github.com/ejoyapp/johex-script-repo/blob/main/docs/Development%20Guide.md)


## 🧩 Supported Analysis Domains

This repository is dedicated to collecting and maintaining high-quality binary analysis scripts, currently covering the following main areas:

* **📄 File Formats:**
    * **Executables:** Windows PE (`.exe`, `.dll`, `.sys`), ELF, etc.
    * **Multimedia:** Deep structural unpacking of MP4, PNG, JPG, GIF.
    * **Archives:** ZIP, RAR structure analysis.
* **💽 File Systems & Disks:**
    * **Windows Ecosystem:** NTFS (MFT record parsing), FAT, FAT32, exFAT.
    * **Linux/Unix Ecosystem:** Low-level structural exploration and forensic analysis of ext4, etc.

---

## 📂 Directory Structure Overview

To ensure efficient client-side fetching and clean data organization, this repository adopts a structure that separates data configuration from physical files:

```text
johex-script-repo/
├── manifests/
│   └── index.json       <-- The only manifest file the JoHex client needs to fetch
├── scripts/
│   ├── pe_parser.py     <-- The actual Python analysis script files
│   ├── elf_parser.py
│   └── hex_enhancer.py
└── README.md

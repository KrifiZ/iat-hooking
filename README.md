# PE Header Parser & API Hooking

A Windows application that parses PE (Portable Executable) headers and demonstrates API hooking by intercepting MessageBoxA calls.

## Features

- Parses DOS, NT, and optional headers from PE executable
- Identifies imported DLLs and functions via Import Address Table (IAT)
- Detects 32-bit vs 64-bit executables
- Demonstrates runtime API hooking by replacing MessageBoxA with custom handler
- Uses VirtualProtect to modify write-protected IAT entries

## Building

Compile with Visual Studio or MSVC compiler with Windows SDK headers.

## Learning Goals

Understanding low-level Windows structures:
- PE format and header structure
- DOS header (e_magic, e_lfanew)
- NT headers (optional header, magic field)
- Import Directory Table (IDT)
- Import Address Table (IAT)
- Thunk data structures
- Memory protection and RWX permissions

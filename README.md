# WinNoStd-Locator

A modular, strict `#![no_std]` Rust library designed for minimalist execution environments, security research, and advanced evasion techniques on Windows x64.

This library allows you to dynamically locate loaded modules in memory and manually parse the Export Address Table (EAT) of a Portable Executable (PE) image. This approach effectively bypasses conventional Windows API monitoring mechanisms such as hooks on `GetModuleHandle` and `GetProcAddress`.

## Features

* **Strict `#![no_std]` Environment:** Zero reliance on the Rust standard library (`std`) or heavy runtimes. Built specifically for reflective code injection, shellcode development, and native payloads.
* **TEB/PEB Obfuscation via Inline Assembly:** Utilizes dynamic x86_64 assembly routines to retrieve the Process Environment Block (PEB), manipulating offsets at runtime to evade common heuristic detection rules.
* **Manual EAT Parsing:** Traverses PE structures step-by-step to locate exported symbols manually via Relative Virtual Addresses (RVAs).
* **Full Export Forwarder Support:** Automatically handles and resolves forwarded functions, ensuring compatibility with exports that point across different modules (such as internal redirects between `kernel32.dll` and `ntdll.dll`).
* **Compile-Time DJB2 Hashing:** Provides a dedicated macro (`dbj2!`) and a `const fn` hashing mechanism to facilitate API hashing. This cleanses the final binary from human-readable API string signatures.
* **Safe Memory Utilities:** Independent, lightweight string matching helpers optimized to handle `UNICODE_STRING` (UTF-16) and ASCII buffers without any dynamic memory allocations.

## Architecture and Design

The repository is organized into five core components:

1. **Undocumented Structures:** Native, C-compatible (`#[repr(C)]`) layouts for `PEB_LDR_DATA` and `LDR_DATA_TABLE_ENTRY`.
2. **String Utilities:** Custom routines for raw case-insensitive string matching to navigate Windows module strings safely.
3. **API Hashing (DJB2):** A compile-time hashing module designed to mask vulnerable API strings into static `u32` integers.
4. **PEB Walker:** A manual link-list parser traversing the native loader lists (`InLoadOrderModuleList`) to identify running modules.
5. **EAT Parser:** A structural PE analyst mapping out exported address tables, ordinals, and forwarder references.

## Usage

Add the required definitions to your workspace. Ensure your build environment targets the 64-bit Windows ecosystem (`x86_64-pc-windows-msvc`).

### Resolving Functions Manually

```rust
use win_nostd_locator::{get_module_base, get_proc_address};

fn main() {
    unsafe {
        // 1. Obtain the base address of a DLL by traversing the PEB
        let ntdll_base = get_module_base("ntdll.dll");
        if ntdll_base.is_null() {
            return;
        }

        // 2. Locate an exported function address manually by parsing the EAT
        let nt_query_ptr = get_proc_address(ntdll_base as *const u8, "NtQuerySystemInformation");
        
        if !nt_query_ptr.is_null() {
            // Function pointer successfully resolved.
            // You can now cast it to the target function signature.
        }
    }
}
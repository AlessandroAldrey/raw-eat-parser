#![no_std]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr::null_mut;
use core::slice;
use core::str;
use core::arch::asm;

use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, 
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_DIRECTORY_ENTRY_EXPORT
};
use windows_sys::Win32::Foundation::{UNICODE_STRING, BOOLEAN};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;

// 1. Undocumented Structures

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: BOOLEAN,
    pub SsHandle: *mut c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

// 2. String utilities
unsafe fn c_strlen(ptr: *const u8) -> usize {
    let mut len = 0;
    while *ptr.add(len) != 0 { len += 1; }
    len
}

unsafe fn str_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    for i in 0..a.len() {
        let mut c1 = a[i];
        let mut c2 = b[i];
        if c1 >= b'A' && c1 <= b'Z' { c1 += 32; }
        if c2 >= b'A' && c2 <= b'Z' { c2 += 32; }
        if c1 != c2 { return false; }
    }
    true
}

unsafe fn utf16_matches_ascii(utf16_ptr: *const u16, utf16_len: usize, ascii: &[u8]) -> bool {
    if utf16_len < ascii.len() { return false; }
    for i in 0..ascii.len() {
        let w = *utf16_ptr.add(i) as u8;
        let a = ascii[i];
        let w_low = if w >= b'A' && w <= b'Z' { w + 32 } else { w };
        let a_low = if a >= b'A' && a <= b'Z' { a + 32 } else { a };
        if w_low != a_low { return false; }
    }
    true
}


// 3. API Hashing
pub const fn hash_djb2(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    
    while i < s.len() {
        let mut c = s[i] as u32;
        
        if c >= b'A' as u32 && c <= b'Z' as u32 {
            c += 32;
        }

        hash = ((hash << 5).wrapping_add(hash)) ^ c;
        i += 1;
    }
    hash
}

#[macro_export]
macro_rules! dbj2 {
    ($s:literal) => {
        $crate::hash_djb2($s.as_bytes())
    };
}

// 4. PEB WALKING
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn get_peb_from_teb() -> *const c_void {
    let teb_addr: usize;
    let peb_addr: usize;
    let mut offset_teb: u64 = 0x10;

    core::arch::asm!("nop");
    offset_teb = offset_teb.wrapping_add(0x20);
    core::arch::asm!(
        "mov {teb}, gs:[{off}]",
        teb = out(reg) teb_addr,
        off = in(reg) offset_teb 
    );

    let mut jump_to_peb = 0x55;
    jump_to_peb += 0x0B;

    core::arch::asm!("xor r11, r11");
    peb_addr = teb_addr.wrapping_add(jump_to_peb);
    peb_addr as *const c_void
}

pub unsafe fn get_module_base(name: &str) -> *const c_void {
    let peb = get_peb_from_teb();
    let ldr_ptr = *(peb.add(0x18) as *const *mut PEB_LDR_DATA);
    
    let head = &(*ldr_ptr).InLoadOrderModuleList as *const LIST_ENTRY;
    let mut curr = (*head).Flink;

    while curr as *const _ != head {
        let entry = curr as *const LDR_DATA_TABLE_ENTRY;
        let buffer = (*entry).BaseDllName.Buffer;
        let len = ((*entry).BaseDllName.Length / 2) as usize;

        if !buffer.is_null() {
            if utf16_matches_ascii(buffer, len, name.as_bytes()) {
                return (*entry).DllBase;
            }
        }
        curr = (*curr).Flink;
    }
    null_mut()
}

// 5. EAT PARSER
pub unsafe fn get_proc_address(base: *const u8, func_name: &str) -> *const c_void {
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE { return null_mut(); } // Usamos constante de windows-sys

    let nt_headers = base.offset((*dos).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE { return null_mut(); }

    let export_dir_info = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_rva = export_dir_info.VirtualAddress;
    let export_size = export_dir_info.Size;

    if export_rva == 0 { return null_mut(); }

    let export_dir = base.add(export_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    
    let num_names = (*export_dir).NumberOfNames;
    let names = base.add((*export_dir).AddressOfNames as usize) as *const u32;
    let ordinals = base.add((*export_dir).AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add((*export_dir).AddressOfFunctions as usize) as *const u32;

    let dir_start = base.add(export_rva as usize) as usize;
    let dir_end = dir_start + export_size as usize;

    for i in 0..num_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = base.add(name_rva as usize);
        let name_len = c_strlen(name_ptr);
        let name_slice = slice::from_raw_parts(name_ptr, name_len);

        if str_eq_ignore_case(name_slice, func_name.as_bytes()) {
            let ordinal = *ordinals.add(i as usize);
            let func_rva = *funcs.add(ordinal as usize);
            let func_ptr = base.add(func_rva as usize);

            if (func_ptr as usize) >= dir_start && (func_ptr as usize) < dir_end {
                return resolve_forwarder(func_ptr);
            }
            return func_ptr as *const c_void;
        }
    }
    null_mut()
}

unsafe fn resolve_forwarder(ptr: *const u8) -> *const c_void {
    let len = c_strlen(ptr);
    let full_str = slice::from_raw_parts(ptr, len);
    
    let mut split_idx = 0;
    for (i, &b) in full_str.iter().enumerate() {
        if b == b'.' { split_idx = i; break; }
    }
    if split_idx == 0 { return null_mut(); }

    let dll_bytes = &full_str[..split_idx];
    let func_bytes = &full_str[split_idx + 1..];

    let dll_name = str::from_utf8_unchecked(dll_bytes);
    let func_name = str::from_utf8_unchecked(func_bytes);

    let target_base = get_module_base(dll_name);
    if !target_base.is_null() {
        return get_proc_address(target_base as *const u8, func_name);
    }
    null_mut()
}

// =============================================================
// PANIC
// =============================================================
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_eat_walker() {
        unsafe {
            // 1. Get base address of ntdll.dll
            let ntdll_name = "ntdll.dll";
            let base = get_module_base(ntdll_name);
            assert!(!base.is_null(), "Failed to get base address of ntdll.dll");

            // 2. Get address of a known function from ntdll.dll
            let func_name = "NtQuerySystemInformation";
            let addr = get_proc_address(base as *const u8, func_name);
            assert!(!addr.is_null(), "Failed to get address of NtQuerySystemInformation");
        }
    }
}
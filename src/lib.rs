#![allow(warnings)]
#![no_std]

use core::arch::asm;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::slice;
use core::str;

use windows_sys::Win32::Foundation::{BOOLEAN, UNICODE_STRING};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};

// 1. Undocumented Structures
pub const HASH_SEED: u32 = 0x811C9DC5;
pub const HASH_KEY: u32 = 31;

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: BOOLEAN,
    pub SsHandle: *mut c_void,
    pub InLoadOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct PEB {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub is_being_debugged: u8,
    pub bit_field: u8,
    pub padding_0: [u8; 4],
    pub mutant: *mut c_void,
    pub image_base_address: *mut c_void,
    pub ldr: *mut PEB_LDR_DATA,
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
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

unsafe fn str_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        let mut c1 = a[i];
        let mut c2 = b[i];
        if c1 >= b'A' && c1 <= b'Z' {
            c1 += 32;
        }
        if c2 >= b'A' && c2 <= b'Z' {
            c2 += 32;
        }
        if c1 != c2 {
            return false;
        }
    }
    true
}

unsafe fn utf16_matches_ascii(utf16_ptr: *const u16, utf16_len: usize, ascii: &[u8]) -> bool {
    let mut i = 0;
    while i < ascii.len() {
        if i >= utf16_len {
            return false;
        }
        let w = *utf16_ptr.add(i) as u8;
        let a = ascii[i];
        let w_low = if w >= b'A' && w <= b'Z' { w + 32 } else { w };
        let a_low = if a >= b'A' && a <= b'Z' { a + 32 } else { a };
        if w_low != a_low {
            return false;
        }
        i += 1;
    }

    // if .dll is in place check the end of the whole word
    if i < utf16_len {
        let next_char = *utf16_ptr.add(i) as u8;
        if next_char != 0 && next_char != b'.' {
            return false;
        }
    }
    true
}

// 3. API Hashing
pub const fn hash_djb2_custom(s: &[u8]) -> u32 {
    let mut hash: u32 = HASH_SEED;
    let mut i = 0;

    while i < s.len() {
        let mut c = s[i] as u32;
        if c >= b'A' as u32 && c <= b'Z' as u32 {
            c += 32;
        }

        hash = (hash.wrapping_mul(HASH_KEY)) ^ c;
        i += 1;
    }
    hash
}

#[macro_export]
macro_rules! dbj2 {
    ($s:literal) => {
        $crate::hash_djb2_custom($s.as_bytes())
    };
}

// 4. PEB WALKING
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn get_peb_from_teb() -> *const PEB {
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

    // Dummy math operations to change signature)
    let mut jump_to_peb = 0x55;
    jump_to_peb += 0x0B;

    // Dummy CPU cycles
    core::arch::asm!("xor r11, r11");
    peb_addr = teb_addr.wrapping_add(jump_to_peb);

    *(peb_addr as *const *const PEB)
}

pub unsafe fn get_module_base_by_hash(target_hash: u32) -> *const c_void {
    let peb_ptr = get_peb_from_teb();
    if peb_ptr.is_null() || (*peb_ptr).ldr.is_null() {
        return null_mut();
    }

    let ldr_ptr = (*peb_ptr).ldr;
    let head = &(*ldr_ptr).InLoadOrderModuleList as *const LIST_ENTRY;
    let mut curr = (*head).Flink;

    while curr as *const _ != head {
        if curr.is_null() {
            break;
        }

        let entry = curr as *const LDR_DATA_TABLE_ENTRY;
        let buffer = (*entry).BaseDllName.Buffer;
        let len = ((*entry).BaseDllName.Length / 2) as usize;

        if !buffer.is_null() && len > 0 {
            let mut raw_bytes = [0u8; 64];
            let safe_len = if len > 64 { 64 } else { len };

            for i in 0..len {
                let c_wide = *buffer.add(i);
                let mut c = c_wide as u8;

                if c >= b'A' && c <= b'Z' {
                    c += 32;
                }
                raw_bytes[i] = c;
            }
            let current_hash = hash_djb2_custom(&raw_bytes[..safe_len]);

            if current_hash == target_hash {
                return (*entry).DllBase;
            }
        }
        curr = (*curr).Flink;
    }
    null_mut()
}

pub unsafe fn get_module_base(name: &str) -> *const c_void {
    let peb_ptr = get_peb_from_teb();
    if peb_ptr.is_null() || (*peb_ptr).ldr.is_null() {
        return null_mut();
    }

    let ldr_ptr = (*peb_ptr).ldr;
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

// 5. EAT Parser
pub unsafe fn get_proc_address_by_hash(base: *const u8, target_hash: u32) -> *const c_void {
    if base.is_null() {
        return null_mut();
    }

    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    let nt_headers = base.offset((*dos).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return null_mut();
    }

    let export_dir_info =
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    let export_rva = export_dir_info.VirtualAddress;
    let export_size = export_dir_info.Size;

    if export_rva == 0 {
        return null_mut();
    }

    let export_dir = base.add(export_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let num_names = (*export_dir).NumberOfNames;
    let names = base.add((*export_dir).AddressOfNames as usize) as *const u32;
    let ordinals = base.add((*export_dir).AddressOfNameOrdinals as usize) as *const u16;
    let funcs = base.add((*export_dir).AddressOfFunctions as usize) as *const u32;

    // Forwarders Limit
    let dir_start = base.add(export_rva as usize) as usize;
    let dir_end = dir_start + export_size as usize;

    for i in 0..num_names {
        let name_rva = *names.add(i as usize);
        let name_ptr = base.add(name_rva as usize);
        let name_len = c_strlen(name_ptr);
        let name_slice = slice::from_raw_parts(name_ptr, name_len);

        let current_hash = hash_djb2_custom(name_slice);

        if current_hash == target_hash {
            let ordinal = *ordinals.add(i as usize);
            let func_rva = *funcs.add(ordinal as usize);
            let func_ptr = base.add(func_rva as usize);

            // Forwarder Check
            if (func_ptr as usize) >= dir_start && (func_ptr as usize) < dir_end {
                return resolve_forwarder_by_hash(func_ptr);
            }
            return func_ptr as *const c_void;
        }
    }
    null_mut()
}

unsafe fn resolve_forwarder_by_hash(ptr: *const u8) -> *const c_void {
    let len = c_strlen(ptr);
    let full_str = slice::from_raw_parts(ptr, len);

    let mut split_idx = 0;
    for (i, &b) in full_str.iter().enumerate() {
        if b == b'.' {
            split_idx = i;
            break;
        }
    }
    if split_idx == 0 {
        return null_mut();
    }

    let dll_bytes = &full_str[..split_idx];
    let func_bytes = &full_str[split_idx + 1..];

    let dll_name = str::from_utf8_unchecked(dll_bytes);

    let mut target_base = get_module_base(dll_name);

    if target_base.is_null() {
        let mut fallback_buffer = [0u8; 32];
        if dll_bytes.len() < 28 {
            fallback_buffer[..dll_bytes.len()].copy_from_slice(dll_bytes);
            fallback_buffer[dll_bytes.len()..dll_bytes.len() + 4].copy_from_slice(b".dll");
            if let Ok(fallback_name) = str::from_utf8(&fallback_buffer[..dll_bytes.len() + 4]) {
                target_base = get_module_base(fallback_name);
            }
        }
    }

    if !target_base.is_null() {
        let target_func_hash = hash_djb2_custom(func_bytes);
        return get_proc_address_by_hash(target_base as *const u8, target_func_hash);
    }
    null_mut()
}

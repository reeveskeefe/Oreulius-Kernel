/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! ELF loader for native binaries (ELF32 and ELF64, basic ET_DYN support).

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::{size_of, MaybeUninit};
use core::ptr;

use crate::arch::mmu::{self as arch_mmu, AddressSpace};
use crate::paging::{PAGE_SIZE, USER_TOP};
use crate::process::{self, ProcessPriority};
use crate::quantum_scheduler::{self, UserProcessLayout, UserRegionSpec, VmaFlags, VmaKind};

const EI_NIDENT: usize = 16;
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

// e_machine values
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const PF_X: u32 = 1;
const PF_W: u32 = 2;

// ELF32 dynamic tags
const DT_NULL: u32 = 0;
const DT_REL: u32 = 17;
const DT_RELSZ: u32 = 18;
const DT_RELENT: u32 = 19;
const DT_RELA: u32 = 7;
const DT_RELASZ: u32 = 8;
const DT_JMPREL: u32 = 23;

// ELF64 dynamic tags (same numeric value, wider fields)
const DT64_NULL: u64 = 0;
const DT64_REL: u64 = 17;
const DT64_RELSZ: u64 = 18;
const DT64_RELENT: u64 = 19;
const DT64_RELA: u64 = 7;
const DT64_RELASZ: u64 = 8;
const DT64_RELAENT: u64 = 9;
const DT64_JMPREL: u64 = 23;

// Relocation types
const R_386_RELATIVE: u32 = 8;
const R_X86_64_RELATIVE: u32 = 8;
const R_AARCH64_RELATIVE: u64 = 1027;
const R_AARCH64_JUMP_SLOT: u64 = 1026;

const DEFAULT_BASE32: u32 = 0x0040_0000;
const DEFAULT_BASE64: u64 = 0x0000_0000_0040_0000;
const DEFAULT_STACK_PAGES: usize = 4;
const USER_MMAP_MIN_ADDR: usize = 0x1000_0000;

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf32Ehdr {
    e_ident: [u8; EI_NIDENT],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf32Phdr {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf32Dyn {
    d_tag: u32,
    d_val: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf32Rel {
    r_offset: u32,
    r_info: u32,
}

fn read_struct<T: Copy>(bytes: &[u8], offset: usize) -> Result<T, &'static str> {
    if offset + size_of::<T>() > bytes.len() {
        return Err("ELF truncated");
    }
    let mut tmp = MaybeUninit::<T>::uninit();
    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr().add(offset),
            tmp.as_mut_ptr() as *mut u8,
            size_of::<T>(),
        );
        Ok(tmp.assume_init())
    }
}

fn check_elf32(bytes: &[u8]) -> Result<Elf32Ehdr, &'static str> {
    let hdr: Elf32Ehdr = read_struct(bytes, 0)?;
    if hdr.e_ident[0..4] != ELF_MAGIC {
        return Err("Invalid ELF magic");
    }
    if hdr.e_ident[4] != ELFCLASS32 {
        return Err("Not an ELF32 binary");
    }
    if hdr.e_ident[5] != ELFDATA2LSB {
        return Err("Big endian ELF not supported");
    }
    if hdr.e_phentsize as usize != size_of::<Elf32Phdr>() {
        return Err("Invalid program header size");
    }
    Ok(hdr)
}

fn align_down(value: u32, align: u32) -> u32 {
    value & !(align - 1)
}

fn align_up(value: u32, align: u32) -> u32 {
    (value + align - 1) & !(align - 1)
}

fn map_segment(
    space: &mut AddressSpace,
    vaddr: u32,
    memsz: u32,
    writable: bool,
) -> Result<(), &'static str> {
    if memsz == 0 {
        return Ok(());
    }
    let start = align_down(vaddr, PAGE_SIZE as u32);
    let end = align_up(vaddr + memsz, PAGE_SIZE as u32);
    if end as usize >= USER_TOP {
        return Err("Segment exceeds user space");
    }
    let pages = ((end - start) as usize) / PAGE_SIZE;
    arch_mmu::alloc_user_pages(space, start as usize, pages, writable)?;
    Ok(())
}

fn copy_to_user(space: &AddressSpace, vaddr: u32, data: &[u8]) -> Result<(), &'static str> {
    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), vaddr as *mut u8, data.len());
    }
    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

fn zero_user(space: &AddressSpace, vaddr: u32, len: usize) -> Result<(), &'static str> {
    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
    }
    unsafe {
        ptr::write_bytes(vaddr as *mut u8, 0, len);
    }
    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

fn parse_program_headers(bytes: &[u8], hdr: &Elf32Ehdr) -> Result<Vec<Elf32Phdr>, &'static str> {
    let mut phdrs = Vec::new();
    let base = hdr.e_phoff as usize;
    for i in 0..hdr.e_phnum as usize {
        let off = base + i * (hdr.e_phentsize as usize);
        let ph: Elf32Phdr = read_struct(bytes, off)?;
        phdrs.push(ph);
    }
    Ok(phdrs)
}

fn collect_dynamic(
    phdrs: &[Elf32Phdr],
    bytes: &[u8],
    base: u32,
) -> Result<Option<Vec<Elf32Dyn>>, &'static str> {
    let dyn_ph = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC);
    let Some(dyn_ph) = dyn_ph else {
        return Ok(None);
    };
    let dyn_off = dyn_ph.p_offset as usize;
    let dyn_len = dyn_ph.p_filesz as usize;
    if dyn_off + dyn_len > bytes.len() {
        return Err("Dynamic segment truncated");
    }
    let count = dyn_len / size_of::<Elf32Dyn>();
    let mut out = Vec::new();
    for i in 0..count {
        let ent: Elf32Dyn = read_struct(bytes, dyn_off + i * size_of::<Elf32Dyn>())?;
        out.push(ent);
        if ent.d_tag == DT_NULL {
            break;
        }
    }
    let _ = base;
    Ok(Some(out))
}

fn addr_in_load_ranges(phdrs: &[Elf32Phdr], base: u32, addr: u32, len: u32) -> bool {
    let req_start = addr as u64;
    let req_end = req_start.saturating_add(len as u64);
    if req_end <= req_start {
        return false;
    }
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let seg_start = (base as u64).saturating_add(ph.p_vaddr as u64);
        let seg_end = seg_start.saturating_add(ph.p_memsz as u64);
        if req_start >= seg_start && req_end <= seg_end {
            return true;
        }
    }
    false
}

fn apply_relocations(
    space: &AddressSpace,
    dyns: &[Elf32Dyn],
    phdrs: &[Elf32Phdr],
    base: u32,
) -> Result<(), &'static str> {
    let mut rel_addr = 0u32;
    let mut rel_size = 0u32;
    let mut rel_ent = size_of::<Elf32Rel>() as u32;
    let mut has_rela = false;

    for d in dyns {
        match d.d_tag {
            DT_REL => rel_addr = d.d_val,
            DT_RELSZ => rel_size = d.d_val,
            DT_RELENT => rel_ent = d.d_val,
            DT_RELA | DT_RELASZ => has_rela = true,
            DT_JMPREL => {}
            _ => {}
        }
    }

    if has_rela {
        return Err("RELA relocations not supported");
    }
    if rel_addr == 0 || rel_size == 0 {
        return Ok(());
    }
    if rel_ent as usize != size_of::<Elf32Rel>() {
        return Err("Invalid REL entry size");
    }
    let rel_table_start = base
        .checked_add(rel_addr)
        .ok_or("REL table address overflow")?;
    if !addr_in_load_ranges(phdrs, base, rel_table_start, rel_size) {
        return Err("REL table outside load segments");
    }

    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
    }

    let count = rel_size / rel_ent;
    for i in 0..count {
        let rel_entry_addr = rel_table_start
            .checked_add(i.saturating_mul(rel_ent))
            .ok_or("REL entry address overflow")?;
        if !addr_in_load_ranges(phdrs, base, rel_entry_addr, size_of::<Elf32Rel>() as u32) {
            let _ = crate::arch::mmu::set_page_table_root(old);
            return Err("REL entry outside load segments");
        }
        let rel_ptr = rel_entry_addr as *const Elf32Rel;
        let rel = unsafe { ptr::read_unaligned(rel_ptr) };
        let r_type = rel.r_info & 0xFF;
        if r_type == R_386_RELATIVE {
            let reloc_u32 = base
                .checked_add(rel.r_offset)
                .ok_or("Relocation address overflow")?;
            if !addr_in_load_ranges(phdrs, base, reloc_u32, size_of::<u32>() as u32) {
                let _ = crate::arch::mmu::set_page_table_root(old);
                return Err("Relocation target outside load segments");
            }
            let reloc_addr = reloc_u32 as *mut u32;
            let val = unsafe { ptr::read_unaligned(reloc_addr) };
            unsafe { ptr::write_unaligned(reloc_addr, val.wrapping_add(base)) };
        }
    }

    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

pub struct LoadedElf {
    pub space: AddressSpace,
    pub entry: u32,
    pub user_stack: u32,
    pub layout: UserProcessLayout,
}

fn segment_flags(flags: u32) -> VmaFlags {
    let mut vma_flags = VmaFlags::USER | VmaFlags::READ;
    if (flags & PF_W) != 0 {
        vma_flags |= VmaFlags::WRITE;
    }
    if (flags & PF_X) != 0 {
        vma_flags |= VmaFlags::EXEC;
    }
    vma_flags
}

fn build_elf32_layout(phdrs: &[Elf32Phdr], base: u32) -> UserProcessLayout {
    let page = PAGE_SIZE;
    let mut regions = Vec::new();
    let mut max_end = 0usize;

    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let start = align_down(base.wrapping_add(ph.p_vaddr), PAGE_SIZE as u32) as usize;
        let end = align_up(
            base.wrapping_add(ph.p_vaddr).wrapping_add(ph.p_memsz),
            PAGE_SIZE as u32,
        ) as usize;
        max_end = max_end.max(end);
        regions.push(UserRegionSpec {
            start,
            end,
            flags: segment_flags(ph.p_flags),
            kind: VmaKind::KernelSynthetic,
        });
    }

    let stack_base = USER_TOP.saturating_sub(DEFAULT_STACK_PAGES * page);
    regions.push(UserRegionSpec {
        start: stack_base,
        end: USER_TOP,
        flags: VmaFlags::READ
            | VmaFlags::WRITE
            | VmaFlags::USER
            | VmaFlags::STACK
            | VmaFlags::GROW_DOWN,
        kind: VmaKind::Stack,
    });

    let heap_base = ((max_end.saturating_add(page - 1)) / page).saturating_mul(page);
    let mmap_base = ((USER_MMAP_MIN_ADDR.max(heap_base.saturating_add(page)) + page - 1) / page)
        .saturating_mul(page);
    let mmap_limit = USER_TOP.saturating_sub(page * 8);

    UserProcessLayout {
        regions,
        heap_base,
        heap_end: heap_base,
        mmap_base,
        mmap_limit,
    }
}

pub fn load_elf32(bytes: &[u8]) -> Result<LoadedElf, &'static str> {
    let hdr = check_elf32(bytes)?;
    if hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN {
        return Err("Unsupported ELF type");
    }

    let phdrs = parse_program_headers(bytes, &hdr)?;
    if phdrs.iter().any(|p| p.p_type == PT_INTERP) {
        return Err("PT_INTERP not supported (no dynamic linker)");
    }

    let base = if hdr.e_type == ET_DYN {
        DEFAULT_BASE32
    } else {
        0
    };

    let mut space = AddressSpace::new()?;

    for ph in &phdrs {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_memsz == 0 {
            continue;
        }
        let writable = (ph.p_flags & PF_W) != 0;
        map_segment(&mut space, base + ph.p_vaddr, ph.p_memsz, writable)?;
    }

    for ph in &phdrs {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_filesz == 0 {
            if ph.p_memsz > 0 {
                zero_user(&space, base + ph.p_vaddr, ph.p_memsz as usize)?;
            }
            continue;
        }
        let off = ph.p_offset as usize;
        let end = off + ph.p_filesz as usize;
        if end > bytes.len() {
            return Err("Segment data truncated");
        }
        copy_to_user(&space, base + ph.p_vaddr, &bytes[off..end])?;
        if ph.p_memsz > ph.p_filesz {
            let bss_start = base + ph.p_vaddr + ph.p_filesz;
            let bss_len = (ph.p_memsz - ph.p_filesz) as usize;
            zero_user(&space, bss_start, bss_len)?;
        }
    }

    if let Some(dyns) = collect_dynamic(&phdrs, bytes, base)? {
        apply_relocations(&space, &dyns, &phdrs, base)?;
    }

    let stack_base = (USER_TOP - (DEFAULT_STACK_PAGES * PAGE_SIZE)) as u32;
    arch_mmu::alloc_user_pages(&mut space, stack_base as usize, DEFAULT_STACK_PAGES, true)?;
    let user_stack = (USER_TOP as u32) - 4;

    let entry = base + hdr.e_entry;

    Ok(LoadedElf {
        space,
        entry,
        user_stack,
        layout: build_elf32_layout(&phdrs, base),
    })
}

pub fn spawn_elf_process(name: &str, bytes: &[u8]) -> Result<(), &'static str> {
    let loaded = load_elf32(bytes)?;
    let pid = process::process_manager()
        .spawn(name, process::current_pid())
        .map_err(|_| "Failed to create process")?;
    let mut proc = process::process_manager()
        .get(pid)
        .ok_or("Process not found")?;
    proc.priority = ProcessPriority::Normal;
    quantum_scheduler::scheduler().lock().add_user_process_with_layout(
        proc,
        Box::new(loaded.space),
        loaded.entry,
        loaded.user_stack,
        loaded.layout,
    )?;
    Ok(())
}

pub fn name_from_path(path: &str) -> String {
    let mut name = String::from("elf");
    if let Some(last) = path.rsplit('/').next() {
        if !last.is_empty() {
            name = last.to_string();
        }
    }
    name
}

// ============================================================================
// ELF64 structures
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; EI_NIDENT],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Dyn {
    d_tag: u64,
    d_val: u64,
}

/// REL entry (no addend — rare on AArch64, but exists for PLT)
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Rel {
    r_offset: u64,
    r_info: u64,
}

/// RELA entry (with addend — the standard for AArch64)
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

// ============================================================================
// ELF64 helpers
// ============================================================================

fn align_down64(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up64(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn check_elf64(bytes: &[u8]) -> Result<Elf64Ehdr, &'static str> {
    let hdr: Elf64Ehdr = read_struct(bytes, 0)?;
    if hdr.e_ident[0..4] != ELF_MAGIC {
        return Err("Invalid ELF magic");
    }
    if hdr.e_ident[4] != ELFCLASS64 {
        return Err("Not an ELF64 binary");
    }
    if hdr.e_ident[5] != ELFDATA2LSB {
        return Err("Big endian ELF64 not supported");
    }
    if hdr.e_machine != EM_AARCH64 && hdr.e_machine != EM_X86_64 {
        return Err("ELF64: unsupported e_machine (only x86_64 and AArch64)");
    }
    if hdr.e_phentsize as usize != size_of::<Elf64Phdr>() {
        return Err("ELF64: invalid program header entry size");
    }
    Ok(hdr)
}

fn map_segment64(
    space: &mut AddressSpace,
    vaddr: u64,
    memsz: u64,
    writable: bool,
) -> Result<(), &'static str> {
    if memsz == 0 {
        return Ok(());
    }
    let start = align_down64(vaddr, PAGE_SIZE as u64) as usize;
    let end = align_up64(vaddr + memsz, PAGE_SIZE as u64) as usize;
    if end >= USER_TOP {
        return Err("ELF64: segment exceeds user space");
    }
    let pages = (end - start) / PAGE_SIZE;
    arch_mmu::alloc_user_pages(space, start, pages, writable)?;
    Ok(())
}

fn copy_to_user64(space: &AddressSpace, vaddr: u64, data: &[u8]) -> Result<(), &'static str> {
    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), vaddr as *mut u8, data.len());
    }
    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

fn zero_user64(space: &AddressSpace, vaddr: u64, len: usize) -> Result<(), &'static str> {
    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
    }
    unsafe {
        ptr::write_bytes(vaddr as *mut u8, 0, len);
    }
    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

fn parse_program_headers64(bytes: &[u8], hdr: &Elf64Ehdr) -> Result<Vec<Elf64Phdr>, &'static str> {
    let mut phdrs = Vec::new();
    let base = hdr.e_phoff as usize;
    for i in 0..hdr.e_phnum as usize {
        let off = base + i * hdr.e_phentsize as usize;
        let ph: Elf64Phdr = read_struct(bytes, off)?;
        phdrs.push(ph);
    }
    Ok(phdrs)
}

fn addr_in_load_ranges64(phdrs: &[Elf64Phdr], base: u64, addr: u64, len: u64) -> bool {
    let req_end = addr.saturating_add(len);
    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let seg_start = base.saturating_add(ph.p_vaddr);
        let seg_end = seg_start.saturating_add(ph.p_memsz);
        if addr >= seg_start && req_end <= seg_end {
            return true;
        }
    }
    false
}

fn apply_rela_relocations64(
    space: &AddressSpace,
    dyns: &[Elf64Dyn],
    phdrs: &[Elf64Phdr],
    base: u64,
) -> Result<(), &'static str> {
    let mut rela_addr: u64 = 0;
    let mut rela_size: u64 = 0;
    let mut rela_ent: u64 = size_of::<Elf64Rela>() as u64;

    for d in dyns {
        match d.d_tag {
            t if t == DT64_RELA => rela_addr = d.d_val,
            t if t == DT64_RELASZ => rela_size = d.d_val,
            t if t == DT64_RELAENT => rela_ent = d.d_val,
            t if t == DT64_NULL => break,
            _ => {}
        }
    }

    if rela_addr == 0 || rela_size == 0 {
        return Ok(());
    }
    if rela_ent as usize != size_of::<Elf64Rela>() {
        return Err("ELF64 RELA: invalid entry size");
    }

    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
    }

    let count = rela_size / rela_ent;
    for i in 0..count {
        let entry_va = base
            .checked_add(rela_addr)
            .and_then(|a| a.checked_add(i.saturating_mul(rela_ent)))
            .ok_or("ELF64 RELA: address overflow")?;
        if !addr_in_load_ranges64(phdrs, base, entry_va, size_of::<Elf64Rela>() as u64) {
            let _ = crate::arch::mmu::set_page_table_root(old);
            return Err("ELF64 RELA: entry outside load segments");
        }
        let rela = unsafe { ptr::read_unaligned(entry_va as *const Elf64Rela) };
        let r_type = rela.r_info & 0xFFFF_FFFF;

        if r_type == R_AARCH64_RELATIVE {
            // S + A where S = base (position-independent)
            let target_va = rela
                .r_offset
                .checked_add(base)
                .ok_or("ELF64 RELA: reloc target overflow")?;
            if !addr_in_load_ranges64(phdrs, base, target_va, 8) {
                let _ = crate::arch::mmu::set_page_table_root(old);
                return Err("ELF64 RELA: reloc target outside load segments");
            }
            let value = base.wrapping_add(rela.r_addend as u64);
            unsafe {
                ptr::write_unaligned(target_va as *mut u64, value);
            }
        }
        // R_AARCH64_JUMP_SLOT and others require PLT which we don't support yet.
    }

    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

// ============================================================================
// ELF64 public entry points
// ============================================================================

pub struct LoadedElf64 {
    pub space: AddressSpace,
    pub entry: u64,
    pub user_stack: u64,
    pub layout: UserProcessLayout,
}

fn build_elf64_layout(phdrs: &[Elf64Phdr], base: u64) -> UserProcessLayout {
    let page = PAGE_SIZE;
    let mut regions = Vec::new();
    let mut max_end = 0usize;

    for ph in phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let start = align_down64(base.wrapping_add(ph.p_vaddr), PAGE_SIZE as u64) as usize;
        let end = align_up64(
            base.wrapping_add(ph.p_vaddr).wrapping_add(ph.p_memsz),
            PAGE_SIZE as u64,
        ) as usize;
        max_end = max_end.max(end);
        regions.push(UserRegionSpec {
            start,
            end,
            flags: segment_flags(ph.p_flags),
            kind: VmaKind::KernelSynthetic,
        });
    }

    let stack_base = USER_TOP.saturating_sub(DEFAULT_STACK_PAGES * page);
    regions.push(UserRegionSpec {
        start: stack_base,
        end: USER_TOP,
        flags: VmaFlags::READ
            | VmaFlags::WRITE
            | VmaFlags::USER
            | VmaFlags::STACK
            | VmaFlags::GROW_DOWN,
        kind: VmaKind::Stack,
    });

    let heap_base = ((max_end.saturating_add(page - 1)) / page).saturating_mul(page);
    let mmap_base = ((USER_MMAP_MIN_ADDR.max(heap_base.saturating_add(page)) + page - 1) / page)
        .saturating_mul(page);
    let mmap_limit = USER_TOP.saturating_sub(page * 8);

    UserProcessLayout {
        regions,
        heap_base,
        heap_end: heap_base,
        mmap_base,
        mmap_limit,
    }
}

pub fn load_elf64(bytes: &[u8]) -> Result<LoadedElf64, &'static str> {
    let hdr = check_elf64(bytes)?;
    if hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN {
        return Err("ELF64: unsupported binary type");
    }

    let phdrs = parse_program_headers64(bytes, &hdr)?;
    if phdrs.iter().any(|p| p.p_type == PT_INTERP) {
        return Err("ELF64: PT_INTERP not supported (no dynamic linker)");
    }

    let base: u64 = if hdr.e_type == ET_DYN {
        DEFAULT_BASE64
    } else {
        0
    };

    let mut space = AddressSpace::new()?;

    // Map all PT_LOAD segments
    for ph in &phdrs {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let writable = (ph.p_flags & PF_W) != 0;
        map_segment64(&mut space, base + ph.p_vaddr, ph.p_memsz, writable)?;
    }

    // Copy file content + zero BSS
    for ph in &phdrs {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if ph.p_filesz == 0 {
            if ph.p_memsz > 0 {
                zero_user64(&space, base + ph.p_vaddr, ph.p_memsz as usize)?;
            }
            continue;
        }
        let off = ph.p_offset as usize;
        let end = off + ph.p_filesz as usize;
        if end > bytes.len() {
            return Err("ELF64: segment data truncated");
        }
        copy_to_user64(&space, base + ph.p_vaddr, &bytes[off..end])?;
        if ph.p_memsz > ph.p_filesz {
            let bss_start = base + ph.p_vaddr + ph.p_filesz;
            zero_user64(&space, bss_start, (ph.p_memsz - ph.p_filesz) as usize)?;
        }
    }

    // Collect DYNAMIC and apply RELA relocations
    let dyn_ph = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC);
    if let Some(dp) = dyn_ph {
        let dyn_off = dp.p_offset as usize;
        let dyn_len = dp.p_filesz as usize;
        if dyn_off + dyn_len > bytes.len() {
            return Err("ELF64: dynamic segment truncated");
        }
        let count = dyn_len / size_of::<Elf64Dyn>();
        let mut dyns: Vec<Elf64Dyn> = Vec::with_capacity(count);
        for i in 0..count {
            let d: Elf64Dyn = read_struct(bytes, dyn_off + i * size_of::<Elf64Dyn>())?;
            let done = d.d_tag == DT64_NULL;
            dyns.push(d);
            if done {
                break;
            }
        }
        apply_rela_relocations64(&space, &dyns, &phdrs, base)?;
    }

    // User stack
    let stack_base = (USER_TOP - DEFAULT_STACK_PAGES * PAGE_SIZE) as u64;
    arch_mmu::alloc_user_pages(&mut space, stack_base as usize, DEFAULT_STACK_PAGES, true)?;
    let user_stack = (USER_TOP as u64) - 16; // 16-byte aligned for AArch64 ABI

    let entry = base + hdr.e_entry;

    Ok(LoadedElf64 {
        space,
        entry,
        user_stack,
        layout: build_elf64_layout(&phdrs, base),
    })
}

pub fn spawn_elf64_process(name: &str, bytes: &[u8]) -> Result<(), &'static str> {
    let loaded = load_elf64(bytes)?;
    let pid = process::process_manager()
        .spawn(name, process::current_pid())
        .map_err(|_| "ELF64: failed to create process")?;
    let mut proc = process::process_manager()
        .get(pid)
        .ok_or("ELF64: process not found after spawn")?;
    proc.priority = ProcessPriority::Normal;
    quantum_scheduler::scheduler().lock().add_user_process_with_layout(
        proc,
        Box::new(loaded.space),
        loaded.entry as u32, // scheduler stores u32 VA; fine for 4 GiB user space
        loaded.user_stack as u32,
        loaded.layout,
    )?;
    Ok(())
}

/// Top-level ELF dispatch — detects 32 vs 64 from EI_CLASS and routes accordingly.
pub fn spawn_elf_process_any(name: &str, bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < EI_NIDENT {
        return Err("ELF: image too small");
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err("ELF: invalid magic");
    }
    match bytes[4] {
        ELFCLASS32 => spawn_elf_process(name, bytes),
        ELFCLASS64 => spawn_elf64_process(name, bytes),
        _ => Err("ELF: unknown EI_CLASS"),
    }
}

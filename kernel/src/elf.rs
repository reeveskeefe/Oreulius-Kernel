/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

//! ELF loader for native binaries (ELF32, basic ET_DYN support).

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::{size_of, MaybeUninit};
use core::ptr;

use crate::paging::{self, AddressSpace, PAGE_SIZE, USER_TOP};
use crate::process::{self, ProcessPriority};
use crate::quantum_scheduler;

const EI_NIDENT: usize = 16;
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const PF_X: u32 = 1;
const PF_W: u32 = 2;

const DT_NULL: u32 = 0;
const DT_REL: u32 = 17;
const DT_RELSZ: u32 = 18;
const DT_RELENT: u32 = 19;
const DT_RELA: u32 = 7;
const DT_RELASZ: u32 = 8;
const DT_JMPREL: u32 = 23;

const R_386_RELATIVE: u32 = 8;

const DEFAULT_BASE: u32 = 0x0040_0000;
const DEFAULT_STACK_PAGES: usize = 1;

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
        ptr::copy_nonoverlapping(bytes.as_ptr().add(offset), tmp.as_mut_ptr() as *mut u8, size_of::<T>());
        Ok(tmp.assume_init())
    }
}

fn check_elf32(bytes: &[u8]) -> Result<Elf32Ehdr, &'static str> {
    let hdr: Elf32Ehdr = read_struct(bytes, 0)?;
    if hdr.e_ident[0..4] != ELF_MAGIC {
        return Err("Invalid ELF magic");
    }
    if hdr.e_ident[4] != ELFCLASS32 {
        return Err("ELF64 not supported");
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

fn map_segment(space: &mut AddressSpace, vaddr: u32, memsz: u32, writable: bool) -> Result<(), &'static str> {
    if memsz == 0 {
        return Ok(());
    }
    let start = align_down(vaddr, PAGE_SIZE as u32);
    let end = align_up(vaddr + memsz, PAGE_SIZE as u32);
    if end as usize >= USER_TOP {
        return Err("Segment exceeds user space");
    }
    let pages = ((end - start) as usize) / PAGE_SIZE;
    paging::alloc_user_pages(space, start as usize, pages, writable)?;
    Ok(())
}

fn copy_to_user(space: &AddressSpace, vaddr: u32, data: &[u8]) -> Result<(), &'static str> {
    let old = paging::current_page_directory_addr();
    unsafe {
        space.activate();
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), vaddr as *mut u8, data.len());
    }
    unsafe {
        paging::set_page_directory(old);
    }
    Ok(())
}

fn zero_user(space: &AddressSpace, vaddr: u32, len: usize) -> Result<(), &'static str> {
    let old = paging::current_page_directory_addr();
    unsafe {
        space.activate();
    }
    unsafe {
        ptr::write_bytes(vaddr as *mut u8, 0, len);
    }
    unsafe {
        paging::set_page_directory(old);
    }
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

fn collect_dynamic(phdrs: &[Elf32Phdr], bytes: &[u8], base: u32) -> Result<Option<Vec<Elf32Dyn>>, &'static str> {
    let dyn_ph = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC);
    let Some(dyn_ph) = dyn_ph else { return Ok(None); };
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
            DT_JMPREL => {},
            _ => {},
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

    let old = paging::current_page_directory_addr();
    unsafe { space.activate(); }

    let count = rel_size / rel_ent;
    for i in 0..count {
        let rel_entry_addr = rel_table_start
            .checked_add(i.saturating_mul(rel_ent))
            .ok_or("REL entry address overflow")?;
        if !addr_in_load_ranges(
            phdrs,
            base,
            rel_entry_addr,
            size_of::<Elf32Rel>() as u32,
        ) {
            unsafe { paging::set_page_directory(old); }
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
                unsafe { paging::set_page_directory(old); }
                return Err("Relocation target outside load segments");
            }
            let reloc_addr = reloc_u32 as *mut u32;
            let val = unsafe { ptr::read_unaligned(reloc_addr) };
            unsafe { ptr::write_unaligned(reloc_addr, val.wrapping_add(base)) };
        }
    }

    unsafe { paging::set_page_directory(old); }
    Ok(())
}

pub struct LoadedElf {
    pub space: AddressSpace,
    pub entry: u32,
    pub user_stack: u32,
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

    let base = if hdr.e_type == ET_DYN { DEFAULT_BASE } else { 0 };

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
    paging::alloc_user_pages(&mut space, stack_base as usize, DEFAULT_STACK_PAGES, true)?;
    let user_stack = (USER_TOP as u32) - 4;

    let entry = base + hdr.e_entry;

    Ok(LoadedElf {
        space,
        entry,
        user_stack,
    })
}

pub fn spawn_elf_process(name: &str, bytes: &[u8]) -> Result<(), &'static str> {
    let loaded = load_elf32(bytes)?;
    let pid = process::process_manager()
        .spawn(name, process::current_pid())
        .map_err(|_| "Failed to create process")?;
    let mut proc = process::process_manager().get(pid).ok_or("Process not found")?;
    proc.priority = ProcessPriority::Normal;
    quantum_scheduler::scheduler()
        .lock()
        .add_user_process(proc, Box::new(loaded.space), loaded.entry, loaded.user_stack)?;
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

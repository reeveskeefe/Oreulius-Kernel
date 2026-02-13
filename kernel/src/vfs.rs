//! Oreulia VFS (Hierarchical Filesystem)
//!
//! Provides a Unix-like inode tree, path resolution, mount points, and
//! per-process file descriptors. Root is an in-memory filesystem; VirtIO
//! block devices can be mounted as a device filesystem.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::min;
use core::fmt::Write;
use spin::Mutex;

use crate::process::{self, Pid};
use crate::virtio_blk;

pub type InodeId = u64;

pub const MAX_NAME_LEN: usize = 64;
pub const MAX_VFS_FILE_SIZE: usize = 1024 * 1024;

// ============================================================================
// Inodes
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InodeKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Copy, Debug)]
pub struct InodeMetadata {
    pub size: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub nlink: u32,
    pub direct_blocks: [u32; 12],
    pub indirect_block: u32,
    pub double_indirect_block: u32,
    pub triple_indirect_block: u32,
}

impl InodeMetadata {
    pub const fn new(mode: u16) -> Self {
        InodeMetadata {
            size: 0,
            mode,
            uid: 0,
            gid: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            nlink: 1,
            direct_blocks: [0; 12],
            indirect_block: 0,
            double_indirect_block: 0,
            triple_indirect_block: 0,
        }
    }
}

#[derive(Clone)]
struct DirEntry {
    name: String,
    inode: InodeId,
}

#[derive(Clone)]
struct Inode {
    id: InodeId,
    kind: InodeKind,
    meta: InodeMetadata,
    data: Vec<u8>,
    entries: Vec<DirEntry>,
}

impl Inode {
    fn new(id: InodeId, kind: InodeKind, mode: u16) -> Self {
        Inode {
            id,
            kind,
            meta: InodeMetadata::new(mode),
            data: Vec::new(),
            entries: Vec::new(),
        }
    }
}

// ============================================================================
// Mounts
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountBackend {
    VirtioBlock,
}

struct Mount {
    path: String,
    backend: MountBackend,
}

// ============================================================================
// File Descriptors / Handles
// ============================================================================

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct OpenFlags: u32 {
        const READ   = 1 << 0;
        const WRITE  = 1 << 1;
        const CREATE = 1 << 2;
        const TRUNC  = 1 << 3;
        const APPEND = 1 << 4;
    }
}

#[derive(Clone, Copy, Debug)]
enum HandleKind {
    MemFile { inode: InodeId },
    MemDir { inode: InodeId },
    VirtioRaw,
    VirtioPartitions,
}

#[derive(Clone, Debug)]
struct Handle {
    kind: HandleKind,
    pos: usize,
    flags: OpenFlags,
    owner: Pid,
}

// ============================================================================
// VFS Core
// ============================================================================

struct Vfs {
    inodes: Vec<Option<Inode>>,
    mounts: Vec<Mount>,
    handles: Vec<Option<Handle>>,
}

impl Vfs {
    const fn new() -> Self {
        Vfs {
            inodes: Vec::new(),
            mounts: Vec::new(),
            handles: Vec::new(),
        }
    }

    fn init(&mut self) {
        if !self.inodes.is_empty() {
            return;
        }
        // Inode 0 is unused; root is inode 1.
        self.inodes.push(None);
        let root_id = self.alloc_inode(InodeKind::Directory, 0o755);
        let _ = root_id;
    }

    fn alloc_inode(&mut self, kind: InodeKind, mode: u16) -> InodeId {
        let id = self.inodes.len() as InodeId;
        self.inodes.push(Some(Inode::new(id, kind, mode)));
        id
    }

    fn get_inode(&self, id: InodeId) -> Option<&Inode> {
        self.inodes.get(id as usize).and_then(|i| i.as_ref())
    }

    fn get_inode_mut(&mut self, id: InodeId) -> Option<&mut Inode> {
        self.inodes.get_mut(id as usize).and_then(|i| i.as_mut())
    }

    fn resolve_path(&self, path: &str) -> Result<InodeId, &'static str> {
        let path = normalize_path(path)?;
        if path == "/" {
            return Ok(1);
        }

        let mut current = 1;
        let mut stack: Vec<InodeId> = Vec::new();
        stack.push(1);

        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if comp == "." {
                continue;
            }
            if comp == ".." {
                if stack.len() > 1 {
                    stack.pop();
                    current = *stack.last().unwrap();
                }
                continue;
            }

            let inode = self.get_inode(current).ok_or("Directory not found")?;
            if inode.kind != InodeKind::Directory {
                return Err("Not a directory");
            }

            let next = inode
                .entries
                .iter()
                .find(|e| e.name == comp)
                .map(|e| e.inode)
                .ok_or("Path component not found")?;
            current = next;
            stack.push(current);
        }

        Ok(current)
    }

    fn split_parent(path: &str) -> Result<(String, String), &'static str> {
        let path = normalize_path(path)?;
        if path == "/" {
            return Err("Root has no parent");
        }
        let idx = path.rfind('/').ok_or("Invalid path")?;
        let (parent, name) = path.split_at(idx);
        let name = &name[1..];
        if name.is_empty() {
            return Err("Invalid name");
        }
        let parent = if parent.is_empty() { "/" } else { parent };
        Ok((parent.to_string(), name.to_string()))
    }

    fn add_dir_entry(&mut self, dir_id: InodeId, name: &str, inode_id: InodeId) -> Result<(), &'static str> {
        if name.len() > MAX_NAME_LEN {
            return Err("Name too long");
        }
        let dir = self.get_inode_mut(dir_id).ok_or("Directory not found")?;
        if dir.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        if dir.entries.iter().any(|e| e.name == name) {
            return Err("Entry exists");
        }
        dir.entries.push(DirEntry {
            name: name.to_string(),
            inode: inode_id,
        });
        Ok(())
    }

    fn find_mount(&self, path: &str) -> Option<(MountBackend, String)> {
        let path = normalize_path(path).ok()?;
        let mut best: Option<(MountBackend, String, usize)> = None;
        for mount in &self.mounts {
            if path == mount.path || path.starts_with(&(mount.path.clone() + "/")) {
                let sub = if path == mount.path {
                    "/".to_string()
                } else {
                    path[mount.path.len()..].to_string()
                };
                let len = mount.path.len();
                if best.as_ref().map(|b| len > b.2).unwrap_or(true) {
                    best = Some((mount.backend, sub, len));
                }
            }
        }
        best.map(|b| (b.0, b.1))
    }

    fn alloc_handle(&mut self, handle: Handle) -> u64 {
        for (idx, slot) in self.handles.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(handle);
                return (idx as u64) + 1;
            }
        }
        self.handles.push(Some(handle));
        self.handles.len() as u64
    }

    fn get_handle_mut(&mut self, handle_id: u64) -> Option<&mut Handle> {
        let idx = (handle_id as usize).checked_sub(1)?;
        self.handles.get_mut(idx).and_then(|h| h.as_mut())
    }

    fn remove_handle(&mut self, handle_id: u64) {
        if let Some(slot) = self.handles.get_mut((handle_id as usize).saturating_sub(1)) {
            *slot = None;
        }
    }
}

static VFS: Mutex<Vfs> = Mutex::new(Vfs::new());

pub fn init() {
    VFS.lock().init();
}

// ============================================================================
// Public VFS API (Paths)
// ============================================================================

pub fn mkdir(path: &str) -> Result<(), &'static str> {
    let mut vfs = VFS.lock();
    vfs.init();
    if vfs.find_mount(path).is_some() {
        return Err("Path is within a mount point");
    }
    let (parent, name) = Vfs::split_parent(path)?;
    let parent_id = vfs.resolve_path(&parent)?;
    let inode_id = vfs.alloc_inode(InodeKind::Directory, 0o755);
    vfs.add_dir_entry(parent_id, &name, inode_id)
}

pub fn create_file(path: &str) -> Result<InodeId, &'static str> {
    let mut vfs = VFS.lock();
    vfs.init();
    if vfs.find_mount(path).is_some() {
        return Err("Path is within a mount point");
    }
    let (parent, name) = Vfs::split_parent(path)?;
    let parent_id = vfs.resolve_path(&parent)?;
    let inode_id = vfs.alloc_inode(InodeKind::File, 0o644);
    vfs.add_dir_entry(parent_id, &name, inode_id)?;
    Ok(inode_id)
}

pub fn write_path(path: &str, data: &[u8]) -> Result<usize, &'static str> {
    {
        let mut vfs = VFS.lock();
        vfs.init();
        if let Some((backend, sub)) = vfs.find_mount(path) {
            return mount_write(backend, &sub, data);
        }

        if let Ok(inode_id) = vfs.resolve_path(path) {
            let inode = vfs.get_inode_mut(inode_id).ok_or("File not found")?;
            if inode.kind != InodeKind::File {
                return Err("Not a file");
            }
            if data.len() > MAX_VFS_FILE_SIZE {
                return Err("File too large");
            }
            inode.data.clear();
            inode.data.extend_from_slice(data);
            inode.meta.size = inode.data.len() as u64;
            inode.meta.mtime = 0;
            return Ok(data.len());
        }
    }

    create_file(path)?;

    let mut vfs = VFS.lock();
    vfs.init();
    let inode_id = vfs.resolve_path(path)?;
    let inode = vfs.get_inode_mut(inode_id).ok_or("File not found")?;
    if inode.kind != InodeKind::File {
        return Err("Not a file");
    }
    if data.len() > MAX_VFS_FILE_SIZE {
        return Err("File too large");
    }
    inode.data.clear();
    inode.data.extend_from_slice(data);
    inode.meta.size = inode.data.len() as u64;
    inode.meta.mtime = 0;
    Ok(data.len())
}

pub fn read_path(path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
    let mut vfs = VFS.lock();
    vfs.init();
    if let Some((backend, sub)) = vfs.find_mount(path) {
        return mount_read(backend, &sub, out);
    }
    let inode_id = vfs.resolve_path(path)?;
    let inode = vfs.get_inode(inode_id).ok_or("File not found")?;
    if inode.kind != InodeKind::File && inode.kind != InodeKind::Symlink {
        return Err("Not a file");
    }
    let len = min(out.len(), inode.data.len());
    out[..len].copy_from_slice(&inode.data[..len]);
    Ok(len)
}

pub fn list_dir(path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
    let mut vfs = VFS.lock();
    vfs.init();
    if let Some((backend, sub)) = vfs.find_mount(path) {
        return mount_list(backend, &sub, out);
    }
    let inode_id = vfs.resolve_path(path)?;
    let inode = vfs.get_inode(inode_id).ok_or("Directory not found")?;
    if inode.kind != InodeKind::Directory {
        return Err("Not a directory");
    }
    let mut s = String::new();
    for entry in &inode.entries {
        let _ = write!(s, "{} ", entry.name);
    }
    let bytes = s.as_bytes();
    let len = min(out.len(), bytes.len());
    out[..len].copy_from_slice(&bytes[..len]);
    Ok(len)
}

pub fn mount_virtio(path: &str) -> Result<(), &'static str> {
    if !virtio_blk::is_present() {
        return Err("No VirtIO block device present");
    }
    let mut vfs = VFS.lock();
    vfs.init();
    let norm = normalize_path(path)?;
    let inode_id = vfs.resolve_path(&norm)?;
    let inode = vfs.get_inode(inode_id).ok_or("Mount point not found")?;
    if inode.kind != InodeKind::Directory {
        return Err("Mount point is not a directory");
    }
    if vfs.mounts.iter().any(|m| m.path == norm) {
        return Err("Mount point already used");
    }
    vfs.mounts.push(Mount {
        path: norm,
        backend: MountBackend::VirtioBlock,
    });
    Ok(())
}

// ============================================================================
// File Descriptors
// ============================================================================

pub fn open_for_current(path: &str, flags: OpenFlags) -> Result<usize, &'static str> {
    let pid = process::current_pid().ok_or("No current process")?;
    open_for_pid(pid, path, flags)
}

pub fn open_for_pid(pid: Pid, path: &str, flags: OpenFlags) -> Result<usize, &'static str> {
    {
        let mut vfs = VFS.lock();
        vfs.init();
        if let Some((backend, sub)) = vfs.find_mount(path) {
            let kind = mount_open_kind(backend, &sub, flags)?;
            let handle = Handle { kind, pos: 0, flags, owner: pid };
            let handle_id = vfs.alloc_handle(handle);
            return process::process_manager()
                .alloc_fd(pid, handle_id)
                .map_err(|e| e.as_str());
        }

        if let Ok(inode_id) = vfs.resolve_path(path) {
            let inode = vfs.get_inode_mut(inode_id).ok_or("File not found")?;
            match inode.kind {
                InodeKind::File => {
                    if flags.contains(OpenFlags::TRUNC) {
                        inode.data.clear();
                        inode.meta.size = 0;
                    }
                    let handle = Handle {
                        kind: HandleKind::MemFile { inode: inode_id },
                        pos: if flags.contains(OpenFlags::APPEND) { inode.data.len() } else { 0 },
                        flags,
                        owner: pid,
                    };
                    let handle_id = vfs.alloc_handle(handle);
                    return process::process_manager()
                        .alloc_fd(pid, handle_id)
                        .map_err(|e| e.as_str());
                }
                InodeKind::Directory => {
                    let handle = Handle {
                        kind: HandleKind::MemDir { inode: inode_id },
                        pos: 0,
                        flags,
                        owner: pid,
                    };
                    let handle_id = vfs.alloc_handle(handle);
                    return process::process_manager()
                        .alloc_fd(pid, handle_id)
                        .map_err(|e| e.as_str());
                }
                InodeKind::Symlink => return Err("Symlink open not supported"),
            }
        }
    }

    if !flags.contains(OpenFlags::CREATE) {
        return Err("File not found");
    }

    create_file(path)?;

    let mut vfs = VFS.lock();
    vfs.init();
    let inode_id = vfs.resolve_path(path)?;
    let inode = vfs.get_inode_mut(inode_id).ok_or("File not found")?;
    match inode.kind {
        InodeKind::File => {
            if flags.contains(OpenFlags::TRUNC) {
                inode.data.clear();
                inode.meta.size = 0;
            }
            let handle = Handle {
                kind: HandleKind::MemFile { inode: inode_id },
                pos: if flags.contains(OpenFlags::APPEND) { inode.data.len() } else { 0 },
                flags,
                owner: pid,
            };
            let handle_id = vfs.alloc_handle(handle);
            process::process_manager()
                .alloc_fd(pid, handle_id)
                .map_err(|e| e.as_str())
        }
        InodeKind::Directory => {
            let handle = Handle {
                kind: HandleKind::MemDir { inode: inode_id },
                pos: 0,
                flags,
                owner: pid,
            };
            let handle_id = vfs.alloc_handle(handle);
            process::process_manager()
                .alloc_fd(pid, handle_id)
                .map_err(|e| e.as_str())
        }
        InodeKind::Symlink => Err("Symlink open not supported"),
    }
}

pub fn read_fd(pid: Pid, fd: usize, out: &mut [u8]) -> Result<usize, &'static str> {
    let handle_id = process::process_manager()
        .get_fd_handle(pid, fd)
        .map_err(|e| e.as_str())?;
    let mut vfs = VFS.lock();
    let (kind, pos) = {
        let handle = vfs.get_handle_mut(handle_id).ok_or("Invalid handle")?;
        if handle.owner != pid {
            return Err("Handle ownership mismatch");
        }
        (handle.kind, handle.pos)
    };
    let read_len = match kind {
        HandleKind::MemFile { inode } => {
            let inode = vfs.get_inode(inode).ok_or("File not found")?;
            let data = &inode.data;
            let start = pos;
            if start >= data.len() {
                return Ok(0);
            }
            let len = min(out.len(), data.len() - start);
            out[..len].copy_from_slice(&data[start..start + len]);
            Ok(len)
        }
        HandleKind::MemDir { .. } => Err("Cannot read directory"),
        HandleKind::VirtioRaw => virtio_read_at(pos, out),
        HandleKind::VirtioPartitions => {
            let text = generate_partition_text()?;
            let bytes = text.as_bytes();
            let start = pos;
            if start >= bytes.len() {
                return Ok(0);
            }
            let len = min(out.len(), bytes.len() - start);
            out[..len].copy_from_slice(&bytes[start..start + len]);
            Ok(len)
        }
    }?;

    if let Some(handle) = vfs.get_handle_mut(handle_id) {
        handle.pos = handle.pos.saturating_add(read_len);
    }
    Ok(read_len)
}

pub fn write_fd(pid: Pid, fd: usize, data: &[u8]) -> Result<usize, &'static str> {
    let handle_id = process::process_manager()
        .get_fd_handle(pid, fd)
        .map_err(|e| e.as_str())?;
    let mut vfs = VFS.lock();
    let (kind, pos, flags) = {
        let handle = vfs.get_handle_mut(handle_id).ok_or("Invalid handle")?;
        if handle.owner != pid {
            return Err("Handle ownership mismatch");
        }
        (handle.kind, handle.pos, handle.flags)
    };
    if !flags.contains(OpenFlags::WRITE) {
        return Err("File not opened for write");
    }
    let written = match kind {
        HandleKind::MemFile { inode } => {
            let inode = vfs.get_inode_mut(inode).ok_or("File not found")?;
            if pos + data.len() > MAX_VFS_FILE_SIZE {
                return Err("File too large");
            }
            if pos > inode.data.len() {
                inode.data.resize(pos, 0);
            }
            if pos + data.len() > inode.data.len() {
                inode.data.resize(pos + data.len(), 0);
            }
            inode.data[pos..pos + data.len()].copy_from_slice(data);
            inode.meta.size = inode.data.len() as u64;
            inode.meta.mtime = 0;
            Ok(data.len())
        }
        HandleKind::MemDir { .. } => Err("Cannot write directory"),
        HandleKind::VirtioRaw => virtio_write_at(pos, data),
        HandleKind::VirtioPartitions => Err("Partitions file is read-only"),
    }?;

    if let Some(handle) = vfs.get_handle_mut(handle_id) {
        handle.pos = handle.pos.saturating_add(written);
    }
    Ok(written)
}

pub fn close_fd(pid: Pid, fd: usize) -> Result<(), &'static str> {
    let handle_id = process::process_manager()
        .get_fd_handle(pid, fd)
        .map_err(|e| e.as_str())?;
    let mut vfs = VFS.lock();
    vfs.remove_handle(handle_id);
    process::process_manager()
        .close_fd(pid, fd)
        .map_err(|e| e.as_str())
}

// ============================================================================
// VirtIO Mount Backend
// ============================================================================

fn mount_open_kind(backend: MountBackend, subpath: &str, flags: OpenFlags) -> Result<HandleKind, &'static str> {
    match backend {
        MountBackend::VirtioBlock => {
            let sub = normalize_subpath(subpath);
            match sub.as_str() {
                "/" => Err("Cannot open mount root"),
                "/raw" => Ok(HandleKind::VirtioRaw),
                "/partitions" => {
                    if flags.contains(OpenFlags::WRITE) {
                        Err("Partitions file is read-only")
                    } else {
                        Ok(HandleKind::VirtioPartitions)
                    }
                }
                _ => Err("Invalid path on virtio mount"),
            }
        }
    }
}

fn mount_list(backend: MountBackend, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str> {
    match backend {
        MountBackend::VirtioBlock => {
            let sub = normalize_subpath(subpath);
            if sub != "/" {
                return Err("Not a directory");
            }
            let text = "raw partitions ";
            let bytes = text.as_bytes();
            let len = min(out.len(), bytes.len());
            out[..len].copy_from_slice(&bytes[..len]);
            Ok(len)
        }
    }
}

fn mount_read(backend: MountBackend, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str> {
    match backend {
        MountBackend::VirtioBlock => {
            let sub = normalize_subpath(subpath);
            match sub.as_str() {
                "/raw" => virtio_read_at(0, out),
                "/partitions" => {
                    let text = generate_partition_text()?;
                    let bytes = text.as_bytes();
                    let len = min(out.len(), bytes.len());
                    out[..len].copy_from_slice(&bytes[..len]);
                    Ok(len)
                }
                _ => Err("Invalid path"),
            }
        }
    }
}

fn mount_write(backend: MountBackend, subpath: &str, data: &[u8]) -> Result<usize, &'static str> {
    match backend {
        MountBackend::VirtioBlock => {
            let sub = normalize_subpath(subpath);
            match sub.as_str() {
                "/raw" => virtio_write_at(0, data),
                _ => Err("Invalid path"),
            }
        }
    }
}

fn generate_partition_text() -> Result<String, &'static str> {
    let mut mbr = [None; 4];
    let mut gpt = [None; 4];
    virtio_blk::read_partitions(&mut mbr, &mut gpt)?;
    let mut s = String::new();
    let _ = writeln!(s, "MBR:");
    for (i, p) in mbr.iter().enumerate() {
        if let Some(part) = p {
            let _ = writeln!(
                s,
                "  {}: type 0x{:02X} lba {} sectors {} boot {}",
                i + 1,
                part.part_type,
                part.lba_start,
                part.sectors,
                if part.bootable { "yes" } else { "no" }
            );
        }
    }
    let _ = writeln!(s, "GPT:");
    for (i, p) in gpt.iter().enumerate() {
        if let Some(part) = p {
            let name = gpt_name_to_string(&part.name);
            let _ = writeln!(s, "  {}: lba {}-{} name {}", i + 1, part.first_lba, part.last_lba, name);
        }
    }
    Ok(s)
}

fn gpt_name_to_string(name: &[u8; 36]) -> String {
    let mut s = String::new();
    for &b in name.iter() {
        if b == 0 {
            break;
        }
        s.push(b as char);
    }
    if s.is_empty() {
        s.push_str("<unnamed>");
    }
    s
}

fn normalize_subpath(subpath: &str) -> String {
    if subpath.is_empty() {
        return "/".to_string();
    }
    if subpath.starts_with('/') {
        subpath.to_string()
    } else {
        let mut s = String::from("/");
        s.push_str(subpath);
        s
    }
}

fn virtio_read_at(offset: usize, out: &mut [u8]) -> Result<usize, &'static str> {
    let sectors = virtio_blk::capacity_sectors().ok_or("No capacity info")?;
    let total_bytes = (sectors as usize).saturating_mul(512);
    if offset >= total_bytes {
        return Ok(0);
    }
    let max_len = min(out.len(), total_bytes - offset);
    let mut remaining = max_len;
    let mut pos = offset;
    let mut out_off = 0;

    let mut sector_buf = [0u8; 512];
    while remaining > 0 {
        let lba = (pos / 512) as u64;
        let sector_off = pos % 512;
        virtio_blk::read_sector(lba, &mut sector_buf)?;
        let chunk = min(remaining, 512 - sector_off);
        out[out_off..out_off + chunk].copy_from_slice(&sector_buf[sector_off..sector_off + chunk]);
        pos += chunk;
        out_off += chunk;
        remaining -= chunk;
    }
    Ok(max_len)
}

fn virtio_write_at(offset: usize, data: &[u8]) -> Result<usize, &'static str> {
    let sectors = virtio_blk::capacity_sectors().ok_or("No capacity info")?;
    let total_bytes = (sectors as usize).saturating_mul(512);
    if offset >= total_bytes {
        return Ok(0);
    }
    let max_len = min(data.len(), total_bytes - offset);
    let mut remaining = max_len;
    let mut pos = offset;
    let mut data_off = 0;

    let mut sector_buf = [0u8; 512];
    while remaining > 0 {
        let lba = (pos / 512) as u64;
        let sector_off = pos % 512;
        virtio_blk::read_sector(lba, &mut sector_buf)?;
        let chunk = min(remaining, 512 - sector_off);
        sector_buf[sector_off..sector_off + chunk].copy_from_slice(&data[data_off..data_off + chunk]);
        virtio_blk::write_sector(lba, &sector_buf)?;
        pos += chunk;
        data_off += chunk;
        remaining -= chunk;
    }
    Ok(max_len)
}

// ============================================================================
// Helpers
// ============================================================================

fn normalize_path(path: &str) -> Result<String, &'static str> {
    if !path.starts_with('/') {
        return Err("Path must be absolute");
    }
    let mut out = String::new();
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
                prev_slash = true;
            }
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    Ok(out)
}

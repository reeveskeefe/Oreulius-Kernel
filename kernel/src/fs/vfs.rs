/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Oreulia VFS (Hierarchical Filesystem)
//!
//! Provides a Unix-like inode tree, path resolution, mount points, and
//! per-process file descriptors. Root is an in-memory filesystem; VirtIO
//! block devices can be mounted as a device filesystem.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::fs::{
    FileKey, FilesystemCapability, FilesystemError, FilesystemQuota, FilesystemRights, Request,
    ResponseStatus,
};
use crate::interrupt_dag::{DagSpinlock, InterruptContext, DAG_LEVEL_THREAD, DAG_LEVEL_VFS};

use crate::vfs_platform::{self, Pid};
use crate::virtio_blk;

pub type InodeId = u64;

pub const MAX_NAME_LEN: usize = 64;
const VFS_PERSIST_MAGIC: u32 = 0x4F_56_46_53; // "OVFS"
const VFS_PERSIST_VERSION: u16 = 3;
static NEXT_VFS_STORAGE_NAMESPACE: AtomicU32 = AtomicU32::new(1);
const VFS_STORE_PREFIX: &str = "system/vfs/";
const VFS_SNAPSHOT_KEY: &str = "system/vfs/snapshot.bin";
const VFS_JOURNAL_KEY: &str = "system/vfs/journal.log";
const VFS_JOURNAL_MAX_BYTES_MULTIPLIER: usize = 8;

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

#[derive(Clone, Debug)]
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

    fn symlink_target(&self) -> Result<&str, &'static str> {
        if self.kind != InodeKind::Symlink {
            return Err("Not a symlink");
        }
        core::str::from_utf8(&self.data).map_err(|_| "Invalid symlink target")
    }
}

// ============================================================================
// Mounts
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountBackend {
    VirtioBlock,
}

type MountNodeId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountNodeKind {
    File,
    Directory,
    Symlink,
    VirtioRaw,
    VirtioPartitions,
}

#[derive(Clone, Debug)]
struct MountNode {
    id: MountNodeId,
    kind: MountNodeKind,
    data: Vec<u8>,
    entries: Vec<DirEntry>,
    nlink: u32,
}

impl MountNode {
    fn new(id: MountNodeId, kind: MountNodeKind) -> Self {
        MountNode {
            id,
            kind,
            data: Vec::new(),
            entries: Vec::new(),
            nlink: 1,
        }
    }

    fn symlink_target(&self) -> Result<&str, &'static str> {
        if self.kind != MountNodeKind::Symlink {
            return Err("Not a symlink");
        }
        core::str::from_utf8(&self.data).map_err(|_| "Invalid symlink target")
    }
}

#[derive(Clone, Debug)]
struct VirtioMountState {
    nodes: Vec<Option<MountNode>>,
}

#[derive(Clone, Debug)]
enum MountState {
    VirtioBlock(VirtioMountState),
}

trait MountedBackendContract {
    fn contract_info(&self, path: &str) -> MountContractInfo;
    fn mkdir(&mut self, subpath: &str) -> Result<(), &'static str>;
    fn create_file(&mut self, subpath: &str) -> Result<MountNodeId, &'static str>;
    fn unlink(&mut self, subpath: &str) -> Result<(), &'static str>;
    fn rmdir(&mut self, subpath: &str) -> Result<(), &'static str>;
    fn rename(&mut self, old_subpath: &str, new_subpath: &str) -> Result<(), &'static str>;
    fn link(&mut self, existing_subpath: &str, new_subpath: &str) -> Result<(), &'static str>;
    fn symlink(&mut self, target: &str, link_path: &str) -> Result<(), &'static str>;
    fn readlink(&mut self, subpath: &str) -> Result<String, &'static str>;
    fn open_kind(
        &mut self,
        mount_idx: usize,
        subpath: &str,
        flags: OpenFlags,
        full_path: &str,
    ) -> Result<HandleKind, &'static str>;
    fn list(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str>;
    fn read(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str>;
    fn write(&mut self, subpath: &str, data: &[u8]) -> Result<usize, &'static str>;
    fn write_at(
        &mut self,
        subpath: &str,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, &'static str>;
    fn path_size(&mut self, subpath: &str) -> Result<usize, &'static str>;
}

#[derive(Clone, Debug, Default)]
pub struct MountHealth {
    pub path: String,
    pub backend: &'static str,
    pub reads: u64,
    pub writes: u64,
    pub mutations: u64,
    pub errors: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MountStatus {
    pub contract: MountContractInfo,
    pub health: MountHealth,
}

#[derive(Clone, Debug)]
pub struct MountContractInfo {
    pub path: String,
    pub backend: &'static str,
    pub mutable: bool,
    pub supports_directories: bool,
    pub supports_links: bool,
    pub supports_symlinks: bool,
    pub special_entries: Vec<&'static str>,
}

#[derive(Clone, Debug, Default)]
struct MountHealthCounters {
    reads: u64,
    writes: u64,
    mutations: u64,
    errors: u64,
    last_error: Option<String>,
}

struct Mount {
    path: String,
    backend: MountBackend,
    state: MountState,
    health: MountHealthCounters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountOperation {
    Read,
    Write,
    Mutation,
}

impl MountOperation {
    fn as_str(self) -> &'static str {
        match self {
            MountOperation::Read => "read",
            MountOperation::Write => "write",
            MountOperation::Mutation => "mutation",
        }
    }
}

impl VirtioMountState {
    fn new() -> Self {
        let mut state = VirtioMountState { nodes: Vec::new() };
        state.nodes.push(None);
        let root = state.alloc_node(MountNodeKind::Directory);
        let raw = state.alloc_node(MountNodeKind::VirtioRaw);
        let partitions = state.alloc_node(MountNodeKind::VirtioPartitions);
        let _ = state.add_dir_entry(root, "raw", raw);
        let _ = state.add_dir_entry(root, "partitions", partitions);
        state
    }

    fn alloc_node(&mut self, kind: MountNodeKind) -> MountNodeId {
        let id = self.nodes.len() as MountNodeId;
        self.nodes.push(Some(MountNode::new(id, kind)));
        id
    }

    fn get_node(&self, id: MountNodeId) -> Option<&MountNode> {
        self.nodes.get(id as usize).and_then(|n| n.as_ref())
    }

    fn get_node_mut(&mut self, id: MountNodeId) -> Option<&mut MountNode> {
        self.nodes.get_mut(id as usize).and_then(|n| n.as_mut())
    }

    fn lookup_child(&self, dir_id: MountNodeId, name: &str) -> Result<MountNodeId, &'static str> {
        let node = self.get_node(dir_id).ok_or("Directory not found")?;
        if node.kind != MountNodeKind::Directory {
            return Err("Not a directory");
        }
        node.entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.inode)
            .ok_or("Path component not found")
    }

    fn resolve_path(&self, path: &str) -> Result<MountNodeId, &'static str> {
        self.resolve_path_internal(path, true, 0)
    }

    fn resolve_path_nofollow(&self, path: &str) -> Result<MountNodeId, &'static str> {
        self.resolve_path_internal(path, false, 0)
    }

    fn resolve_path_internal(
        &self,
        path: &str,
        follow_final: bool,
        depth: usize,
    ) -> Result<MountNodeId, &'static str> {
        if depth > 16 {
            return Err("Symlink loop detected");
        }
        let path = normalize_subpath(path);
        if path == "/" {
            return Ok(1);
        }

        let mut current = 1;
        let mut resolved_components: Vec<String> = Vec::new();
        let components: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| c.to_string())
            .collect();

        let mut idx = 0usize;
        while idx < components.len() {
            let comp = &components[idx];
            if comp == "." {
                idx += 1;
                continue;
            }
            if comp == ".." {
                resolved_components.pop();
                current = if resolved_components.is_empty() {
                    1
                } else {
                    self.resolve_path(&components_to_path(&resolved_components))?
                };
                idx += 1;
                continue;
            }

            let next = self.lookup_child(current, comp)?;
            let next_node = self.get_node(next).ok_or("Path component not found")?;
            let is_final = idx + 1 == components.len();

            if next_node.kind == MountNodeKind::Symlink && (!is_final || follow_final) {
                let target = next_node.symlink_target()?;
                let remainder = if is_final {
                    String::new()
                } else {
                    components[idx + 1..].join("/")
                };
                let base = components_to_path(&resolved_components);
                let mut combined = if target.starts_with('/') {
                    normalize_subpath(target)
                } else {
                    join_paths(&base, target)?
                };
                if !remainder.is_empty() {
                    combined = join_paths(&combined, &remainder)?;
                }
                return self.resolve_path_internal(&combined, follow_final, depth + 1);
            }

            current = next;
            resolved_components.push(comp.clone());
            idx += 1;
        }

        Ok(current)
    }

    fn split_parent(path: &str) -> Result<(String, String), &'static str> {
        let path = normalize_subpath(path);
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

    fn add_dir_entry(
        &mut self,
        dir_id: MountNodeId,
        name: &str,
        node_id: MountNodeId,
    ) -> Result<(), &'static str> {
        if name.len() > MAX_NAME_LEN {
            return Err("Name too long");
        }
        let dir = self.get_node_mut(dir_id).ok_or("Directory not found")?;
        if dir.kind != MountNodeKind::Directory {
            return Err("Not a directory");
        }
        if dir.entries.iter().any(|entry| entry.name == name) {
            return Err("Entry exists");
        }
        dir.entries.push(DirEntry {
            name: name.to_string(),
            inode: node_id,
        });
        Ok(())
    }

    fn replace_dir_entry(
        &mut self,
        dir_id: MountNodeId,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), &'static str> {
        if new_name.len() > MAX_NAME_LEN {
            return Err("Name too long");
        }
        let dir = self.get_node_mut(dir_id).ok_or("Directory not found")?;
        if dir.kind != MountNodeKind::Directory {
            return Err("Not a directory");
        }
        if old_name != new_name && dir.entries.iter().any(|entry| entry.name == new_name) {
            return Err("Entry exists");
        }
        let entry = dir
            .entries
            .iter_mut()
            .find(|entry| entry.name == old_name)
            .ok_or("Path component not found")?;
        entry.name = new_name.to_string();
        Ok(())
    }

    fn remove_dir_entry(
        &mut self,
        dir_id: MountNodeId,
        name: &str,
    ) -> Result<MountNodeId, &'static str> {
        let dir = self.get_node_mut(dir_id).ok_or("Directory not found")?;
        if dir.kind != MountNodeKind::Directory {
            return Err("Not a directory");
        }
        let idx = dir
            .entries
            .iter()
            .position(|entry| entry.name == name)
            .ok_or("Path component not found")?;
        Ok(dir.entries.remove(idx).inode)
    }

    fn node_size(&self, node_id: MountNodeId) -> Result<usize, &'static str> {
        let node = self.get_node(node_id).ok_or("File not found")?;
        match node.kind {
            MountNodeKind::File | MountNodeKind::Symlink => Ok(node.data.len()),
            MountNodeKind::VirtioRaw => {
                let sectors = virtio_blk::capacity_sectors().ok_or("No capacity info")?;
                Ok((sectors as usize).saturating_mul(512))
            }
            MountNodeKind::VirtioPartitions => Ok(generate_partition_text()?.len()),
            MountNodeKind::Directory => Err("Not a file"),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), &'static str> {
        let node_count = self.nodes.iter().flatten().count() as u32;
        out.extend_from_slice(&node_count.to_le_bytes());
        for node in self.nodes.iter().flatten() {
            out.extend_from_slice(&node.id.to_le_bytes());
            out.push(match node.kind {
                MountNodeKind::File => 0,
                MountNodeKind::Directory => 1,
                MountNodeKind::Symlink => 2,
                MountNodeKind::VirtioRaw => 3,
                MountNodeKind::VirtioPartitions => 4,
            });
            out.extend_from_slice(&node.nlink.to_le_bytes());
            let data_len =
                u32::try_from(node.data.len()).map_err(|_| "Persistent mount state too large")?;
            out.extend_from_slice(&data_len.to_le_bytes());
            let entry_count = u32::try_from(node.entries.len())
                .map_err(|_| "Persistent mount state too large")?;
            out.extend_from_slice(&entry_count.to_le_bytes());
            out.extend_from_slice(&node.data);
            for entry in &node.entries {
                let name_bytes = entry.name.as_bytes();
                let name_len = u16::try_from(name_bytes.len())
                    .map_err(|_| "Persistent mount entry name too long")?;
                out.extend_from_slice(&name_len.to_le_bytes());
                out.extend_from_slice(name_bytes);
                out.extend_from_slice(&entry.inode.to_le_bytes());
            }
        }
        Ok(())
    }

    fn decode_from(data: &[u8], cursor: &mut usize) -> Option<Self> {
        let node_count = read_u32(data, *cursor)? as usize;
        *cursor += 4;
        let mut max_id = 0usize;
        let mut decoded_nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let id = read_u64(data, *cursor)?;
            *cursor += 8;
            let kind = match *data.get(*cursor)? {
                0 => MountNodeKind::File,
                1 => MountNodeKind::Directory,
                2 => MountNodeKind::Symlink,
                3 => MountNodeKind::VirtioRaw,
                4 => MountNodeKind::VirtioPartitions,
                _ => return None,
            };
            *cursor += 1;
            let nlink = read_u32(data, *cursor)?;
            *cursor += 4;
            let data_len = read_u32(data, *cursor)? as usize;
            *cursor += 4;
            let entry_count = read_u32(data, *cursor)? as usize;
            *cursor += 4;
            if cursor.saturating_add(data_len) > data.len() {
                return None;
            }
            let node_data = data[*cursor..*cursor + data_len].to_vec();
            *cursor += data_len;
            let mut entries = Vec::with_capacity(entry_count);
            for _ in 0..entry_count {
                let name_len = read_u16(data, *cursor)? as usize;
                *cursor += 2;
                if cursor.saturating_add(name_len) > data.len() {
                    return None;
                }
                let name = core::str::from_utf8(&data[*cursor..*cursor + name_len])
                    .ok()?
                    .to_string();
                *cursor += name_len;
                let inode = read_u64(data, *cursor)?;
                *cursor += 8;
                entries.push(DirEntry { name, inode });
            }
            let mut node = MountNode::new(id, kind);
            node.nlink = nlink;
            node.data = node_data;
            node.entries = entries;
            max_id = max_id.max(id as usize);
            decoded_nodes.push((id as usize, node));
        }

        let mut nodes = vec![None; max_id.saturating_add(1).max(2)];
        for (idx, node) in decoded_nodes {
            if idx >= nodes.len() {
                return None;
            }
            nodes[idx] = Some(node);
        }
        if nodes.get(1).and_then(|node| node.as_ref()).is_none() {
            return None;
        }
        Some(VirtioMountState { nodes })
    }
}

impl MountedBackendContract for VirtioMountState {
    fn contract_info(&self, path: &str) -> MountContractInfo {
        MountContractInfo {
            path: path.to_string(),
            backend: "virtio-block",
            mutable: true,
            supports_directories: true,
            supports_links: true,
            supports_symlinks: true,
            special_entries: vec!["raw", "partitions"],
        }
    }

    fn mkdir(&mut self, subpath: &str) -> Result<(), &'static str> {
        let (parent, name) = VirtioMountState::split_parent(subpath)?;
        let parent_id = self.resolve_path(&parent)?;
        let node_id = self.alloc_node(MountNodeKind::Directory);
        self.add_dir_entry(parent_id, &name, node_id)
    }

    fn create_file(&mut self, subpath: &str) -> Result<MountNodeId, &'static str> {
        let (parent, name) = VirtioMountState::split_parent(subpath)?;
        let parent_id = self.resolve_path(&parent)?;
        let node_id = self.alloc_node(MountNodeKind::File);
        self.add_dir_entry(parent_id, &name, node_id)?;
        Ok(node_id)
    }

    fn unlink(&mut self, subpath: &str) -> Result<(), &'static str> {
        let subpath = normalize_subpath(subpath);
        if subpath == "/" {
            return Err("Cannot delete mount root");
        }
        let node_id = self.resolve_path_nofollow(&subpath)?;
        let node = self.get_node(node_id).ok_or("File not found")?;
        match node.kind {
            MountNodeKind::Directory => return Err("Use rmdir for directories"),
            MountNodeKind::VirtioRaw | MountNodeKind::VirtioPartitions => {
                return Err("Cannot unlink fixed virtio mount entries");
            }
            _ => {}
        }
        let (parent, name) = VirtioMountState::split_parent(&subpath)?;
        let parent_id = self.resolve_path(&parent)?;
        let removed_id = self.remove_dir_entry(parent_id, &name)?;
        if removed_id != node_id {
            return Err("Directory entry mismatch");
        }
        let slot = self
            .nodes
            .get_mut(node_id as usize)
            .ok_or("File not found")?;
        let node = slot.as_mut().ok_or("File not found")?;
        if node.nlink > 1 {
            node.nlink -= 1;
        } else {
            *slot = None;
        }
        Ok(())
    }

    fn rmdir(&mut self, subpath: &str) -> Result<(), &'static str> {
        let subpath = normalize_subpath(subpath);
        if subpath == "/" {
            return Err("Cannot remove mount root");
        }
        let node_id = self.resolve_path_nofollow(&subpath)?;
        let node = self.get_node(node_id).ok_or("Directory not found")?;
        if node.kind != MountNodeKind::Directory {
            return Err("Not a directory");
        }
        if !node.entries.is_empty() {
            return Err("Directory not empty");
        }
        let (parent, name) = VirtioMountState::split_parent(&subpath)?;
        let parent_id = self.resolve_path(&parent)?;
        let removed_id = self.remove_dir_entry(parent_id, &name)?;
        if removed_id != node_id {
            return Err("Directory entry mismatch");
        }
        let slot = self
            .nodes
            .get_mut(node_id as usize)
            .ok_or("Directory not found")?;
        *slot = None;
        Ok(())
    }

    fn rename(&mut self, old_subpath: &str, new_subpath: &str) -> Result<(), &'static str> {
        let old_subpath = normalize_subpath(old_subpath);
        let new_subpath = normalize_subpath(new_subpath);
        if old_subpath == new_subpath {
            return Ok(());
        }
        if old_subpath == "/" || new_subpath == "/" {
            return Err("Cannot rename mount root");
        }
        let node_id = self.resolve_path_nofollow(&old_subpath)?;
        let node = self.get_node(node_id).ok_or("Path component not found")?;
        if matches!(
            node.kind,
            MountNodeKind::VirtioRaw | MountNodeKind::VirtioPartitions
        ) {
            return Err("Virtio mount entries are fixed");
        }
        if node.kind == MountNodeKind::Directory
            && (new_subpath == old_subpath
                || new_subpath
                    .strip_prefix(&old_subpath)
                    .is_some_and(|suffix| suffix.starts_with('/')))
        {
            return Err("Cannot move directory into itself");
        }
        let (old_parent, old_name) = VirtioMountState::split_parent(&old_subpath)?;
        let (new_parent, new_name) = VirtioMountState::split_parent(&new_subpath)?;
        let old_parent_id = self.resolve_path(&old_parent)?;
        let new_parent_id = self.resolve_path(&new_parent)?;
        if old_parent_id == new_parent_id {
            self.replace_dir_entry(old_parent_id, &old_name, &new_name)?;
        } else {
            let removed_id = self.remove_dir_entry(old_parent_id, &old_name)?;
            if removed_id != node_id {
                return Err("Directory entry mismatch");
            }
            if let Err(e) = self.add_dir_entry(new_parent_id, &new_name, node_id) {
                let _ = self.add_dir_entry(old_parent_id, &old_name, node_id);
                return Err(e);
            }
        }
        Ok(())
    }

    fn link(&mut self, existing_subpath: &str, new_subpath: &str) -> Result<(), &'static str> {
        let existing_subpath = normalize_subpath(existing_subpath);
        let new_subpath = normalize_subpath(new_subpath);
        let node_id = self.resolve_path_nofollow(&existing_subpath)?;
        let node = self.get_node(node_id).ok_or("File not found")?;
        if node.kind != MountNodeKind::File {
            return Err("Hard links only supported for mounted regular files");
        }
        let (parent, name) = VirtioMountState::split_parent(&new_subpath)?;
        let parent_id = self.resolve_path(&parent)?;
        self.add_dir_entry(parent_id, &name, node_id)?;
        let node = self.get_node_mut(node_id).ok_or("File not found")?;
        node.nlink = node.nlink.saturating_add(1);
        Ok(())
    }

    fn symlink(&mut self, target: &str, link_path: &str) -> Result<(), &'static str> {
        let link_path = normalize_subpath(link_path);
        let (parent, name) = VirtioMountState::split_parent(&link_path)?;
        let parent_id = self.resolve_path(&parent)?;
        let node_id = self.alloc_node(MountNodeKind::Symlink);
        let node = self.get_node_mut(node_id).ok_or("Symlink not found")?;
        node.data.extend_from_slice(target.as_bytes());
        self.add_dir_entry(parent_id, &name, node_id)
    }

    fn readlink(&mut self, subpath: &str) -> Result<String, &'static str> {
        let node_id = self.resolve_path_nofollow(subpath)?;
        let node = self.get_node(node_id).ok_or("File not found")?;
        Ok(node.symlink_target()?.to_string())
    }

    fn open_kind(
        &mut self,
        mount_idx: usize,
        subpath: &str,
        flags: OpenFlags,
        full_path: &str,
    ) -> Result<HandleKind, &'static str> {
        let subpath = normalize_subpath(subpath);
        if subpath == "/" {
            return Err("Cannot open mount root");
        }
        let node_id = self.resolve_path(&subpath)?;
        let node = self.get_node(node_id).ok_or("File not found")?;
        match node.kind {
            MountNodeKind::File => Ok(HandleKind::MountFile {
                mount_idx,
                node_id,
                path: full_path.to_string(),
            }),
            MountNodeKind::Directory => Ok(HandleKind::MountDir { mount_idx, node_id }),
            MountNodeKind::Symlink => Err("Symlink open not supported"),
            MountNodeKind::VirtioRaw => Ok(HandleKind::VirtioRaw {
                path: full_path.to_string(),
            }),
            MountNodeKind::VirtioPartitions => {
                if flags.contains(OpenFlags::WRITE) {
                    Err("Partitions file is read-only")
                } else {
                    Ok(HandleKind::VirtioPartitions {
                        path: full_path.to_string(),
                    })
                }
            }
        }
    }

    fn list(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str> {
        let node_id = self.resolve_path(subpath)?;
        let node = self.get_node(node_id).ok_or("Directory not found")?;
        if node.kind != MountNodeKind::Directory {
            return Err("Not a directory");
        }
        let mut s = String::new();
        for entry in &node.entries {
            let _ = write!(s, "{} ", entry.name);
        }
        let bytes = s.as_bytes();
        let len = min(out.len(), bytes.len());
        out[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }

    fn read(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str> {
        let node_id = self.resolve_path(subpath)?;
        let node = self.get_node(node_id).ok_or("File not found")?;
        match node.kind {
            MountNodeKind::File | MountNodeKind::Symlink => {
                let len = min(out.len(), node.data.len());
                out[..len].copy_from_slice(&node.data[..len]);
                Ok(len)
            }
            MountNodeKind::Directory => Err("Not a file"),
            MountNodeKind::VirtioRaw => virtio_read_at(0, out),
            MountNodeKind::VirtioPartitions => {
                let text = generate_partition_text()?;
                let bytes = text.as_bytes();
                let len = min(out.len(), bytes.len());
                out[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
        }
    }

    fn write(&mut self, subpath: &str, data: &[u8]) -> Result<usize, &'static str> {
        let subpath = normalize_subpath(subpath);
        match self.resolve_path(&subpath) {
            Ok(node_id) => {
                let node_kind = self.get_node(node_id).ok_or("File not found")?.kind;
                match node_kind {
                    MountNodeKind::File => {
                        let node = self.get_node_mut(node_id).ok_or("File not found")?;
                        node.data.clear();
                        node.data.extend_from_slice(data);
                        Ok(data.len())
                    }
                    MountNodeKind::VirtioRaw => virtio_write_at(0, data),
                    MountNodeKind::VirtioPartitions => Err("Partitions file is read-only"),
                    MountNodeKind::Directory => Err("Not a file"),
                    MountNodeKind::Symlink => Err("Not a file"),
                }
            }
            Err(_) => {
                let node_id = self.create_file(&subpath)?;
                let node = self.get_node_mut(node_id).ok_or("File not found")?;
                node.data.extend_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn write_at(
        &mut self,
        subpath: &str,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, &'static str> {
        let node_id = self.resolve_path(subpath)?;
        let node_kind = self.get_node(node_id).ok_or("File not found")?.kind;
        match node_kind {
            MountNodeKind::File => {
                let node = self.get_node_mut(node_id).ok_or("File not found")?;
                if offset > node.data.len() {
                    node.data.resize(offset, 0);
                }
                if offset + data.len() > node.data.len() {
                    node.data.resize(offset + data.len(), 0);
                }
                node.data[offset..offset + data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            MountNodeKind::VirtioRaw => virtio_write_at(offset, data),
            MountNodeKind::VirtioPartitions => Err("Partitions file is read-only"),
            MountNodeKind::Directory => Err("Cannot write directory"),
            MountNodeKind::Symlink => Err("Cannot write symlink"),
        }
    }

    fn path_size(&mut self, subpath: &str) -> Result<usize, &'static str> {
        let node_id = self.resolve_path(subpath)?;
        self.node_size(node_id)
    }
}

impl MountedBackendContract for MountState {
    fn contract_info(&self, path: &str) -> MountContractInfo {
        match self {
            MountState::VirtioBlock(state) => state.contract_info(path),
        }
    }

    fn mkdir(&mut self, subpath: &str) -> Result<(), &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.mkdir(subpath),
        }
    }

    fn create_file(&mut self, subpath: &str) -> Result<MountNodeId, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.create_file(subpath),
        }
    }

    fn unlink(&mut self, subpath: &str) -> Result<(), &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.unlink(subpath),
        }
    }

    fn rmdir(&mut self, subpath: &str) -> Result<(), &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.rmdir(subpath),
        }
    }

    fn rename(&mut self, old_subpath: &str, new_subpath: &str) -> Result<(), &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.rename(old_subpath, new_subpath),
        }
    }

    fn link(&mut self, existing_subpath: &str, new_subpath: &str) -> Result<(), &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.link(existing_subpath, new_subpath),
        }
    }

    fn symlink(&mut self, target: &str, link_path: &str) -> Result<(), &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.symlink(target, link_path),
        }
    }

    fn readlink(&mut self, subpath: &str) -> Result<String, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.readlink(subpath),
        }
    }

    fn open_kind(
        &mut self,
        mount_idx: usize,
        subpath: &str,
        flags: OpenFlags,
        full_path: &str,
    ) -> Result<HandleKind, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.open_kind(mount_idx, subpath, flags, full_path),
        }
    }

    fn list(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.list(subpath, out),
        }
    }

    fn read(&mut self, subpath: &str, out: &mut [u8]) -> Result<usize, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.read(subpath, out),
        }
    }

    fn write(&mut self, subpath: &str, data: &[u8]) -> Result<usize, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.write(subpath, data),
        }
    }

    fn write_at(
        &mut self,
        subpath: &str,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.write_at(subpath, offset, data),
        }
    }

    fn path_size(&mut self, subpath: &str) -> Result<usize, &'static str> {
        match self {
            MountState::VirtioBlock(state) => state.path_size(subpath),
        }
    }
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

#[derive(Clone, Debug)]
enum HandleKind {
    MemFile {
        inode: InodeId,
        path: String,
    },
    MemDir {
        inode: InodeId,
    },
    MountFile {
        mount_idx: usize,
        node_id: MountNodeId,
        path: String,
    },
    MountDir {
        mount_idx: usize,
        node_id: MountNodeId,
    },
    VirtioRaw {
        path: String,
    },
    VirtioPartitions {
        path: String,
    },
}

#[derive(Clone, Debug)]
struct Handle {
    kind: HandleKind,
    pos: usize,
    flags: OpenFlags,
    owner: Pid,
    capability: FilesystemCapability,
}

// ============================================================================
// Health / Policy
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VfsPolicy {
    /// Maximum size for a single in-memory VFS file.
    ///
    /// `None` means unbounded.
    pub max_mem_file_size: Option<usize>,
}

impl VfsPolicy {
    pub const fn unbounded() -> Self {
        VfsPolicy {
            max_mem_file_size: None,
        }
    }

    pub const fn bounded(max_mem_file_size: usize) -> Self {
        VfsPolicy {
            max_mem_file_size: Some(max_mem_file_size),
        }
    }

    pub fn runtime_default() -> Self {
        let (heap_start, heap_end) = crate::runtime_heap_range();
        if heap_end > heap_start {
            let heap_bytes = heap_end - heap_start;
            let suggested = (heap_bytes / 8).max(crate::runtime_page_size());
            VfsPolicy::bounded(suggested)
        } else {
            VfsPolicy::unbounded()
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct VfsHealth {
    pub total_inode_slots: usize,
    pub live_inodes: usize,
    pub file_count: usize,
    pub directory_count: usize,
    pub symlink_count: usize,
    pub total_bytes: usize,
    pub open_handles: usize,
    pub mount_count: usize,
    pub orphaned_inodes: usize,
    pub max_mem_file_size: Option<usize>,
    pub mount_health: Vec<MountHealth>,
}

#[derive(Clone, Debug, Default)]
pub struct VfsFsckReport {
    pub inodes_scanned: usize,
    pub dangling_entries_removed: usize,
    pub orphaned_inodes_relinked: usize,
    pub nlink_repairs: usize,
    pub size_repairs: usize,
    pub lost_found_created: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VfsAccess {
    Read,
    Write,
    List,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfsWatchKind {
    Read,
    Write,
    List,
    Create,
    Delete,
    Rename,
    Link,
    Symlink,
    ReadLink,
    Mkdir,
    Rmdir,
    Mount,
}

#[derive(Clone, Debug)]
struct VfsWatch {
    id: u64,
    path: String,
    recursive: bool,
}

#[derive(Clone, Debug)]
pub struct VfsWatchInfo {
    pub id: u64,
    pub path: String,
    pub recursive: bool,
}

#[derive(Clone, Debug)]
pub struct VfsWatchEvent {
    pub sequence: u64,
    pub watch_id: u64,
    pub kind: VfsWatchKind,
    pub path: String,
    pub detail: Option<String>,
}

#[derive(Clone, Debug)]
struct VfsWatchSubscriber {
    channel_id: u32,
    backlog: VecDeque<VfsWatchEvent>,
    in_flight: Option<u64>,
    last_acked_sequence: u64,
    dropped_count: u64,
}

impl VfsWatchSubscriber {
    fn new(channel_id: u32) -> Self {
        Self {
            channel_id,
            backlog: VecDeque::new(),
            in_flight: None,
            last_acked_sequence: 0,
            dropped_count: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VfsWatchSubscriberInfo {
    pub channel_id: u32,
    pub pending_events: usize,
    pub in_flight: Option<u64>,
    pub last_acked_sequence: u64,
    pub dropped_count: u64,
}

#[derive(Clone, Debug)]
struct CapabilityMapper {
    directory_caps: BTreeMap<InodeId, FilesystemCapability>,
    process_caps: BTreeMap<u32, FilesystemCapability>,
    default_capability: FilesystemCapability,
}

impl CapabilityMapper {
    fn runtime_default() -> Self {
        CapabilityMapper {
            directory_caps: BTreeMap::new(),
            process_caps: BTreeMap::new(),
            default_capability: crate::fs::filesystem().root_capability(),
        }
    }
}

// ============================================================================
// VFS Core
// ============================================================================

struct Vfs {
    inodes: Vec<Option<Inode>>,
    mounts: Vec<Mount>,
    handles: Vec<Option<Handle>>,
    policy: Option<VfsPolicy>,
    capability_mapper: Option<CapabilityMapper>,
    storage_namespace: u64,
    watches: BTreeMap<u64, VfsWatch>,
    watch_events: VecDeque<VfsWatchEvent>,
    notify_channels: BTreeMap<u32, VfsWatchSubscriber>,
    next_watch_id: u64,
    next_watch_event_sequence: u64,
}

impl Vfs {
    const fn new() -> Self {
        Vfs {
            inodes: Vec::new(),
            mounts: Vec::new(),
            handles: Vec::new(),
            policy: None,
            capability_mapper: None,
            storage_namespace: 0,
            watches: BTreeMap::new(),
            watch_events: VecDeque::new(),
            notify_channels: BTreeMap::new(),
            next_watch_id: 1,
            next_watch_event_sequence: 1,
        }
    }

    fn init(&mut self) {
        if self.policy.is_none() {
            self.policy = Some(VfsPolicy::runtime_default());
        }
        if self.capability_mapper.is_none() {
            self.capability_mapper = Some(CapabilityMapper::runtime_default());
        }
        if self.storage_namespace == 0 {
            self.storage_namespace = allocate_vfs_storage_namespace();
        }
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

    fn inode_payload_key(&self, inode_id: InodeId) -> Result<FileKey, &'static str> {
        inode_payload_key_for_namespace(self.storage_namespace, inode_id)
    }

    fn inode_payload_len(&self, inode_id: InodeId) -> Result<usize, &'static str> {
        let inode = self.get_inode(inode_id).ok_or("File not found")?;
        Ok(match inode.kind {
            InodeKind::File => usize::try_from(inode.meta.size).unwrap_or(usize::MAX),
            InodeKind::Symlink => inode.data.len(),
            InodeKind::Directory => 0,
        })
    }

    fn read_file_payload(&self, inode_id: InodeId) -> Result<Vec<u8>, &'static str> {
        let inode = self.get_inode(inode_id).ok_or("File not found")?;
        if inode.kind != InodeKind::File {
            return Err("Not a file");
        }
        if !inode.data.is_empty() {
            return Ok(inode.data.clone());
        }

        let key = self.inode_payload_key(inode_id)?;
        let response = crate::fs::filesystem().handle_request(Request::read(
            key,
            crate::fs::filesystem().root_capability(),
        ));
        match response.status {
            ResponseStatus::Ok => Ok(response.data),
            ResponseStatus::Error(FilesystemError::NotFound) if inode.meta.size == 0 => {
                Ok(Vec::new())
            }
            ResponseStatus::Error(FilesystemError::NotFound) => Err("VFS payload missing"),
            ResponseStatus::Error(FilesystemError::PermissionDenied) => {
                Err("VFS payload read denied")
            }
            ResponseStatus::Error(_) => Err("VFS payload read failed"),
        }
    }

    fn write_file_payload(
        &mut self,
        inode_id: InodeId,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        let inode = self.get_inode(inode_id).ok_or("File not found")?;
        if inode.kind != InodeKind::File {
            return Err("Not a file");
        }
        let key = self.inode_payload_key(inode_id)?;
        let response = if payload.is_empty() {
            crate::fs::filesystem().handle_request(Request::delete(
                key,
                crate::fs::filesystem().root_capability(),
            ))
        } else {
            let request = Request::write(key, payload, crate::fs::filesystem().root_capability())
                .map_err(|_| "VFS payload request invalid")?;
            crate::fs::filesystem().handle_request(request)
        };
        match response.status {
            ResponseStatus::Ok => {}
            ResponseStatus::Error(FilesystemError::NotFound) if payload.is_empty() => {}
            ResponseStatus::Error(FilesystemError::PermissionDenied) => {
                return Err("VFS payload write denied")
            }
            ResponseStatus::Error(_) => return Err("VFS payload write failed"),
        }

        let inode = self.get_inode_mut(inode_id).ok_or("File not found")?;
        inode.data.clear();
        inode.meta.size = payload.len() as u64;
        inode.meta.mtime = 0;
        Ok(())
    }

    fn delete_file_payload(&mut self, inode_id: InodeId) {
        let Ok(key) = self.inode_payload_key(inode_id) else {
            return;
        };
        let _ = crate::fs::filesystem().handle_request(Request::delete(
            key,
            crate::fs::filesystem().root_capability(),
        ));
        if let Some(inode) = self.get_inode_mut(inode_id) {
            inode.data.clear();
            inode.meta.size = 0;
        }
    }

    fn migrate_inline_file_payloads(&mut self) -> Result<(), &'static str> {
        let payloads: Vec<(InodeId, Vec<u8>)> = self
            .inodes
            .iter()
            .flatten()
            .filter(|inode| inode.kind == InodeKind::File && !inode.data.is_empty())
            .map(|inode| (inode.id, inode.data.clone()))
            .collect();
        for (inode_id, payload) in payloads {
            self.write_file_payload(inode_id, &payload)?;
        }
        Ok(())
    }

    fn effective_policy(&self) -> VfsPolicy {
        self.policy.unwrap_or_else(VfsPolicy::runtime_default)
    }

    fn watch_event_capacity(&self) -> usize {
        (crate::runtime_page_size() / core::mem::size_of::<VfsWatchEvent>()).max(16)
    }

    fn trim_watch_events(&mut self) {
        let cap = self.watch_event_capacity();
        while self.watch_events.len() > cap {
            self.watch_events.pop_front();
        }
    }

    fn trim_notify_backlog(subscriber: &mut VfsWatchSubscriber, cap: usize) {
        while subscriber.backlog.len() > cap {
            let drop_front = subscriber
                .backlog
                .front()
                .map(|event| Some(event.sequence) != subscriber.in_flight)
                .unwrap_or(true);
            if drop_front {
                subscriber.backlog.pop_front();
            } else {
                subscriber.backlog.pop_back();
            }
            subscriber.dropped_count = subscriber.dropped_count.saturating_add(1);
        }
    }

    fn next_watch_sequence(&mut self) -> u64 {
        let sequence = self.next_watch_event_sequence;
        self.next_watch_event_sequence = self.next_watch_event_sequence.saturating_add(1);
        sequence
    }

    fn path_matches_watch(watch: &VfsWatch, path: &str) -> bool {
        if watch.path == path {
            return true;
        }
        watch.recursive
            && path
                .strip_prefix(watch.path.as_str())
                .is_some_and(|suffix| watch.path == "/" || suffix.starts_with('/'))
    }

    fn record_watch_event(&mut self, kind: VfsWatchKind, path: &str, detail: Option<String>) {
        let export_event = VfsWatchEvent {
            sequence: self.next_watch_sequence(),
            watch_id: 0,
            kind,
            path: path.to_string(),
            detail: detail.clone(),
        };
        self.broadcast_watch_event(&export_event);
        self.emit_watch_telemetry(&export_event);

        let watch_ids: Vec<u64> = self
            .watches
            .values()
            .filter(|watch| Self::path_matches_watch(watch, path))
            .map(|watch| watch.id)
            .collect();
        for watch_id in watch_ids {
            let sequence = self.next_watch_sequence();
            self.watch_events.push_back(VfsWatchEvent {
                sequence,
                watch_id,
                kind,
                path: path.to_string(),
                detail: detail.clone(),
            });
        }
        self.trim_watch_events();
    }

    fn add_watch(&mut self, path: &str, recursive: bool) -> Result<u64, &'static str> {
        let normalized = normalize_path(path)?;
        let id = self.next_watch_id;
        self.next_watch_id = self.next_watch_id.saturating_add(1);
        self.watches.insert(
            id,
            VfsWatch {
                id,
                path: normalized,
                recursive,
            },
        );
        Ok(id)
    }

    fn remove_watch(&mut self, id: u64) -> bool {
        self.watches.remove(&id).is_some()
    }

    fn list_watches(&self) -> Vec<VfsWatchInfo> {
        self.watches
            .values()
            .map(|watch| VfsWatchInfo {
                id: watch.id,
                path: watch.path.clone(),
                recursive: watch.recursive,
            })
            .collect()
    }

    fn recent_watch_events(&self, limit: usize) -> Vec<VfsWatchEvent> {
        let start = self.watch_events.len().saturating_sub(limit);
        self.watch_events.iter().skip(start).cloned().collect()
    }

    fn subscribe_notify_channel(&mut self, channel_id: u32) -> Result<(), &'static str> {
        let cap = crate::capability::resolve_channel_capability(
            crate::ipc::ProcessId::KERNEL,
            crate::ipc::ChannelId::new(channel_id),
            crate::capability::ChannelAccess::Send,
        )?;
        crate::ipc::ipc()
            .channel_stats(&cap)
            .map_err(|_| "Invalid channel")?;
        self.notify_channels
            .entry(channel_id)
            .or_insert_with(|| VfsWatchSubscriber::new(channel_id));
        Ok(())
    }

    fn unsubscribe_notify_channel(&mut self, channel_id: u32) -> bool {
        self.notify_channels.remove(&channel_id).is_some()
    }

    fn list_notify_channels(&self) -> Vec<u32> {
        self.notify_channels.keys().copied().collect()
    }

    fn list_notify_subscribers(&self) -> Vec<VfsWatchSubscriberInfo> {
        self.notify_channels
            .values()
            .map(|subscriber| VfsWatchSubscriberInfo {
                channel_id: subscriber.channel_id,
                pending_events: subscriber.backlog.len(),
                in_flight: subscriber.in_flight,
                last_acked_sequence: subscriber.last_acked_sequence,
                dropped_count: subscriber.dropped_count,
            })
            .collect()
    }

    fn notify_channel_stats(
        &self,
        channel_id: u32,
    ) -> Result<VfsWatchSubscriberInfo, &'static str> {
        let subscriber = self
            .notify_channels
            .get(&channel_id)
            .ok_or("Channel not subscribed")?;
        Ok(VfsWatchSubscriberInfo {
            channel_id: subscriber.channel_id,
            pending_events: subscriber.backlog.len(),
            in_flight: subscriber.in_flight,
            last_acked_sequence: subscriber.last_acked_sequence,
            dropped_count: subscriber.dropped_count,
        })
    }

    fn ack_notify_channel(&mut self, channel_id: u32, sequence: u64) -> Result<(), &'static str> {
        {
            let subscriber = self
                .notify_channels
                .get_mut(&channel_id)
                .ok_or("Channel not subscribed")?;
            if sequence <= subscriber.last_acked_sequence {
                return Ok(());
            }
            match subscriber.in_flight {
                Some(in_flight) if in_flight == sequence => {
                    let Some(front) = subscriber.backlog.front() else {
                        subscriber.in_flight = None;
                        subscriber.last_acked_sequence = sequence;
                        return Ok(());
                    };
                    if front.sequence != sequence {
                        return Err("Watch subscriber backlog out of sync");
                    }
                    subscriber.backlog.pop_front();
                    subscriber.in_flight = None;
                    subscriber.last_acked_sequence = sequence;
                }
                Some(_) => return Err("Watch ACK sequence mismatch"),
                None => return Err("No in-flight watch event"),
            }
        }
        self.drain_notify_backlogs();
        Ok(())
    }

    fn broadcast_watch_event(&mut self, event: &VfsWatchEvent) {
        if self.notify_channels.is_empty() {
            return;
        }
        let backlog_cap = self.watch_event_capacity();
        for subscriber in self.notify_channels.values_mut() {
            subscriber.backlog.push_back(event.clone());
            Self::trim_notify_backlog(subscriber, backlog_cap);
        }
        self.drain_notify_backlogs();
    }

    fn drain_notify_backlogs(&mut self) {
        let mut stale_channels = Vec::new();
        for (channel_id, subscriber) in self.notify_channels.iter_mut() {
            if subscriber.in_flight.is_some() {
                continue;
            }
            let capability = match crate::capability::resolve_channel_capability(
                crate::ipc::ProcessId::KERNEL,
                crate::ipc::ChannelId::new(*channel_id),
                crate::capability::ChannelAccess::Send,
            ) {
                Ok(cap) => cap,
                Err(_) => {
                    stale_channels.push(*channel_id);
                    continue;
                }
            };
            let Some(pending) = subscriber.backlog.front().cloned() else {
                continue;
            };
            let payload = encode_watch_event_payload(&pending);
            let Ok(message) =
                crate::ipc::Message::with_data(crate::ipc::ProcessId::KERNEL, &payload)
            else {
                continue;
            };
            match crate::ipc::ipc().send(message, &capability) {
                Ok(()) => {
                    subscriber.in_flight = Some(pending.sequence);
                }
                Err(crate::ipc::IpcError::WouldBlock) => {}
                Err(crate::ipc::IpcError::InvalidCap | crate::ipc::IpcError::Closed) => {
                    stale_channels.push(*channel_id);
                }
                Err(_) => {}
            }
        }
        for channel_id in stale_channels {
            self.unsubscribe_notify_channel(channel_id);
        }
    }

    fn emit_watch_telemetry(&self, event: &VfsWatchEvent) {
        let pid = vfs_platform::current_pid()
            .map(vfs_platform::pid_to_raw)
            .unwrap_or(crate::ipc::ProcessId::KERNEL.0);
        let score = event
            .detail
            .as_ref()
            .map(|detail| detail.len())
            .unwrap_or(event.path.len())
            .min(u8::MAX as usize) as u8;
        let summary = crate::wait_free_ring::TelemetryEvent::new(
            pid,
            watch_kind_code(event.kind),
            crate::wait_free_ring::TELEMETRY_CAP_TYPE_VFS_WATCH,
            score,
            vfs_platform::ticks_now(),
        );
        let _ = crate::wait_free_ring::TELEMETRY_RING.push(summary);
    }

    fn capability_mapper(&self) -> &CapabilityMapper {
        self.capability_mapper
            .as_ref()
            .expect("VFS capability mapper not initialized")
    }

    fn capability_mapper_mut(&mut self) -> &mut CapabilityMapper {
        self.capability_mapper
            .as_mut()
            .expect("VFS capability mapper not initialized")
    }

    fn max_mem_file_size(&self) -> Option<usize> {
        self.effective_policy().max_mem_file_size
    }

    fn ensure_file_size_allowed(&self, new_size: usize) -> Result<(), &'static str> {
        if let Some(limit) = self.max_mem_file_size() {
            if new_size > limit {
                return Err("Configured VFS file size limit exceeded");
            }
        }
        Ok(())
    }

    fn set_directory_capability_by_inode(
        &mut self,
        inode_id: InodeId,
        capability: FilesystemCapability,
    ) -> Result<(), &'static str> {
        let inode = self.get_inode(inode_id).ok_or("Directory not found")?;
        if inode.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        self.capability_mapper_mut()
            .directory_caps
            .insert(inode_id, capability);
        Ok(())
    }

    fn directory_capability_by_inode(
        &self,
        inode_id: InodeId,
    ) -> Result<Option<FilesystemCapability>, &'static str> {
        let inode = self.get_inode(inode_id).ok_or("Directory not found")?;
        if inode.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        Ok(self
            .capability_mapper()
            .directory_caps
            .get(&inode_id)
            .cloned())
    }

    fn clear_directory_capability_by_inode(
        &mut self,
        inode_id: InodeId,
    ) -> Result<(), &'static str> {
        let inode = self.get_inode(inode_id).ok_or("Directory not found")?;
        if inode.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        self.capability_mapper_mut()
            .directory_caps
            .remove(&inode_id);
        Ok(())
    }

    fn set_process_capability(&mut self, pid: Pid, capability: FilesystemCapability) {
        self.capability_mapper_mut()
            .process_caps
            .insert(pid_key(pid), capability);
    }

    fn clear_process_capability(&mut self, pid: Pid) {
        self.capability_mapper_mut()
            .process_caps
            .remove(&pid_key(pid));
    }

    fn process_capability(&self, pid: Pid) -> Option<FilesystemCapability> {
        self.capability_mapper()
            .process_caps
            .get(&pid_key(pid))
            .cloned()
    }

    fn inherit_process_capability(
        &mut self,
        parent_pid: Pid,
        child_pid: Pid,
        attenuate: Option<FilesystemRights>,
    ) {
        let parent_cap = self
            .capability_mapper()
            .process_caps
            .get(&pid_key(parent_pid))
            .cloned()
            .unwrap_or_else(|| self.capability_mapper().default_capability.clone());
        let child_cap = if let Some(rights) = attenuate {
            let cap_id = parent_cap.cap_id;
            attenuate_capability(parent_cap, &FilesystemCapability::new(cap_id, rights))
        } else {
            parent_cap
        };
        self.set_process_capability(child_pid, child_cap);
    }

    fn resolve_process_capability(&self, pid: Option<Pid>) -> FilesystemCapability {
        if let Some(pid) = pid {
            self.capability_mapper()
                .process_caps
                .get(&pid_key(pid))
                .cloned()
                .unwrap_or_else(|| self.capability_mapper().default_capability.clone())
        } else {
            self.capability_mapper().default_capability.clone()
        }
    }

    fn resolve_path(&self, path: &str) -> Result<InodeId, &'static str> {
        self.resolve_path_internal(path, true, 0)
    }

    fn resolve_path_nofollow(&self, path: &str) -> Result<InodeId, &'static str> {
        self.resolve_path_internal(path, false, 0)
    }

    fn lookup_child(&self, dir_id: InodeId, name: &str) -> Result<InodeId, &'static str> {
        let inode = self.get_inode(dir_id).ok_or("Directory not found")?;
        if inode.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        inode
            .entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.inode)
            .ok_or("Path component not found")
    }

    fn resolve_path_internal(
        &self,
        path: &str,
        follow_final: bool,
        depth: usize,
    ) -> Result<InodeId, &'static str> {
        if depth > 16 {
            return Err("Symlink loop detected");
        }
        let path = normalize_path(path)?;
        if path == "/" {
            return Ok(1);
        }

        let mut current = 1;
        let mut inode_stack: Vec<InodeId> = vec![1];
        let mut resolved_components: Vec<String> = Vec::new();
        let components: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| c.to_string())
            .collect();

        let mut idx = 0usize;
        while idx < components.len() {
            let comp = &components[idx];
            if comp == "." {
                idx += 1;
                continue;
            }
            if comp == ".." {
                if inode_stack.len() > 1 {
                    inode_stack.pop();
                    resolved_components.pop();
                    current = *inode_stack.last().unwrap();
                }
                idx += 1;
                continue;
            }

            let next = self.lookup_child(current, comp)?;
            let next_inode = self.get_inode(next).ok_or("Path component not found")?;
            let is_final = idx + 1 == components.len();

            if next_inode.kind == InodeKind::Symlink && (!is_final || follow_final) {
                let target = next_inode.symlink_target()?;
                let remainder = if is_final {
                    String::new()
                } else {
                    components[idx + 1..].join("/")
                };
                let base = components_to_path(&resolved_components);
                let mut combined = if target.starts_with('/') {
                    normalize_path(target)?
                } else {
                    join_paths(&base, target)?
                };
                if !remainder.is_empty() {
                    combined = join_paths(&combined, &remainder)?;
                }
                return self.resolve_path_internal(&combined, follow_final, depth + 1);
            }

            current = next;
            inode_stack.push(current);
            resolved_components.push(comp.clone());
            idx += 1;
        }

        Ok(current)
    }

    fn resolve_path_chain(
        &self,
        path: &str,
        follow_final: bool,
    ) -> Result<Vec<InodeId>, &'static str> {
        let normalized = normalize_path(path)?;
        if normalized == "/" {
            return Ok(vec![1]);
        }

        let mut chain = Vec::new();
        chain.push(1);

        let components: Vec<&str> = normalized.split('/').filter(|c| !c.is_empty()).collect();
        let mut prefix = String::new();
        for (idx, component) in components.iter().enumerate() {
            prefix.push('/');
            prefix.push_str(component);
            let is_final = idx + 1 == components.len();
            let inode_id = if is_final && !follow_final {
                self.resolve_path_nofollow(&prefix)?
            } else {
                self.resolve_path(&prefix)?
            };
            chain.push(inode_id);
        }

        Ok(chain)
    }

    fn resolve_parent_chain(&self, path: &str) -> Result<Vec<InodeId>, &'static str> {
        let (parent, _) = Vfs::split_parent(path)?;
        self.resolve_path_chain(&parent, true)
    }

    fn resolve_authority_chain(
        &self,
        path: &str,
        follow_final: bool,
    ) -> Result<Vec<InodeId>, &'static str> {
        let normalized = normalize_path(path)?;
        if let Some((mount_idx, _, _)) = self.find_mount(&normalized) {
            let mount_path = self
                .mounts
                .get(mount_idx)
                .ok_or("Mount not found")?
                .path
                .clone();
            return self.resolve_path_chain(&mount_path, true);
        }
        self.resolve_path_chain(&normalized, follow_final)
    }

    fn resolve_authority_parent_chain(&self, path: &str) -> Result<Vec<InodeId>, &'static str> {
        let normalized = normalize_path(path)?;
        if let Some((mount_idx, _, _)) = self.find_mount(&normalized) {
            let mount_path = self
                .mounts
                .get(mount_idx)
                .ok_or("Mount not found")?
                .path
                .clone();
            return self.resolve_path_chain(&mount_path, true);
        }
        self.resolve_parent_chain(&normalized)
    }

    fn resolve_capability_for_chain(
        &self,
        pid: Option<Pid>,
        chain: &[InodeId],
    ) -> FilesystemCapability {
        let mut capability = self.resolve_process_capability(pid);
        for inode_id in chain {
            if let Some(dir_cap) = self.capability_mapper().directory_caps.get(inode_id) {
                capability = attenuate_capability(capability, dir_cap);
            }
        }
        capability
    }

    fn ensure_path_rights(
        &self,
        pid: Option<Pid>,
        path: &str,
        chain: &[InodeId],
        required: VfsAccess,
    ) -> Result<FilesystemCapability, &'static str> {
        let capability = self.resolve_capability_for_chain(pid, chain);
        if !capability_allows_path(&capability, path) || !access_allowed(&capability, required) {
            return Err("Permission denied");
        }
        Ok(capability)
    }

    fn handle_kind_path<'a>(kind: &'a HandleKind) -> Option<&'a str> {
        match kind {
            HandleKind::MemFile { path, .. }
            | HandleKind::MountFile { path, .. }
            | HandleKind::VirtioRaw { path }
            | HandleKind::VirtioPartitions { path } => Some(path.as_str()),
            HandleKind::MemDir { .. } | HandleKind::MountDir { .. } => None,
        }
    }

    fn revalidate_handle_access(
        &self,
        pid: Pid,
        kind: &HandleKind,
        required: VfsAccess,
    ) -> Result<(), &'static str> {
        let Some(path) = Self::handle_kind_path(kind) else {
            return Ok(());
        };
        let chain = self.resolve_authority_chain(path, true)?;
        let _ = self.ensure_path_rights(Some(pid), path, &chain, required)?;
        Ok(())
    }

    fn subtree_usage(&self, root_id: InodeId) -> Result<(usize, usize), &'static str> {
        let mut visited = vec![false; self.inodes.len()];
        let mut stack = vec![root_id];
        let mut file_count = 0usize;
        let mut total_bytes = 0usize;

        while let Some(inode_id) = stack.pop() {
            let idx = inode_id as usize;
            if idx >= visited.len() || visited[idx] {
                continue;
            }
            visited[idx] = true;

            let inode = self.get_inode(inode_id).ok_or("Inode not found")?;
            match inode.kind {
                InodeKind::File | InodeKind::Symlink => {
                    file_count = file_count.saturating_add(1);
                    total_bytes =
                        total_bytes.saturating_add(self.inode_payload_len(inode_id).unwrap_or(0));
                }
                InodeKind::Directory => {
                    for entry in &inode.entries {
                        stack.push(entry.inode);
                    }
                }
            }
        }

        Ok((file_count, total_bytes))
    }

    fn collect_quota_scopes(
        &self,
        pid: Option<Pid>,
        chain: &[InodeId],
    ) -> Vec<(InodeId, FilesystemQuota)> {
        let mut scopes = Vec::new();
        let process_cap = self.resolve_process_capability(pid);
        if let Some(quota) = process_cap.quota {
            scopes.push((1, quota));
        }
        for inode_id in chain {
            if let Some(dir_cap) = self.capability_mapper().directory_caps.get(inode_id) {
                if let Some(quota) = dir_cap.quota {
                    scopes.push((*inode_id, quota));
                }
            }
        }
        scopes
    }

    fn ensure_quota_allows(
        &self,
        pid: Option<Pid>,
        chain: &[InodeId],
        old_size: usize,
        new_size: usize,
        creating_file: bool,
    ) -> Result<(), &'static str> {
        for (root_id, quota) in self.collect_quota_scopes(pid, chain) {
            let (file_count, total_bytes) = self.subtree_usage(root_id)?;
            if let Some(limit) = quota.max_single_file_bytes {
                if new_size > limit {
                    return Err("Capability quota exceeded");
                }
            }
            if let Some(limit) = quota.max_total_bytes {
                let adjusted = total_bytes
                    .saturating_sub(old_size)
                    .saturating_add(new_size);
                if adjusted > limit {
                    return Err("Capability quota exceeded");
                }
            }
            if creating_file {
                if let Some(limit) = quota.max_file_count {
                    if file_count.saturating_add(1) > limit {
                        return Err("Capability quota exceeded");
                    }
                }
            }
        }
        Ok(())
    }

    fn rewrite_handle_paths(&mut self, old_path: &str, new_path: &str) {
        for handle in self.handles.iter_mut().flatten() {
            match &mut handle.kind {
                HandleKind::MemFile { path, .. }
                | HandleKind::MountFile { path, .. }
                | HandleKind::VirtioRaw { path }
                | HandleKind::VirtioPartitions { path } => {
                    if let Some(rewritten) = rewrite_path_prefix(path, old_path, new_path) {
                        *path = rewritten;
                    }
                }
                HandleKind::MemDir { .. } | HandleKind::MountDir { .. } => {}
            }
        }
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

    fn add_dir_entry(
        &mut self,
        dir_id: InodeId,
        name: &str,
        inode_id: InodeId,
    ) -> Result<(), &'static str> {
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

    fn replace_dir_entry(
        &mut self,
        dir_id: InodeId,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), &'static str> {
        if new_name.len() > MAX_NAME_LEN {
            return Err("Name too long");
        }
        let dir = self.get_inode_mut(dir_id).ok_or("Directory not found")?;
        if dir.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        if old_name != new_name && dir.entries.iter().any(|e| e.name == new_name) {
            return Err("Entry exists");
        }
        let entry = dir
            .entries
            .iter_mut()
            .find(|entry| entry.name == old_name)
            .ok_or("Path component not found")?;
        entry.name = new_name.to_string();
        Ok(())
    }

    fn remove_dir_entry(&mut self, dir_id: InodeId, name: &str) -> Result<InodeId, &'static str> {
        let dir = self.get_inode_mut(dir_id).ok_or("Directory not found")?;
        if dir.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        let idx = dir
            .entries
            .iter()
            .position(|entry| entry.name == name)
            .ok_or("Path component not found")?;
        Ok(dir.entries.remove(idx).inode)
    }

    fn find_mount(&self, path: &str) -> Option<(usize, MountBackend, String)> {
        let path = normalize_path(path).ok()?;
        let mut best: Option<(usize, MountBackend, String, usize)> = None;
        for (idx, mount) in self.mounts.iter().enumerate() {
            if path == mount.path || path.starts_with(&(mount.path.clone() + "/")) {
                let sub = if path == mount.path {
                    "/".to_string()
                } else {
                    path[mount.path.len()..].to_string()
                };
                let len = mount.path.len();
                if best.as_ref().map(|b| len > b.3).unwrap_or(true) {
                    best = Some((idx, mount.backend, sub, len));
                }
            }
        }
        best.map(|b| (b.0, b.1, b.2))
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

    fn inode_has_open_handles(&self, inode_id: InodeId) -> bool {
        self.handles
            .iter()
            .flatten()
            .any(|handle| match handle.kind {
                HandleKind::MemFile { inode, .. } | HandleKind::MemDir { inode } => {
                    inode == inode_id
                }
                _ => false,
            })
    }

    fn note_mount_success(&mut self, mount_idx: usize, op: MountOperation) {
        let Some(mount) = self.mounts.get_mut(mount_idx) else {
            return;
        };
        match op {
            MountOperation::Read => {
                mount.health.reads = mount.health.reads.saturating_add(1);
            }
            MountOperation::Write => {
                mount.health.writes = mount.health.writes.saturating_add(1);
            }
            MountOperation::Mutation => {
                mount.health.mutations = mount.health.mutations.saturating_add(1);
            }
        }
    }

    fn note_mount_error(
        &mut self,
        mount_idx: usize,
        op: MountOperation,
        subpath: &str,
        error: &str,
    ) {
        let Some(mount) = self.mounts.get_mut(mount_idx) else {
            return;
        };
        mount.health.errors = mount.health.errors.saturating_add(1);
        mount.health.last_error = Some(alloc::format!(
            "{} {} failed: {}",
            op.as_str(),
            normalize_subpath(subpath),
            error
        ));
    }

    fn persist_local_state(&self) {
        let encoded = match self.encode_persistent_state() {
            Ok(v) => v,
            Err(_) => return,
        };
        let Ok(key) = vfs_snapshot_key() else {
            return;
        };
        let Ok(request) = Request::write(key, &encoded, vfs_store_capability()) else {
            return;
        };
        let _ = crate::fs::filesystem().handle_request(request);
    }

    fn record_mutation_journal(&self, op: &str, detail: &str) {
        let Ok(key) = vfs_journal_key() else {
            return;
        };
        let capability = vfs_store_capability();
        let mut journal = match crate::fs::filesystem()
            .handle_request(Request::read(key.clone(), capability.clone()))
            .status
        {
            ResponseStatus::Ok => {
                crate::fs::filesystem()
                    .handle_request(Request::read(key.clone(), capability.clone()))
                    .data
            }
            ResponseStatus::Error(FilesystemError::NotFound) => Vec::new(),
            ResponseStatus::Error(_) => return,
        };
        let tick = vfs_platform::ticks_now();
        let line = alloc::format!("[{}] {} {}\n", tick, op, detail);
        journal.extend_from_slice(line.as_bytes());
        let max_bytes = crate::runtime_page_size().saturating_mul(VFS_JOURNAL_MAX_BYTES_MULTIPLIER);
        if journal.len() > max_bytes {
            let drain_until = journal
                .len()
                .saturating_sub(max_bytes)
                .saturating_add(
                    journal
                        .iter()
                        .skip(journal.len().saturating_sub(max_bytes))
                        .position(|b| *b == b'\n')
                        .map(|idx| idx + 1)
                        .unwrap_or(0),
                )
                .min(journal.len());
            journal.drain(..drain_until);
        }
        let Ok(request) = Request::write(key, &journal, capability) else {
            return;
        };
        let _ = crate::fs::filesystem().handle_request(request);
    }

    fn health(&self) -> VfsHealth {
        let mut live_inodes = 0usize;
        let mut file_count = 0usize;
        let mut directory_count = 0usize;
        let mut symlink_count = 0usize;
        let mut total_bytes = 0usize;
        let mut referenced = vec![0u32; self.inodes.len()];

        for inode in self.inodes.iter().flatten() {
            live_inodes += 1;
            match inode.kind {
                InodeKind::File => {
                    file_count += 1;
                    total_bytes =
                        total_bytes.saturating_add(self.inode_payload_len(inode.id).unwrap_or(0));
                }
                InodeKind::Directory => {
                    directory_count += 1;
                    for entry in &inode.entries {
                        if let Some(count) = referenced.get_mut(entry.inode as usize) {
                            *count = count.saturating_add(1);
                        }
                    }
                }
                InodeKind::Symlink => {
                    symlink_count += 1;
                    total_bytes = total_bytes.saturating_add(inode.data.len());
                }
            }
        }

        let orphaned_inodes = self
            .inodes
            .iter()
            .enumerate()
            .skip(2)
            .filter(|(idx, inode)| {
                inode.is_some() && referenced.get(*idx).copied().unwrap_or(0) == 0
            })
            .count();

        let mount_health = self
            .mounts
            .iter()
            .map(|mount| MountHealth {
                path: mount.path.clone(),
                backend: match mount.backend {
                    MountBackend::VirtioBlock => "virtio-block",
                },
                reads: mount.health.reads,
                writes: mount.health.writes,
                mutations: mount.health.mutations,
                errors: mount.health.errors,
                last_error: mount.health.last_error.clone(),
            })
            .collect();

        VfsHealth {
            total_inode_slots: self.inodes.len(),
            live_inodes,
            file_count,
            directory_count,
            symlink_count,
            total_bytes,
            open_handles: self.handles.iter().flatten().count(),
            mount_count: self.mounts.len(),
            orphaned_inodes,
            max_mem_file_size: self.max_mem_file_size(),
            mount_health,
        }
    }

    fn mount_statuses(&self) -> Vec<MountStatus> {
        self.mounts
            .iter()
            .map(|mount| MountStatus {
                contract: mount.state.contract_info(&mount.path),
                health: MountHealth {
                    path: mount.path.clone(),
                    backend: match mount.backend {
                        MountBackend::VirtioBlock => "virtio-block",
                    },
                    reads: mount.health.reads,
                    writes: mount.health.writes,
                    mutations: mount.health.mutations,
                    errors: mount.health.errors,
                    last_error: mount.health.last_error.clone(),
                },
            })
            .collect()
    }

    fn ensure_lost_found(&mut self) -> Result<(InodeId, bool), &'static str> {
        if let Ok(existing) = self.lookup_child(1, "lost+found") {
            let inode = self.get_inode(existing).ok_or("lost+found missing")?;
            if inode.kind != InodeKind::Directory {
                return Err("lost+found exists but is not a directory");
            }
            return Ok((existing, false));
        }

        let inode_id = self.alloc_inode(InodeKind::Directory, 0o700);
        self.add_dir_entry(1, "lost+found", inode_id)?;
        Ok((inode_id, true))
    }

    fn fsck_and_repair(&mut self) -> Result<VfsFsckReport, &'static str> {
        self.init();

        let root = self.get_inode(1).ok_or("Root inode missing")?;
        if root.kind != InodeKind::Directory {
            return Err("Root inode is not a directory");
        }

        let mut report = VfsFsckReport::default();
        let mut referenced = vec![0u32; self.inodes.len()];
        let mut dangling_entries = Vec::<(InodeId, String)>::new();

        for inode in self.inodes.iter().flatten() {
            report.inodes_scanned = report.inodes_scanned.saturating_add(1);
            if inode.kind != InodeKind::Directory {
                continue;
            }
            for entry in &inode.entries {
                if self.get_inode(entry.inode).is_some() {
                    if let Some(count) = referenced.get_mut(entry.inode as usize) {
                        *count = count.saturating_add(1);
                    }
                } else {
                    dangling_entries.push((inode.id, entry.name.clone()));
                }
            }
        }

        for (dir_id, name) in dangling_entries {
            if self.remove_dir_entry(dir_id, &name).is_ok() {
                report.dangling_entries_removed = report.dangling_entries_removed.saturating_add(1);
            }
        }

        let orphan_ids: Vec<InodeId> = self
            .inodes
            .iter()
            .enumerate()
            .skip(2)
            .filter_map(|(idx, inode)| {
                if inode.is_some() && referenced.get(idx).copied().unwrap_or(0) == 0 {
                    Some(idx as InodeId)
                } else {
                    None
                }
            })
            .collect();

        if !orphan_ids.is_empty() {
            let (lost_found_id, created) = self.ensure_lost_found()?;
            report.lost_found_created = created;
            for orphan_id in orphan_ids {
                let mut attempt = 0usize;
                loop {
                    let name = if attempt == 0 {
                        alloc::format!("inode-{}", orphan_id)
                    } else {
                        alloc::format!("inode-{}-{}", orphan_id, attempt)
                    };
                    if self.add_dir_entry(lost_found_id, &name, orphan_id).is_ok() {
                        report.orphaned_inodes_relinked =
                            report.orphaned_inodes_relinked.saturating_add(1);
                        break;
                    }
                    attempt = attempt.saturating_add(1);
                }
            }
        }

        let mut final_refs = vec![0u32; self.inodes.len()];
        for inode in self.inodes.iter().flatten() {
            if inode.kind != InodeKind::Directory {
                continue;
            }
            for entry in &inode.entries {
                if let Some(count) = final_refs.get_mut(entry.inode as usize) {
                    *count = count.saturating_add(1);
                }
            }
        }

        let file_sizes: Vec<u64> = self
            .inodes
            .iter()
            .enumerate()
            .map(|(idx, inode_opt)| {
                inode_opt
                    .as_ref()
                    .map(|inode| match inode.kind {
                        InodeKind::File => self
                            .read_file_payload(idx as InodeId)
                            .map(|payload| payload.len() as u64)
                            .unwrap_or(0),
                        InodeKind::Symlink => inode.data.len() as u64,
                        InodeKind::Directory => inode.meta.size,
                    })
                    .unwrap_or(0)
            })
            .collect();

        for (idx, inode_opt) in self.inodes.iter_mut().enumerate() {
            let Some(inode) = inode_opt.as_mut() else {
                continue;
            };
            let expected_nlink = if idx == 1 {
                1
            } else {
                final_refs.get(idx).copied().unwrap_or(0)
            };
            if inode.meta.nlink != expected_nlink {
                inode.meta.nlink = expected_nlink;
                report.nlink_repairs = report.nlink_repairs.saturating_add(1);
            }
            let expected_size = file_sizes.get(idx).copied().unwrap_or(0);
            if matches!(inode.kind, InodeKind::File | InodeKind::Symlink)
                && inode.meta.size != expected_size
            {
                inode.meta.size = expected_size;
                report.size_repairs = report.size_repairs.saturating_add(1);
            }
        }

        Ok(report)
    }

    fn unlink_path(&mut self, path: &str) -> Result<(), &'static str> {
        let normalized = normalize_path(path)?;
        if normalized == "/" {
            return Err("Cannot delete root");
        }
        if let Some((mount_idx, _backend, sub)) = self.find_mount(&normalized) {
            let result = mount_unlink(self, mount_idx, &sub);
            match &result {
                Ok(()) => self.note_mount_success(mount_idx, MountOperation::Mutation),
                Err(e) => self.note_mount_error(mount_idx, MountOperation::Mutation, &sub, e),
            }
            return result;
        }

        let inode_id = self.resolve_path_nofollow(&normalized)?;
        let inode = self.get_inode(inode_id).ok_or("File not found")?;
        if inode.kind == InodeKind::Directory {
            return Err("Use rmdir for directories");
        }
        if inode.meta.nlink <= 1 && self.inode_has_open_handles(inode_id) {
            return Err("File busy");
        }

        let (parent, name) = Vfs::split_parent(&normalized)?;
        let parent_id = self.resolve_path(&parent)?;
        let removed_inode = self.remove_dir_entry(parent_id, &name)?;
        if removed_inode != inode_id {
            return Err("Directory entry mismatch");
        }

        let (kind, nlink) = {
            let inode = self.get_inode(inode_id).ok_or("File not found")?;
            (inode.kind, inode.meta.nlink)
        };
        if nlink > 1 {
            let inode = self.get_inode_mut(inode_id).ok_or("File not found")?;
            inode.meta.nlink -= 1;
        } else {
            if kind == InodeKind::File {
                self.delete_file_payload(inode_id);
            }
            let slot = self
                .inodes
                .get_mut(inode_id as usize)
                .ok_or("File not found")?;
            *slot = None;
        }
        Ok(())
    }

    fn rmdir_path(&mut self, path: &str) -> Result<(), &'static str> {
        let normalized = normalize_path(path)?;
        if normalized == "/" {
            return Err("Cannot delete root");
        }
        if let Some((mount_idx, _backend, sub)) = self.find_mount(&normalized) {
            let result = mount_rmdir(self, mount_idx, &sub);
            match &result {
                Ok(()) => self.note_mount_success(mount_idx, MountOperation::Mutation),
                Err(e) => self.note_mount_error(mount_idx, MountOperation::Mutation, &sub, e),
            }
            return result;
        }

        let inode_id = self.resolve_path_nofollow(&normalized)?;
        let inode = self.get_inode(inode_id).ok_or("Directory not found")?;
        if inode.kind != InodeKind::Directory {
            return Err("Not a directory");
        }
        if !inode.entries.is_empty() {
            return Err("Directory not empty");
        }
        if self.inode_has_open_handles(inode_id) {
            return Err("Directory busy");
        }

        let (parent, name) = Vfs::split_parent(&normalized)?;
        let parent_id = self.resolve_path(&parent)?;
        let removed_inode = self.remove_dir_entry(parent_id, &name)?;
        if removed_inode != inode_id {
            return Err("Directory entry mismatch");
        }

        let slot = self
            .inodes
            .get_mut(inode_id as usize)
            .ok_or("Directory not found")?;
        *slot = None;
        Ok(())
    }

    fn rename_path(&mut self, old_path: &str, new_path: &str) -> Result<(), &'static str> {
        let old_path = normalize_path(old_path)?;
        let new_path = normalize_path(new_path)?;
        if old_path == new_path {
            return Ok(());
        }
        if old_path == "/" || new_path == "/" {
            return Err("Cannot rename root");
        }

        match (self.find_mount(&old_path), self.find_mount(&new_path)) {
            (Some((old_idx, _old_backend, old_sub)), Some((new_idx, _new_backend, new_sub))) => {
                if old_idx != new_idx {
                    return Err("Cross-device rename");
                }
                let result = mount_rename(self, old_idx, &old_sub, &new_sub);
                match &result {
                    Ok(()) => self.note_mount_success(old_idx, MountOperation::Mutation),
                    Err(e) => self.note_mount_error(old_idx, MountOperation::Mutation, &old_sub, e),
                }
                return result;
            }
            (Some(_), None) | (None, Some(_)) => return Err("Cross-device rename"),
            (None, None) => {}
        }

        let inode_id = self.resolve_path_nofollow(&old_path)?;
        let inode = self.get_inode(inode_id).ok_or("Path component not found")?;
        if inode.kind == InodeKind::Directory
            && (new_path == old_path
                || new_path
                    .strip_prefix(&old_path)
                    .is_some_and(|suffix| suffix.starts_with('/')))
        {
            return Err("Cannot move directory into itself");
        }

        let (old_parent, old_name) = Vfs::split_parent(&old_path)?;
        let (new_parent, new_name) = Vfs::split_parent(&new_path)?;
        let old_parent_id = self.resolve_path(&old_parent)?;
        let new_parent_id = self.resolve_path(&new_parent)?;

        if old_parent_id == new_parent_id {
            self.replace_dir_entry(old_parent_id, &old_name, &new_name)?;
        } else {
            let removed_inode = self.remove_dir_entry(old_parent_id, &old_name)?;
            if removed_inode != inode_id {
                return Err("Directory entry mismatch");
            }
            if let Err(e) = self.add_dir_entry(new_parent_id, &new_name, inode_id) {
                let _ = self.add_dir_entry(old_parent_id, &old_name, inode_id);
                return Err(e);
            }
        }
        self.rewrite_handle_paths(&old_path, &new_path);
        Ok(())
    }

    fn link_path(&mut self, existing: &str, new_path: &str) -> Result<(), &'static str> {
        let existing = normalize_path(existing)?;
        let new_path = normalize_path(new_path)?;

        match (self.find_mount(&existing), self.find_mount(&new_path)) {
            (Some((old_idx, _old_backend, old_sub)), Some((new_idx, _new_backend, new_sub))) => {
                if old_idx != new_idx {
                    return Err("Cross-device link");
                }
                let result = mount_link(self, old_idx, &old_sub, &new_sub);
                match &result {
                    Ok(()) => self.note_mount_success(old_idx, MountOperation::Mutation),
                    Err(e) => self.note_mount_error(old_idx, MountOperation::Mutation, &old_sub, e),
                }
                return result;
            }
            (Some(_), None) | (None, Some(_)) => return Err("Cross-device link"),
            (None, None) => {}
        }

        let inode_id = self.resolve_path_nofollow(&existing)?;
        let inode = self.get_inode(inode_id).ok_or("File not found")?;
        if inode.kind == InodeKind::Directory {
            return Err("Hard link to directory not allowed");
        }

        let (new_parent, new_name) = Vfs::split_parent(&new_path)?;
        let new_parent_id = self.resolve_path(&new_parent)?;
        self.add_dir_entry(new_parent_id, &new_name, inode_id)?;
        let inode = self.get_inode_mut(inode_id).ok_or("File not found")?;
        inode.meta.nlink = inode.meta.nlink.saturating_add(1);
        Ok(())
    }

    fn symlink_path(&mut self, target: &str, link_path: &str) -> Result<(), &'static str> {
        let link_path = normalize_path(link_path)?;
        if let Some((mount_idx, _backend, sub)) = self.find_mount(&link_path) {
            let result = mount_symlink(self, mount_idx, target, &sub);
            match &result {
                Ok(()) => self.note_mount_success(mount_idx, MountOperation::Mutation),
                Err(e) => self.note_mount_error(mount_idx, MountOperation::Mutation, &sub, e),
            }
            return result;
        }

        let (parent, name) = Vfs::split_parent(&link_path)?;
        let parent_id = self.resolve_path(&parent)?;
        let inode_id = self.alloc_inode(InodeKind::Symlink, 0o777);
        let inode = self.get_inode_mut(inode_id).ok_or("Symlink not found")?;
        inode.data.extend_from_slice(target.as_bytes());
        inode.meta.size = inode.data.len() as u64;
        self.add_dir_entry(parent_id, &name, inode_id)
    }

    fn readlink_path(&mut self, path: &str) -> Result<String, &'static str> {
        let path = normalize_path(path)?;
        if let Some((mount_idx, _backend, sub)) = self.find_mount(&path) {
            let result = mount_readlink(self, mount_idx, &sub);
            match &result {
                Ok(_) => self.note_mount_success(mount_idx, MountOperation::Read),
                Err(e) => self.note_mount_error(mount_idx, MountOperation::Read, &sub, e),
            }
            return result;
        }
        let inode_id = self.resolve_path_nofollow(&path)?;
        let inode = self.get_inode(inode_id).ok_or("File not found")?;
        Ok(inode.symlink_target()?.to_string())
    }

    fn encode_persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        out.extend_from_slice(&VFS_PERSIST_MAGIC.to_le_bytes());
        out.extend_from_slice(&VFS_PERSIST_VERSION.to_le_bytes());
        out.extend_from_slice(&self.storage_namespace.to_le_bytes());

        let inode_count = self.inodes.iter().flatten().count() as u32;
        out.extend_from_slice(&inode_count.to_le_bytes());
        for inode in self.inodes.iter().flatten() {
            out.extend_from_slice(&inode.id.to_le_bytes());
            out.push(match inode.kind {
                InodeKind::File => 0,
                InodeKind::Directory => 1,
                InodeKind::Symlink => 2,
            });
            out.extend_from_slice(&inode.meta.mode.to_le_bytes());
            out.extend_from_slice(&inode.meta.uid.to_le_bytes());
            out.extend_from_slice(&inode.meta.gid.to_le_bytes());
            out.extend_from_slice(&inode.meta.atime.to_le_bytes());
            out.extend_from_slice(&inode.meta.mtime.to_le_bytes());
            out.extend_from_slice(&inode.meta.ctime.to_le_bytes());
            out.extend_from_slice(&inode.meta.size.to_le_bytes());
            out.extend_from_slice(&inode.meta.nlink.to_le_bytes());
            let inline_len = match inode.kind {
                InodeKind::Symlink => inode.data.len(),
                InodeKind::File | InodeKind::Directory => 0,
            };
            let data_len = u32::try_from(inline_len).map_err(|_| "Persistent state too large")?;
            out.extend_from_slice(&data_len.to_le_bytes());
            let entry_count =
                u32::try_from(inode.entries.len()).map_err(|_| "Persistent state too large")?;
            out.extend_from_slice(&entry_count.to_le_bytes());
            if inode.kind == InodeKind::Symlink {
                out.extend_from_slice(&inode.data);
            }
            for entry in &inode.entries {
                let name_bytes = entry.name.as_bytes();
                let name_len = u16::try_from(name_bytes.len())
                    .map_err(|_| "Persistent entry name too long")?;
                out.extend_from_slice(&name_len.to_le_bytes());
                out.extend_from_slice(name_bytes);
                out.extend_from_slice(&entry.inode.to_le_bytes());
            }
        }

        let mount_count =
            u32::try_from(self.mounts.len()).map_err(|_| "Persistent mount table too large")?;
        out.extend_from_slice(&mount_count.to_le_bytes());
        for mount in &self.mounts {
            out.push(match mount.backend {
                MountBackend::VirtioBlock => 0,
            });
            let path_bytes = mount.path.as_bytes();
            let path_len =
                u16::try_from(path_bytes.len()).map_err(|_| "Persistent mount path too long")?;
            out.extend_from_slice(&path_len.to_le_bytes());
            out.extend_from_slice(path_bytes);
            match &mount.state {
                MountState::VirtioBlock(state) => state.encode_into(&mut out)?,
            }
        }
        let mapper = self.capability_mapper();
        let dir_cap_count = u32::try_from(mapper.directory_caps.len())
            .map_err(|_| "Persistent directory capability table too large")?;
        out.extend_from_slice(&dir_cap_count.to_le_bytes());
        for (inode_id, capability) in &mapper.directory_caps {
            out.extend_from_slice(&inode_id.to_le_bytes());
            encode_capability(&mut out, capability)?;
        }

        let proc_cap_count = u32::try_from(mapper.process_caps.len())
            .map_err(|_| "Persistent process capability table too large")?;
        out.extend_from_slice(&proc_cap_count.to_le_bytes());
        for (pid, capability) in &mapper.process_caps {
            out.extend_from_slice(&pid.to_le_bytes());
            encode_capability(&mut out, capability)?;
        }
        Ok(out)
    }

    fn decode_persistent_state(data: &[u8]) -> Option<Self> {
        if read_u32(data, 0)? != VFS_PERSIST_MAGIC {
            return None;
        }
        let version = read_u16(data, 4)?;
        if version != 1 && version != VFS_PERSIST_VERSION {
            return None;
        }
        let mut cursor = 6usize;
        let storage_namespace = if version >= 3 {
            let namespace = read_u64(data, cursor)?;
            cursor += 8;
            namespace
        } else {
            allocate_vfs_storage_namespace()
        };
        let inode_count = read_u32(data, cursor)? as usize;
        cursor += 4;

        let mut max_id = 0usize;
        let mut decoded_inodes = Vec::new();
        for _ in 0..inode_count {
            let id = read_u64(data, cursor)?;
            cursor += 8;
            let kind = match *data.get(cursor)? {
                0 => InodeKind::File,
                1 => InodeKind::Directory,
                2 => InodeKind::Symlink,
                _ => return None,
            };
            cursor += 1;
            let mode = read_u16(data, cursor)?;
            cursor += 2;
            let uid = read_u32(data, cursor)?;
            cursor += 4;
            let gid = read_u32(data, cursor)?;
            cursor += 4;
            let atime = read_u64(data, cursor)?;
            cursor += 8;
            let mtime = read_u64(data, cursor)?;
            cursor += 8;
            let ctime = read_u64(data, cursor)?;
            cursor += 8;
            let size = if version >= 3 {
                let size = read_u64(data, cursor)?;
                cursor += 8;
                size
            } else {
                0
            };
            let nlink = read_u32(data, cursor)?;
            cursor += 4;
            let data_len = read_u32(data, cursor)? as usize;
            cursor += 4;
            let entry_count = read_u32(data, cursor)? as usize;
            cursor += 4;
            if cursor.saturating_add(data_len) > data.len() {
                return None;
            }
            let file_data = data[cursor..cursor + data_len].to_vec();
            cursor += data_len;
            let mut entries = Vec::with_capacity(entry_count);
            for _ in 0..entry_count {
                let name_len = read_u16(data, cursor)? as usize;
                cursor += 2;
                if cursor.saturating_add(name_len) > data.len() {
                    return None;
                }
                let name = core::str::from_utf8(&data[cursor..cursor + name_len])
                    .ok()?
                    .to_string();
                cursor += name_len;
                let inode = read_u64(data, cursor)?;
                cursor += 8;
                entries.push(DirEntry { name, inode });
            }

            let mut inode = Inode::new(id, kind, mode);
            inode.meta.uid = uid;
            inode.meta.gid = gid;
            inode.meta.atime = atime;
            inode.meta.mtime = mtime;
            inode.meta.ctime = ctime;
            inode.meta.nlink = nlink;
            inode.meta.size = if version >= 3 {
                size
            } else {
                file_data.len() as u64
            };
            inode.data = file_data;
            inode.entries = entries;
            max_id = max_id.max(id as usize);
            decoded_inodes.push((id as usize, inode));
        }

        let mut inodes = vec![None; max_id.saturating_add(1).max(2)];
        for (idx, inode) in decoded_inodes {
            if idx >= inodes.len() {
                return None;
            }
            inodes[idx] = Some(inode);
        }
        if inodes.get(1).and_then(|inode| inode.as_ref()).is_none() {
            return None;
        }

        let mount_count = read_u32(data, cursor)? as usize;
        cursor += 4;
        let mut mounts = Vec::with_capacity(mount_count);
        for _ in 0..mount_count {
            let backend = match *data.get(cursor)? {
                0 => MountBackend::VirtioBlock,
                _ => return None,
            };
            cursor += 1;
            let path_len = read_u16(data, cursor)? as usize;
            cursor += 2;
            if cursor.saturating_add(path_len) > data.len() {
                return None;
            }
            let path = core::str::from_utf8(&data[cursor..cursor + path_len])
                .ok()?
                .to_string();
            cursor += path_len;
            let state = match (backend, version) {
                (MountBackend::VirtioBlock, 1) => MountState::VirtioBlock(VirtioMountState::new()),
                (MountBackend::VirtioBlock, _) => {
                    MountState::VirtioBlock(VirtioMountState::decode_from(data, &mut cursor)?)
                }
            };
            mounts.push(Mount {
                path,
                backend,
                state,
                health: MountHealthCounters::default(),
            });
        }
        let mut capability_mapper = CapabilityMapper::runtime_default();
        if version >= 3 {
            let dir_cap_count = read_u32(data, cursor)? as usize;
            cursor += 4;
            for _ in 0..dir_cap_count {
                let inode_id = read_u64(data, cursor)?;
                cursor += 8;
                let capability = decode_capability(data, &mut cursor)?;
                capability_mapper
                    .directory_caps
                    .insert(inode_id, capability);
            }

            let proc_cap_count = read_u32(data, cursor)? as usize;
            cursor += 4;
            for _ in 0..proc_cap_count {
                let pid = read_u32(data, cursor)?;
                cursor += 4;
                let capability = decode_capability(data, &mut cursor)?;
                capability_mapper.process_caps.insert(pid, capability);
            }
        }
        if cursor != data.len() {
            return None;
        }
        let mut decoded = Vfs {
            inodes,
            mounts,
            handles: Vec::new(),
            policy: Some(VfsPolicy::runtime_default()),
            capability_mapper: Some(capability_mapper),
            storage_namespace,
            watches: BTreeMap::new(),
            watch_events: VecDeque::new(),
            notify_channels: BTreeMap::new(),
            next_watch_id: 1,
            next_watch_event_sequence: 1,
        };
        decoded.init();
        decoded.migrate_inline_file_payloads().ok()?;
        Some(decoded)
    }
}

static VFS: DagSpinlock<DAG_LEVEL_VFS, Vfs> = DagSpinlock::new(Vfs::new());

/// Constructs a kernel-thread-level DAG context for VFS operations.
///
/// `DAG_LEVEL_THREAD = 8 > DAG_LEVEL_VFS = 5`, so `acquire_lock(&VFS, …)` is
/// statically valid from this context.  All public VFS entry points must obtain
/// this context (or receive it as a parameter) before touching the lock.
#[inline(always)]
fn thread_context() -> InterruptContext<DAG_LEVEL_THREAD> {
    // SAFETY: DAG_LEVEL_THREAD > DAG_LEVEL_VFS; we are not in an IRQ handler
    // and no higher-priority lock is held.
    unsafe { InterruptContext::<DAG_LEVEL_THREAD>::new() }
}

pub fn init() {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
    });
}

pub fn policy() -> VfsPolicy {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.effective_policy()
    })
}

pub fn set_policy(policy: VfsPolicy) {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.policy = Some(policy);
    });
}

pub fn max_mem_file_size() -> Option<usize> {
    policy().max_mem_file_size
}

pub fn health() -> VfsHealth {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.health()
    })
}

pub fn mounts() -> Vec<MountStatus> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.mount_statuses()
    })
}

pub fn fsck_and_repair() -> Result<VfsFsckReport, &'static str> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        let report = vfs.fsck_and_repair()?;
        vfs.record_mutation_journal(
            "fsck",
            &alloc::format!(
                "dangling_removed={} relinked={} nlink_repairs={} size_repairs={}",
                report.dangling_entries_removed,
                report.orphaned_inodes_relinked,
                report.nlink_repairs,
                report.size_repairs
            ),
        );
        vfs.persist_local_state();
        Ok(report)
    })
}

pub fn set_directory_capability(
    path: &str,
    capability: FilesystemCapability,
) -> Result<(), &'static str> {
    let normalized = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let inode_id = vfs.resolve_path(&normalized)?;
        vfs.set_directory_capability_by_inode(inode_id, capability)?;
        vfs.record_mutation_journal("cap-dir-set", &alloc::format!("path={}", normalized));
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn clear_directory_capability(path: &str) -> Result<(), &'static str> {
    let normalized = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let inode_id = vfs.resolve_path(&normalized)?;
        vfs.clear_directory_capability_by_inode(inode_id)?;
        vfs.record_mutation_journal("cap-dir-clear", &alloc::format!("path={}", normalized));
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn set_process_capability(pid: Pid, capability: FilesystemCapability) {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.set_process_capability(pid, capability);
        vfs.record_mutation_journal("cap-proc-set", &alloc::format!("pid={}", pid_key(pid)));
        vfs.persist_local_state();
    });
}

pub fn clear_process_capability(pid: Pid) {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.clear_process_capability(pid);
        vfs.record_mutation_journal("cap-proc-clear", &alloc::format!("pid={}", pid_key(pid)));
        vfs.persist_local_state();
    });
}

pub fn inherit_process_capability(
    parent_pid: Pid,
    child_pid: Pid,
    attenuate: Option<FilesystemRights>,
) -> Result<(), &'static str> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.inherit_process_capability(parent_pid, child_pid, attenuate);
        vfs.record_mutation_journal(
            "cap-proc-inherit",
            &alloc::format!(
                "parent={} child={}",
                pid_key(parent_pid),
                pid_key(child_pid)
            ),
        );
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn effective_capability_for_pid(
    pid: Option<Pid>,
    path: &str,
) -> Result<FilesystemCapability, &'static str> {
    let normalized = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let chain = match vfs.resolve_authority_chain(&normalized, false) {
            Ok(chain) => chain,
            Err(_) => vfs.resolve_authority_parent_chain(&normalized)?,
        };
        Ok(vfs.resolve_capability_for_chain(pid, &chain))
    })
}

pub fn directory_capability(path: &str) -> Result<Option<FilesystemCapability>, &'static str> {
    let normalized = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let inode_id = vfs.resolve_path(&normalized)?;
        vfs.directory_capability_by_inode(inode_id)
    })
}

pub fn process_capability(pid: Pid) -> Option<FilesystemCapability> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.process_capability(pid)
    })
}

pub fn watch(path: &str, recursive: bool) -> Result<u64, &'static str> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.add_watch(path, recursive)
    })
}

pub fn unwatch(id: u64) -> bool {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.remove_watch(id)
    })
}

pub fn watches() -> Vec<VfsWatchInfo> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.list_watches()
    })
}

pub fn notify(limit: usize) -> Vec<VfsWatchEvent> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.recent_watch_events(limit.clamp(1, 256))
    })
}

pub fn subscribe_notify_channel(channel_id: crate::ipc::ChannelId) -> Result<(), &'static str> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.subscribe_notify_channel(channel_id.0)
    })
}

pub fn unsubscribe_notify_channel(channel_id: crate::ipc::ChannelId) -> bool {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.unsubscribe_notify_channel(channel_id.0)
    })
}

pub fn notify_channels() -> Vec<crate::ipc::ChannelId> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.list_notify_channels()
            .into_iter()
            .map(crate::ipc::ChannelId::new)
            .collect()
    })
}

pub fn notify_subscribers() -> Vec<VfsWatchSubscriberInfo> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.list_notify_subscribers()
    })
}

pub fn notify_channel_stats(
    channel_id: crate::ipc::ChannelId,
) -> Result<VfsWatchSubscriberInfo, &'static str> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.notify_channel_stats(channel_id.0)
    })
}

pub fn ack_notify_channel(
    channel_id: crate::ipc::ChannelId,
    sequence: u64,
) -> Result<(), &'static str> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        vfs.ack_notify_channel(channel_id.0, sequence)
    })
}

// ============================================================================
// Public VFS API (Paths)
// ============================================================================

pub fn mkdir(path: &str) -> Result<(), &'static str> {
    let normalized = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        if let Some((mount_idx, _backend, sub)) = vfs.find_mount(&normalized) {
            let chain = vfs.resolve_authority_parent_chain(&normalized)?;
            let _ = vfs.ensure_path_rights(
                vfs_platform::current_pid(),
                &normalized,
                &chain,
                VfsAccess::Write,
            )?;
            let result = mount_mkdir(vfs, mount_idx, &sub);
            match &result {
                Ok(_) => vfs.note_mount_success(mount_idx, MountOperation::Mutation),
                Err(e) => vfs.note_mount_error(mount_idx, MountOperation::Mutation, &sub, e),
            }
            result?;
            vfs.record_mutation_journal("mkdir", &alloc::format!("path={}", normalized));
            vfs.record_watch_event(VfsWatchKind::Mkdir, &normalized, None);
            vfs.persist_local_state();
            return Ok(());
        }
        let chain = vfs.resolve_parent_chain(&normalized)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized,
            &chain,
            VfsAccess::Write,
        )?;
        let (parent, name) = Vfs::split_parent(&normalized)?;
        let parent_id = vfs.resolve_path(&parent)?;
        let inode_id = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(parent_id, &name, inode_id)?;
        vfs.record_mutation_journal("mkdir", &alloc::format!("path={}", normalized));
        vfs.record_watch_event(VfsWatchKind::Mkdir, &normalized, None);
        vfs.persist_local_state();
        Ok(())
    })
}

/// Internal helper: creates a file within an already-held `Vfs` lock guard.
/// Used by `write_path_internal` and `open_for_pid` to avoid dropping and
/// re-acquiring the VFS lock mid-function.
fn create_file_inner(vfs: &mut Vfs, path: &str) -> Result<InodeId, &'static str> {
    let normalized = normalize_path(path)?;
    if let Some((mount_idx, _backend, sub)) = vfs.find_mount(&normalized) {
        let chain = vfs.resolve_authority_parent_chain(&normalized)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized,
            &chain,
            VfsAccess::Write,
        )?;
        let result = mount_create_file(vfs, mount_idx, &sub);
        match &result {
            Ok(_) => vfs.note_mount_success(mount_idx, MountOperation::Mutation),
            Err(e) => vfs.note_mount_error(mount_idx, MountOperation::Mutation, &sub, e),
        }
        let node_id = result?;
        vfs.record_mutation_journal("create", &alloc::format!("path={}", normalized));
        vfs.record_watch_event(VfsWatchKind::Create, &normalized, None);
        vfs.persist_local_state();
        return Ok(node_id);
    }
    let chain = vfs.resolve_parent_chain(&normalized)?;
    let _ = vfs.ensure_path_rights(
        vfs_platform::current_pid(),
        &normalized,
        &chain,
        VfsAccess::Write,
    )?;
    vfs.ensure_quota_allows(vfs_platform::current_pid(), &chain, 0, 0, true)?;
    let (parent, name) = Vfs::split_parent(&normalized)?;
    let parent_id = vfs.resolve_path(&parent)?;
    let inode_id = vfs.alloc_inode(InodeKind::File, 0o644);
    vfs.add_dir_entry(parent_id, &name, inode_id)?;
    vfs.record_mutation_journal("create", &alloc::format!("path={}", normalized));
    vfs.record_watch_event(VfsWatchKind::Create, &normalized, None);
    vfs.persist_local_state();
    Ok(inode_id)
}

pub fn create_file(path: &str) -> Result<InodeId, &'static str> {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        create_file_inner(vfs, path)
    })
}

pub fn write_path(path: &str, data: &[u8]) -> Result<usize, &'static str> {
    write_path_internal(path, data, true)
}

pub fn write_path_untracked(path: &str, data: &[u8]) -> Result<usize, &'static str> {
    write_path_internal(path, data, false)
}

fn write_path_internal(
    path: &str,
    data: &[u8],
    track_temporal: bool,
) -> Result<usize, &'static str> {
    let normalized_path = normalize_path(path)?;
    let subject_pid = vfs_platform::current_pid();
    // Single acquire_lock covers the entire function body — eliminates all
    // mid-function lock-drop/re-acquire cycles (PMA §9).
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();

        // ── Mount-backed write path ────────────────────────────────────────
        if let Some((mount_idx, _backend, sub)) = vfs.find_mount(&normalized_path) {
            let chain = vfs.resolve_authority_parent_chain(&normalized_path)?;
            let _ =
                vfs.ensure_path_rights(subject_pid, &normalized_path, &chain, VfsAccess::Write)?;
            let written = match mount_write(vfs, mount_idx, &sub, data) {
                Ok(w) => {
                    vfs.note_mount_success(mount_idx, MountOperation::Write);
                    w
                }
                Err(e) => {
                    vfs.note_mount_error(mount_idx, MountOperation::Write, &sub, e);
                    return Err(e);
                }
            };
            if track_temporal {
                capture_temporal_backend_write(&normalized_path, 0, data, written);
            }
            vfs.record_mutation_journal(
                "backend-write",
                &alloc::format!("path={} bytes={} offset=0", normalized_path, written),
            );
            vfs.record_watch_event(
                VfsWatchKind::Write,
                &normalized_path,
                Some(alloc::format!("bytes={} offset=0", written)),
            );
            vfs.persist_local_state();
            return Ok(written);
        }

        // ── In-memory overwrite of existing file ──────────────────────────
        if let Ok(inode_id) = vfs.resolve_path(&normalized_path) {
            let chain = vfs.resolve_path_chain(&normalized_path, true)?;
            let _ =
                vfs.ensure_path_rights(subject_pid, &normalized_path, &chain, VfsAccess::Write)?;
            let old_size = vfs.inode_payload_len(inode_id)?;
            vfs.ensure_file_size_allowed(data.len())?;
            vfs.ensure_quota_allows(subject_pid, &chain, old_size, data.len(), false)?;
            if vfs.get_inode(inode_id).ok_or("File not found")?.kind != InodeKind::File {
                return Err("Not a file");
            }
            vfs.write_file_payload(inode_id, data)?;
            if track_temporal {
                let _ = vfs_platform::temporal_record_write(&normalized_path, data);
            }
            vfs.record_mutation_journal(
                "write",
                &alloc::format!("path={} bytes={}", normalized_path, data.len()),
            );
            vfs.record_watch_event(
                VfsWatchKind::Write,
                &normalized_path,
                Some(alloc::format!("bytes={}", data.len())),
            );
            vfs.persist_local_state();
            return Ok(data.len());
        }

        // ── Create-then-write new file ─────────────────────────────────────
        // Quota/rights check before creation.
        let chain = vfs.resolve_parent_chain(&normalized_path)?;
        let _ = vfs.ensure_path_rights(subject_pid, &normalized_path, &chain, VfsAccess::Write)?;
        vfs.ensure_file_size_allowed(data.len())?;
        vfs.ensure_quota_allows(subject_pid, &chain, 0, data.len(), true)?;

        let (parent, name) = Vfs::split_parent(&normalized_path)?;
        let parent_id = vfs.resolve_path(&parent)?;
        let inode_id = vfs.alloc_inode(InodeKind::File, 0o644);
        if let Err(e) = vfs.add_dir_entry(parent_id, &name, inode_id) {
            if let Some(slot) = vfs.inodes.get_mut(inode_id as usize) {
                *slot = None;
            }
            return Err(e);
        }
        if vfs.get_inode(inode_id).ok_or("File not found")?.kind != InodeKind::File {
            let _ = vfs.remove_dir_entry(parent_id, &name);
            if let Some(slot) = vfs.inodes.get_mut(inode_id as usize) {
                *slot = None;
            }
            return Err("Not a file");
        }
        if let Err(e) = vfs.write_file_payload(inode_id, data) {
            let _ = vfs.remove_dir_entry(parent_id, &name);
            vfs.delete_file_payload(inode_id);
            if let Some(slot) = vfs.inodes.get_mut(inode_id as usize) {
                *slot = None;
            }
            return Err(e);
        }
        if track_temporal {
            let _ = vfs_platform::temporal_record_write(&normalized_path, data);
        }
        vfs.record_mutation_journal("create", &alloc::format!("path={}", normalized_path));
        vfs.record_mutation_journal(
            "write",
            &alloc::format!("path={} bytes={}", normalized_path, data.len()),
        );
        vfs.record_watch_event(VfsWatchKind::Create, &normalized_path, None);
        vfs.record_watch_event(
            VfsWatchKind::Write,
            &normalized_path,
            Some(alloc::format!("bytes={}", data.len())),
        );
        vfs.persist_local_state();
        Ok(data.len())
    })
}

pub fn read_path(path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
    let normalized_path = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        if let Some((mount_idx, _backend, sub)) = vfs.find_mount(&normalized_path) {
            let chain = vfs.resolve_authority_chain(&normalized_path, true)?;
            let _ = vfs.ensure_path_rights(
                vfs_platform::current_pid(),
                &normalized_path,
                &chain,
                VfsAccess::Read,
            )?;
            let result = mount_read(vfs, mount_idx, &sub, out);
            match &result {
                Ok(_) => vfs.note_mount_success(mount_idx, MountOperation::Read),
                Err(e) => vfs.note_mount_error(mount_idx, MountOperation::Read, &sub, e),
            }
            let len = result?;
            vfs.record_watch_event(
                VfsWatchKind::Read,
                &normalized_path,
                Some(alloc::format!("bytes={}", len)),
            );
            return Ok(len);
        }
        let chain = vfs.resolve_path_chain(&normalized_path, true)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_path,
            &chain,
            VfsAccess::Read,
        )?;
        let inode_id = vfs.resolve_path(&normalized_path)?;
        let inode = vfs.get_inode(inode_id).ok_or("File not found")?;
        if inode.kind != InodeKind::File && inode.kind != InodeKind::Symlink {
            return Err("Not a file");
        }
        let data = if inode.kind == InodeKind::File {
            vfs.read_file_payload(inode_id)?
        } else {
            inode.data.clone()
        };
        let len = min(out.len(), data.len());
        out[..len].copy_from_slice(&data[..len]);
        vfs.record_watch_event(
            VfsWatchKind::Read,
            &normalized_path,
            Some(alloc::format!("bytes={}", len)),
        );
        Ok(len)
    })
}

pub fn list_dir(path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
    let normalized_path = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        if let Some((mount_idx, _backend, sub)) = vfs.find_mount(&normalized_path) {
            let chain = vfs.resolve_authority_chain(&normalized_path, true)?;
            let _ = vfs.ensure_path_rights(
                vfs_platform::current_pid(),
                &normalized_path,
                &chain,
                VfsAccess::List,
            )?;
            let result = mount_list(vfs, mount_idx, &sub, out);
            match &result {
                Ok(_) => vfs.note_mount_success(mount_idx, MountOperation::Read),
                Err(e) => vfs.note_mount_error(mount_idx, MountOperation::Read, &sub, e),
            }
            let len = result?;
            vfs.record_watch_event(
                VfsWatchKind::List,
                &normalized_path,
                Some(alloc::format!("bytes={}", len)),
            );
            return Ok(len);
        }
        let chain = vfs.resolve_path_chain(&normalized_path, true)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_path,
            &chain,
            VfsAccess::List,
        )?;
        let inode_id = vfs.resolve_path(&normalized_path)?;
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
        vfs.record_watch_event(
            VfsWatchKind::List,
            &normalized_path,
            Some(alloc::format!("bytes={}", len)),
        );
        Ok(len)
    })
}

pub fn path_size(path: &str) -> Result<usize, &'static str> {
    let normalized_path = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        if let Some((mount_idx, _backend, sub)) = vfs.find_mount(&normalized_path) {
            let chain = vfs.resolve_authority_chain(&normalized_path, true)?;
            let _ = vfs.ensure_path_rights(
                vfs_platform::current_pid(),
                &normalized_path,
                &chain,
                VfsAccess::Read,
            )?;
            let result = mount_path_size(vfs, mount_idx, &sub);
            match &result {
                Ok(_) => vfs.note_mount_success(mount_idx, MountOperation::Read),
                Err(e) => vfs.note_mount_error(mount_idx, MountOperation::Read, &sub, e),
            }
            return result;
        }
        let chain = vfs.resolve_path_chain(&normalized_path, true)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_path,
            &chain,
            VfsAccess::Read,
        )?;
        let inode_id = vfs.resolve_path(&normalized_path)?;
        let inode = vfs.get_inode(inode_id).ok_or("File not found")?;
        match inode.kind {
            InodeKind::File => vfs.inode_payload_len(inode_id),
            InodeKind::Symlink => Ok(inode.data.len()),
            InodeKind::Directory => Err("Not a file"),
        }
    })
}

pub fn unlink(path: &str) -> Result<(), &'static str> {
    let normalized_path = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let chain = vfs.resolve_authority_chain(&normalized_path, false)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_path,
            &chain,
            VfsAccess::Delete,
        )?;
        vfs.unlink_path(&normalized_path)?;
        vfs.record_mutation_journal("unlink", &alloc::format!("path={}", normalized_path));
        vfs.record_watch_event(VfsWatchKind::Delete, &normalized_path, None);
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn rmdir(path: &str) -> Result<(), &'static str> {
    let normalized_path = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let chain = vfs.resolve_authority_chain(&normalized_path, false)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_path,
            &chain,
            VfsAccess::Delete,
        )?;
        vfs.rmdir_path(&normalized_path)?;
        vfs.record_mutation_journal("rmdir", &alloc::format!("path={}", normalized_path));
        vfs.record_watch_event(VfsWatchKind::Rmdir, &normalized_path, None);
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn rename(old_path: &str, new_path: &str) -> Result<(), &'static str> {
    let old_path = normalize_path(old_path)?;
    let new_path = normalize_path(new_path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let old_chain = vfs.resolve_authority_chain(&old_path, false)?;
        let new_chain = vfs.resolve_authority_parent_chain(&new_path)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &old_path,
            &old_chain,
            VfsAccess::Delete,
        )?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &new_path,
            &new_chain,
            VfsAccess::Write,
        )?;
        vfs.rename_path(&old_path, &new_path)?;
        vfs.record_mutation_journal(
            "rename",
            &alloc::format!("old={} new={}", old_path, new_path),
        );
        vfs.record_watch_event(
            VfsWatchKind::Rename,
            &old_path,
            Some(alloc::format!("to={}", new_path)),
        );
        vfs.record_watch_event(
            VfsWatchKind::Rename,
            &new_path,
            Some(alloc::format!("from={}", old_path)),
        );
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn link(existing: &str, new_path: &str) -> Result<(), &'static str> {
    let existing = normalize_path(existing)?;
    let new_path = normalize_path(new_path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let existing_chain = vfs.resolve_authority_chain(&existing, false)?;
        let new_chain = vfs.resolve_authority_parent_chain(&new_path)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &existing,
            &existing_chain,
            VfsAccess::Read,
        )?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &new_path,
            &new_chain,
            VfsAccess::Write,
        )?;
        let inode_id = vfs.resolve_path_nofollow(&existing)?;
        let old_size = vfs.inode_payload_len(inode_id)?;
        vfs.ensure_quota_allows(
            vfs_platform::current_pid(),
            &new_chain,
            old_size,
            old_size,
            true,
        )?;
        vfs.link_path(&existing, &new_path)?;
        vfs.record_mutation_journal("link", &alloc::format!("src={} dst={}", existing, new_path));
        vfs.record_watch_event(
            VfsWatchKind::Link,
            &new_path,
            Some(alloc::format!("src={}", existing)),
        );
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn symlink(target: &str, link_path: &str) -> Result<(), &'static str> {
    let normalized_link = normalize_path(link_path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let chain = vfs.resolve_authority_parent_chain(&normalized_link)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_link,
            &chain,
            VfsAccess::Write,
        )?;
        vfs.ensure_quota_allows(
            vfs_platform::current_pid(),
            &chain,
            0,
            target.as_bytes().len(),
            true,
        )?;
        vfs.symlink_path(target, &normalized_link)?;
        vfs.record_mutation_journal(
            "symlink",
            &alloc::format!("target={} link={}", target, normalized_link),
        );
        vfs.record_watch_event(
            VfsWatchKind::Symlink,
            &normalized_link,
            Some(alloc::format!("target={}", target)),
        );
        vfs.persist_local_state();
        Ok(())
    })
}

pub fn readlink(path: &str) -> Result<String, &'static str> {
    let normalized_path = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let chain = vfs.resolve_authority_chain(&normalized_path, false)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_path,
            &chain,
            VfsAccess::Read,
        )?;
        let target = vfs.readlink_path(&normalized_path)?;
        vfs.record_watch_event(
            VfsWatchKind::ReadLink,
            &normalized_path,
            Some(alloc::format!("target={}", target)),
        );
        Ok(target)
    })
}

pub fn mount_virtio(path: &str) -> Result<(), &'static str> {
    if !virtio_blk::is_present() {
        return Err("No VirtIO block device present");
    }
    let norm = normalize_path(path)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let chain = vfs.resolve_path_chain(&norm, true)?;
        let _ =
            vfs.ensure_path_rights(vfs_platform::current_pid(), &norm, &chain, VfsAccess::Write)?;
        let inode_id = vfs.resolve_path(&norm)?;
        let inode = vfs.get_inode(inode_id).ok_or("Mount point not found")?;
        if inode.kind != InodeKind::Directory {
            return Err("Mount point is not a directory");
        }
        if vfs.mounts.iter().any(|m| m.path == norm) {
            return Err("Mount point already used");
        }
        let journal_path = norm.clone();
        vfs.mounts.push(Mount {
            path: norm.clone(),
            backend: MountBackend::VirtioBlock,
            state: MountState::VirtioBlock(VirtioMountState::new()),
            health: MountHealthCounters::default(),
        });
        vfs.record_mutation_journal(
            "mount",
            &alloc::format!("backend=virtio path={}", journal_path),
        );
        vfs.record_watch_event(
            VfsWatchKind::Mount,
            &norm,
            Some("backend=virtio".to_string()),
        );
        vfs.persist_local_state();
        Ok(())
    })
}

// ============================================================================
// File Descriptors
// ============================================================================

pub fn open_for_current(path: &str, flags: OpenFlags) -> Result<usize, &'static str> {
    let pid = vfs_platform::current_pid().ok_or("No current process")?;
    open_for_pid(pid, path, flags)
}

pub fn open_for_pid(pid: Pid, path: &str, flags: OpenFlags) -> Result<usize, &'static str> {
    let normalized_path = normalize_path(path)?;
    let required_access = if flags
        .intersects(OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC | OpenFlags::APPEND)
    {
        VfsAccess::Write
    } else {
        VfsAccess::Read
    };
    // Single acquire_lock covers the entire open path — no mid-function
    // lock-drop/re-acquire cycles (PMA §9).
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();

        // ── Mount-backed open ─────────────────────────────────────────────
        if let Some((mount_idx, _backend, sub)) = vfs.find_mount(&normalized_path) {
            let chain = vfs.resolve_authority_parent_chain(&normalized_path)?;
            let capability =
                vfs.ensure_path_rights(Some(pid), &normalized_path, &chain, required_access)?;
            let mut created = false;
            let kind = match mount_open_kind(vfs, mount_idx, &sub, flags, &normalized_path) {
                Ok(kind) => kind,
                Err("File not found") if flags.contains(OpenFlags::CREATE) => {
                    match mount_create_file(vfs, mount_idx, &sub) {
                        Ok(_) => {
                            created = true;
                            mount_open_kind(vfs, mount_idx, &sub, flags, &normalized_path)?
                        }
                        Err(e) => {
                            vfs.note_mount_error(mount_idx, MountOperation::Mutation, &sub, e);
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    vfs.note_mount_error(mount_idx, MountOperation::Read, &sub, e);
                    return Err(e);
                }
            };
            if flags.contains(OpenFlags::TRUNC) {
                if let Err(e) = mount_write(vfs, mount_idx, &sub, &[]) {
                    vfs.note_mount_error(mount_idx, MountOperation::Write, &sub, e);
                    return Err(e);
                }
                vfs.record_mutation_journal(
                    "mount-truncate",
                    &alloc::format!("path={}", normalized_path),
                );
                vfs.record_watch_event(
                    VfsWatchKind::Write,
                    &normalized_path,
                    Some("truncate=1".to_string()),
                );
            }
            if created {
                vfs.record_mutation_journal(
                    "mount-create",
                    &alloc::format!("path={}", normalized_path),
                );
                vfs.record_watch_event(VfsWatchKind::Create, &normalized_path, None);
            }
            if created || flags.contains(OpenFlags::TRUNC) {
                vfs.persist_local_state();
            }
            let pos = if flags.contains(OpenFlags::APPEND) {
                match mount_path_size(vfs, mount_idx, &sub) {
                    Ok(pos) => pos,
                    Err(e) => {
                        vfs.note_mount_error(mount_idx, MountOperation::Read, &sub, e);
                        return Err(e);
                    }
                }
            } else {
                0
            };
            vfs.note_mount_success(mount_idx, MountOperation::Read);
            let handle = Handle {
                kind,
                pos,
                flags,
                owner: pid,
                capability,
            };
            let handle_id = vfs.alloc_handle(handle);
            return vfs_platform::alloc_fd(pid, handle_id);
        }

        // ── In-memory inode open ──────────────────────────────────────────
        if let Ok(inode_id) = vfs.resolve_path(&normalized_path) {
            let chain = vfs.resolve_path_chain(&normalized_path, true)?;
            let capability =
                vfs.ensure_path_rights(Some(pid), &normalized_path, &chain, required_access)?;
            let inode_kind = vfs.get_inode(inode_id).ok_or("File not found")?.kind;
            match inode_kind {
                InodeKind::File => {
                    if flags.contains(OpenFlags::TRUNC) {
                        let old_size = vfs.inode_payload_len(inode_id)?;
                        vfs.ensure_quota_allows(Some(pid), &chain, old_size, 0, false)?;
                        vfs.write_file_payload(inode_id, &[])?;
                        let _ = vfs_platform::temporal_record_write(&normalized_path, &[]);
                        vfs.record_mutation_journal(
                            "truncate",
                            &alloc::format!("path={}", normalized_path),
                        );
                        vfs.record_watch_event(
                            VfsWatchKind::Write,
                            &normalized_path,
                            Some("truncate=1".to_string()),
                        );
                        vfs.persist_local_state();
                    }
                    let pos = vfs.inode_payload_len(inode_id)?;
                    let handle = Handle {
                        kind: HandleKind::MemFile {
                            inode: inode_id,
                            path: normalized_path.clone(),
                        },
                        pos: if flags.contains(OpenFlags::APPEND) {
                            pos
                        } else {
                            0
                        },
                        flags,
                        owner: pid,
                        capability,
                    };
                    let handle_id = vfs.alloc_handle(handle);
                    return vfs_platform::alloc_fd(pid, handle_id);
                }
                InodeKind::Directory => {
                    let handle = Handle {
                        kind: HandleKind::MemDir { inode: inode_id },
                        pos: 0,
                        flags,
                        owner: pid,
                        capability,
                    };
                    let handle_id = vfs.alloc_handle(handle);
                    return vfs_platform::alloc_fd(pid, handle_id);
                }
                InodeKind::Symlink => return Err("Symlink open not supported"),
            }
        }

        // ── Create-on-open (O_CREAT) ──────────────────────────────────────
        if !flags.contains(OpenFlags::CREATE) {
            return Err("File not found");
        }
        let chain = vfs.resolve_parent_chain(&normalized_path)?;
        let _ = vfs.ensure_path_rights(Some(pid), &normalized_path, &chain, VfsAccess::Write)?;
        vfs.ensure_quota_allows(Some(pid), &chain, 0, 0, true)?;

        // Create without dropping the lock.
        create_file_inner(vfs, &normalized_path)?;

        let inode_id = vfs.resolve_path(&normalized_path)?;
        let chain = vfs.resolve_path_chain(&normalized_path, true)?;
        let capability =
            vfs.ensure_path_rights(Some(pid), &normalized_path, &chain, required_access)?;
        let inode_kind = vfs.get_inode(inode_id).ok_or("File not found")?.kind;
        match inode_kind {
            InodeKind::File => {
                if flags.contains(OpenFlags::TRUNC) {
                    let old_size = vfs.inode_payload_len(inode_id)?;
                    vfs.ensure_quota_allows(Some(pid), &chain, old_size, 0, false)?;
                    vfs.write_file_payload(inode_id, &[])?;
                    let _ = vfs_platform::temporal_record_write(&normalized_path, &[]);
                    vfs.record_mutation_journal(
                        "truncate",
                        &alloc::format!("path={}", normalized_path),
                    );
                    vfs.record_watch_event(
                        VfsWatchKind::Write,
                        &normalized_path,
                        Some("truncate=1".to_string()),
                    );
                    vfs.persist_local_state();
                }
                let pos = vfs.inode_payload_len(inode_id)?;
                let handle = Handle {
                    kind: HandleKind::MemFile {
                        inode: inode_id,
                        path: normalized_path,
                    },
                    pos: if flags.contains(OpenFlags::APPEND) {
                        pos
                    } else {
                        0
                    },
                    flags,
                    owner: pid,
                    capability,
                };
                let handle_id = vfs.alloc_handle(handle);
                vfs_platform::alloc_fd(pid, handle_id)
            }
            InodeKind::Directory => {
                let handle = Handle {
                    kind: HandleKind::MemDir { inode: inode_id },
                    pos: 0,
                    flags,
                    owner: pid,
                    capability,
                };
                let handle_id = vfs.alloc_handle(handle);
                vfs_platform::alloc_fd(pid, handle_id)
            }
            InodeKind::Symlink => Err("Symlink open not supported"),
        }
    })
}

pub fn read_fd(pid: Pid, fd: usize, out: &mut [u8]) -> Result<usize, &'static str> {
    let handle_id = vfs_platform::get_fd_handle(pid, fd)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        let (kind, pos, capability) = {
            let handle = vfs.get_handle_mut(handle_id).ok_or("Invalid handle")?;
            if handle.owner != pid {
                return Err("Handle ownership mismatch");
            }
            (handle.kind.clone(), handle.pos, handle.capability.clone())
        };
        if !access_allowed(&capability, VfsAccess::Read) {
            return Err("Permission denied");
        }
        vfs.revalidate_handle_access(pid, &kind, VfsAccess::Read)?;
        let read_len = match kind {
            HandleKind::MemFile { inode, .. } => {
                let data = vfs.read_file_payload(inode)?;
                let start = pos;
                if start >= data.len() {
                    return Ok(0);
                }
                let len = min(out.len(), data.len() - start);
                out[..len].copy_from_slice(&data[start..start + len]);
                Ok(len)
            }
            HandleKind::MemDir { .. } => Err("Cannot read directory"),
            HandleKind::MountFile {
                mount_idx, node_id, ..
            } => mount_file_read_at(vfs, mount_idx, node_id, pos, out),
            HandleKind::MountDir { .. } => Err("Cannot read directory"),
            HandleKind::VirtioRaw { ref path } => match virtio_read_at(pos, out) {
                Ok(len) => {
                    if let Some((mount_idx, _, _)) = vfs.find_mount(&path) {
                        vfs.note_mount_success(mount_idx, MountOperation::Read);
                    }
                    Ok(len)
                }
                Err(e) => {
                    if let Some((mount_idx, _, sub)) = vfs.find_mount(&path) {
                        vfs.note_mount_error(mount_idx, MountOperation::Read, &sub, e);
                    }
                    Err(e)
                }
            },
            HandleKind::VirtioPartitions { .. } => {
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
        match &kind {
            HandleKind::MemFile { path, .. }
            | HandleKind::VirtioRaw { path }
            | HandleKind::VirtioPartitions { path } => vfs.record_watch_event(
                VfsWatchKind::Read,
                path,
                Some(alloc::format!("bytes={} offset={}", read_len, pos)),
            ),
            HandleKind::MountFile { path, .. } => vfs.record_watch_event(
                VfsWatchKind::Read,
                path,
                Some(alloc::format!("bytes={} offset={}", read_len, pos)),
            ),
            _ => {}
        }
        Ok(read_len)
    })
}

pub fn write_fd(pid: Pid, fd: usize, data: &[u8]) -> Result<usize, &'static str> {
    let handle_id = vfs_platform::get_fd_handle(pid, fd)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        let (kind, pos, flags, capability) = {
            let handle = vfs.get_handle_mut(handle_id).ok_or("Invalid handle")?;
            if handle.owner != pid {
                return Err("Handle ownership mismatch");
            }
            (
                handle.kind.clone(),
                handle.pos,
                handle.flags,
                handle.capability.clone(),
            )
        };
        if !flags.contains(OpenFlags::WRITE) {
            return Err("File not opened for write");
        }
        if !access_allowed(&capability, VfsAccess::Write) {
            return Err("Permission denied");
        }
        vfs.revalidate_handle_access(pid, &kind, VfsAccess::Write)?;
        let mut temporal_capture: Option<(String, Vec<u8>)> = None;
        let mut journal_detail: Option<String> = None;
        let mut persist_local_state = false;
        let written = match kind {
            HandleKind::MemFile { inode, ref path } => {
                let new_size = pos.saturating_add(data.len());
                let chain = vfs.resolve_parent_chain(&path)?;
                let old_size = vfs.inode_payload_len(inode)?;
                vfs.ensure_file_size_allowed(new_size)?;
                vfs.ensure_quota_allows(Some(pid), &chain, old_size, new_size, false)?;
                let mut payload = vfs.read_file_payload(inode)?;
                if pos > payload.len() {
                    payload.resize(pos, 0);
                }
                if pos + data.len() > payload.len() {
                    payload.resize(pos + data.len(), 0);
                }
                payload[pos..pos + data.len()].copy_from_slice(data);
                vfs.write_file_payload(inode, &payload)?;
                temporal_capture = Some((path.clone(), payload));
                if let Some((path, _)) = temporal_capture.as_ref() {
                    journal_detail = Some(alloc::format!(
                        "path={} bytes={} offset={}",
                        path,
                        data.len(),
                        pos
                    ));
                }
                persist_local_state = true;
                Ok(data.len())
            }
            HandleKind::MemDir { .. } => Err("Cannot write directory"),
            HandleKind::MountFile {
                mount_idx,
                node_id,
                ref path,
            } => {
                let written = mount_file_write_at_node(vfs, mount_idx, node_id, pos, data)?;
                journal_detail = Some(alloc::format!(
                    "path={} bytes={} offset={}",
                    path,
                    written,
                    pos
                ));
                persist_local_state = true;
                Ok(written)
            }
            HandleKind::MountDir { .. } => Err("Cannot write directory"),
            HandleKind::VirtioRaw { ref path } => {
                let written = match virtio_write_at(pos, data) {
                    Ok(written) => written,
                    Err(e) => {
                        if let Some((mount_idx, _, sub)) = vfs.find_mount(&path) {
                            vfs.note_mount_error(mount_idx, MountOperation::Write, &sub, e);
                        }
                        return Err(e);
                    }
                };
                capture_temporal_backend_write(&path, pos, data, written);
                if let Some((mount_idx, _, _)) = vfs.find_mount(&path) {
                    vfs.note_mount_success(mount_idx, MountOperation::Write);
                }
                journal_detail = Some(alloc::format!(
                    "path={} bytes={} offset={}",
                    path,
                    written,
                    pos
                ));
                Ok(written)
            }
            HandleKind::VirtioPartitions { .. } => Err("Partitions file is read-only"),
        }?;

        if let Some(handle) = vfs.get_handle_mut(handle_id) {
            handle.pos = handle.pos.saturating_add(written);
        }

        // Temporal capture happens outside the closure (pure I/O, no VFS state).
        // Journal + persist happen here, still inside the single acquire_lock.
        if let Some((ref path, ref payload)) = temporal_capture {
            let _ = vfs_platform::temporal_record_write(path, payload);
        }
        if let Some(ref detail) = journal_detail {
            vfs.record_mutation_journal("fd-write", detail);
        }
        if persist_local_state {
            vfs.persist_local_state();
        }
        match &kind {
            HandleKind::MemFile { path, .. } | HandleKind::VirtioRaw { path } => vfs
                .record_watch_event(
                    VfsWatchKind::Write,
                    path,
                    Some(alloc::format!("bytes={} offset={}", written, pos)),
                ),
            HandleKind::MountFile { path, .. } => vfs.record_watch_event(
                VfsWatchKind::Write,
                path,
                Some(alloc::format!("bytes={} offset={}", written, pos)),
            ),
            _ => {}
        }
        Ok(written)
    })
}

pub fn close_fd(pid: Pid, fd: usize) -> Result<(), &'static str> {
    let handle_id = vfs_platform::get_fd_handle(pid, fd)?;
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.remove_handle(handle_id);
        vfs_platform::close_fd(pid, fd)
    })
}

/// Duplicate all open VFS handles from `parent_fd_table` for `child_pid`.
///
/// Each occupied FD slot gets a freshly allocated handle in the VFS table
/// (the `Handle` is cloned with `owner` updated to `child_pid`; `pos` is
/// preserved so the child inherits the parent's file offset, matching POSIX
/// `fork()` semantics).  The returned table uses the new child handle IDs.
/// FD slots that were `None` in the parent remain `None` in the child.
pub fn dup_fds_for_fork(
    child_pid: Pid,
    parent_fd_table: &[Option<u64>; crate::process::MAX_FD],
) -> [Option<u64>; crate::process::MAX_FD] {
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        let mut child_table = [None; crate::process::MAX_FD];
        for (slot, &entry) in parent_fd_table.iter().enumerate() {
            if let Some(parent_handle_id) = entry {
                let idx = (parent_handle_id as usize).saturating_sub(1);
                if let Some(Some(parent_handle)) = vfs.handles.get(idx) {
                    let mut child_handle = parent_handle.clone();
                    child_handle.owner = child_pid;
                    let child_handle_id = vfs.alloc_handle(child_handle);
                    child_table[slot] = Some(child_handle_id);
                }
            }
        }
        child_table
    })
}

pub fn recover_from_persistence() -> Result<(), &'static str> {
    let snapshot = if let Ok(key) = vfs_snapshot_key() {
        let capability = vfs_store_capability();
        let response = crate::fs::filesystem().handle_request(Request::read(key, capability));
        match response.status {
            ResponseStatus::Ok if !response.data.is_empty() => response.data,
            ResponseStatus::Ok => return Err("vfs snapshot empty"),
            ResponseStatus::Error(FilesystemError::NotFound) => {
                return Err("vfs flat snapshot missing");
            }
            ResponseStatus::Error(FilesystemError::PermissionDenied) => {
                return Err("vfs flat persistence read denied");
            }
            ResponseStatus::Error(_) => return Err("vfs flat persistence read failed"),
        }
    } else {
        return Err("vfs snapshot key invalid");
    };
    if snapshot.is_empty() {
        return Err("vfs snapshot empty");
    }
    let mut recovered =
        Vfs::decode_persistent_state(&snapshot).ok_or("vfs snapshot decode failed")?;
    if !crate::virtio_blk::is_present() {
        recovered.mounts.clear();
    }
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        *vfs = recovered;
        vfs.persist_local_state();
        Ok(())
    })
}

// ============================================================================
// VirtIO Mount Backend
// ============================================================================

fn mount_state_mut(vfs: &mut Vfs, mount_idx: usize) -> Result<&mut MountState, &'static str> {
    vfs.mounts
        .get_mut(mount_idx)
        .map(|mount| &mut mount.state)
        .ok_or("Mount not found")
}

fn synthetic_mount_inode_id(mount_idx: usize, node_id: MountNodeId) -> InodeId {
    0x8000_0000_0000_0000u64 | ((mount_idx as u64) << 32) | (node_id & 0xFFFF_FFFF)
}

fn mount_mkdir(vfs: &mut Vfs, mount_idx: usize, subpath: &str) -> Result<(), &'static str> {
    mount_state_mut(vfs, mount_idx)?.mkdir(subpath)
}

fn mount_create_file(
    vfs: &mut Vfs,
    mount_idx: usize,
    subpath: &str,
) -> Result<InodeId, &'static str> {
    let node_id = mount_state_mut(vfs, mount_idx)?.create_file(subpath)?;
    Ok(synthetic_mount_inode_id(mount_idx, node_id))
}

fn mount_unlink(vfs: &mut Vfs, mount_idx: usize, subpath: &str) -> Result<(), &'static str> {
    mount_state_mut(vfs, mount_idx)?.unlink(subpath)
}

fn mount_rmdir(vfs: &mut Vfs, mount_idx: usize, subpath: &str) -> Result<(), &'static str> {
    mount_state_mut(vfs, mount_idx)?.rmdir(subpath)
}

fn mount_rename(
    vfs: &mut Vfs,
    mount_idx: usize,
    old_subpath: &str,
    new_subpath: &str,
) -> Result<(), &'static str> {
    mount_state_mut(vfs, mount_idx)?.rename(old_subpath, new_subpath)
}

fn mount_link(
    vfs: &mut Vfs,
    mount_idx: usize,
    existing_subpath: &str,
    new_subpath: &str,
) -> Result<(), &'static str> {
    mount_state_mut(vfs, mount_idx)?.link(existing_subpath, new_subpath)
}

fn mount_symlink(
    vfs: &mut Vfs,
    mount_idx: usize,
    target: &str,
    link_path: &str,
) -> Result<(), &'static str> {
    let _ = normalize_path(link_path)?;
    mount_state_mut(vfs, mount_idx)?.symlink(target, link_path)
}

fn mount_readlink(vfs: &mut Vfs, mount_idx: usize, subpath: &str) -> Result<String, &'static str> {
    mount_state_mut(vfs, mount_idx)?.readlink(subpath)
}

fn mount_open_kind(
    vfs: &mut Vfs,
    mount_idx: usize,
    subpath: &str,
    flags: OpenFlags,
    full_path: &str,
) -> Result<HandleKind, &'static str> {
    mount_state_mut(vfs, mount_idx)?.open_kind(mount_idx, subpath, flags, full_path)
}

fn mount_list(
    vfs: &mut Vfs,
    mount_idx: usize,
    subpath: &str,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    mount_state_mut(vfs, mount_idx)?.list(subpath, out)
}

fn mount_read(
    vfs: &mut Vfs,
    mount_idx: usize,
    subpath: &str,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    mount_state_mut(vfs, mount_idx)?.read(subpath, out)
}

fn mount_write(
    vfs: &mut Vfs,
    mount_idx: usize,
    subpath: &str,
    data: &[u8],
) -> Result<usize, &'static str> {
    mount_state_mut(vfs, mount_idx)?.write(subpath, data)
}

fn mount_write_at(
    vfs: &mut Vfs,
    mount_idx: usize,
    subpath: &str,
    offset: usize,
    data: &[u8],
) -> Result<usize, &'static str> {
    mount_state_mut(vfs, mount_idx)?.write_at(subpath, offset, data)
}

fn mount_path_size(vfs: &mut Vfs, mount_idx: usize, subpath: &str) -> Result<usize, &'static str> {
    mount_state_mut(vfs, mount_idx)?.path_size(subpath)
}

fn mount_file_read_at(
    vfs: &mut Vfs,
    mount_idx: usize,
    node_id: MountNodeId,
    offset: usize,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    match mount_state_mut(vfs, mount_idx)? {
        MountState::VirtioBlock(state) => {
            let node = state.get_node(node_id).ok_or("File not found")?;
            if node.kind != MountNodeKind::File {
                return Err("Not a file");
            }
            if offset >= node.data.len() {
                return Ok(0);
            }
            let len = min(out.len(), node.data.len() - offset);
            out[..len].copy_from_slice(&node.data[offset..offset + len]);
            Ok(len)
        }
    }
}

fn mount_file_write_at_node(
    vfs: &mut Vfs,
    mount_idx: usize,
    node_id: MountNodeId,
    offset: usize,
    data: &[u8],
) -> Result<usize, &'static str> {
    match mount_state_mut(vfs, mount_idx)? {
        MountState::VirtioBlock(state) => {
            let node = state.get_node_mut(node_id).ok_or("File not found")?;
            if node.kind != MountNodeKind::File {
                return Err("Not a file");
            }
            if offset > node.data.len() {
                node.data.resize(offset, 0);
            }
            if offset + data.len() > node.data.len() {
                node.data.resize(offset + data.len(), 0);
            }
            node.data[offset..offset + data.len()].copy_from_slice(data);
            Ok(data.len())
        }
    }
}

pub const TEMPORAL_DEVICE_ENCODING_V1: u8 = 1;
pub const TEMPORAL_DEVICE_ENCODING_V2: u8 = 2;
pub const TEMPORAL_DEVICE_OBJECT_VIRTIO_RAW: u8 = 1;
pub const TEMPORAL_DEVICE_EVENT_WRITE: u8 = 1;
pub const TEMPORAL_DEVICE_FLAG_PARTIAL_CAPTURE: u8 = 1 << 0;
const TEMPORAL_DEVICE_CAPTURE_MAX_BYTES: usize = 240 * 1024;

fn capture_temporal_backend_write(path: &str, offset: usize, data: &[u8], written: usize) {
    let effective = min(written, data.len());
    let encoded_write_len = min(effective, u32::MAX as usize);
    let stored_len = min(encoded_write_len, TEMPORAL_DEVICE_CAPTURE_MAX_BYTES);
    let flags = if stored_len < effective {
        TEMPORAL_DEVICE_FLAG_PARTIAL_CAPTURE
    } else {
        0
    };
    let mut payload = Vec::new();
    payload.reserve(28usize.saturating_add(stored_len));
    payload.push(TEMPORAL_DEVICE_ENCODING_V2);
    payload.push(TEMPORAL_DEVICE_OBJECT_VIRTIO_RAW);
    payload.push(TEMPORAL_DEVICE_EVENT_WRITE);
    payload.push(flags);
    payload.extend_from_slice(&(offset as u64).to_le_bytes());
    payload.extend_from_slice(&(encoded_write_len as u32).to_le_bytes());
    payload.extend_from_slice(&(stored_len as u32).to_le_bytes());
    payload.extend_from_slice(&vfs_platform::ticks_now().to_le_bytes());
    payload.extend_from_slice(&data[..stored_len]);
    let _ = vfs_platform::temporal_record_object_write(path, &payload);
}

pub fn temporal_try_apply_backend_payload(
    path: &str,
    payload: &[u8],
) -> Result<bool, &'static str> {
    let normalized_path = normalize_path(path)?;

    let (offset, write_len, stored_len, data_offset, flags) =
        decode_temporal_backend_payload(payload)?;
    if (flags & TEMPORAL_DEVICE_FLAG_PARTIAL_CAPTURE) != 0 {
        return Err("Temporal backend payload is partial");
    }
    if stored_len != write_len {
        return Err("Temporal backend payload length mismatch");
    }
    if data_offset.saturating_add(stored_len) > payload.len() {
        return Err("Temporal backend payload truncated");
    }
    let write_data = &payload[data_offset..data_offset + stored_len];
    let offset_usize = usize::try_from(offset).map_err(|_| "Temporal backend offset overflow")?;

    // Single acquire_lock for the entire payload application (PMA §9).
    thread_context().acquire_lock(&VFS, |vfs, _sub| {
        vfs.init();
        let (mount_idx, _backend, sub) = match vfs.find_mount(&normalized_path) {
            Some(v) => v,
            None => return Ok(false),
        };
        if normalize_subpath(&sub) != "/raw" {
            return Ok(false);
        }
        let chain = vfs.resolve_authority_chain(&normalized_path, true)?;
        let _ = vfs.ensure_path_rights(
            vfs_platform::current_pid(),
            &normalized_path,
            &chain,
            VfsAccess::Write,
        )?;
        let written = match mount_write_at(vfs, mount_idx, &sub, offset_usize, write_data) {
            Ok(w) => {
                vfs.note_mount_success(mount_idx, MountOperation::Write);
                w
            }
            Err(e) => {
                vfs.note_mount_error(mount_idx, MountOperation::Write, &sub, e);
                return Err(e);
            }
        };
        if written != write_data.len() {
            return Err("Temporal backend short write");
        }
        Ok(true)
    })
}

fn decode_temporal_backend_payload(
    payload: &[u8],
) -> Result<(u64, usize, usize, usize, u8), &'static str> {
    if payload.len() < 28 {
        return Err("Temporal backend payload too short");
    }
    if payload[1] != TEMPORAL_DEVICE_OBJECT_VIRTIO_RAW {
        return Err("Temporal backend object mismatch");
    }
    if payload[2] != TEMPORAL_DEVICE_EVENT_WRITE {
        return Err("Temporal backend event mismatch");
    }

    let flags = payload[3];
    let offset = read_u64(payload, 4).ok_or("Temporal backend offset missing")?;
    match payload[0] {
        TEMPORAL_DEVICE_ENCODING_V1 => {
            let write_len =
                read_u32(payload, 12).ok_or("Temporal backend write length missing")? as usize;
            let stored_len =
                read_u16(payload, 16).ok_or("Temporal backend stored length missing")? as usize;
            Ok((offset, write_len, stored_len, 28, flags))
        }
        TEMPORAL_DEVICE_ENCODING_V2 => {
            let write_len =
                read_u32(payload, 12).ok_or("Temporal backend write length missing")? as usize;
            let stored_len =
                read_u32(payload, 16).ok_or("Temporal backend stored length missing")? as usize;
            Ok((offset, write_len, stored_len, 28, flags))
        }
        _ => Err("Temporal backend encoding unsupported"),
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
            let _ = writeln!(
                s,
                "  {}: lba {}-{} name {}",
                i + 1,
                part.first_lba,
                part.last_lba,
                name
            );
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

fn components_to_path(components: &[String]) -> String {
    if components.is_empty() {
        return "/".to_string();
    }
    let mut out = String::new();
    for comp in components {
        out.push('/');
        out.push_str(comp);
    }
    out
}

fn join_paths(base: &str, tail: &str) -> Result<String, &'static str> {
    if tail.starts_with('/') {
        return normalize_path(tail);
    }
    let mut out = if base == "/" {
        String::from("/")
    } else {
        normalize_path(base)?
    };
    if out != "/" {
        out.push('/');
    }
    out.push_str(tail);
    normalize_path(&out)
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
        sector_buf[sector_off..sector_off + chunk]
            .copy_from_slice(&data[data_off..data_off + chunk]);
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

#[cfg(not(target_arch = "aarch64"))]
fn pid_key(pid: Pid) -> u32 {
    pid.0
}

#[cfg(target_arch = "aarch64")]
fn pid_key(pid: Pid) -> u32 {
    pid.0
}

fn allocate_vfs_storage_namespace() -> u64 {
    NEXT_VFS_STORAGE_NAMESPACE.fetch_add(1, Ordering::Relaxed) as u64
}

fn vfs_store_capability() -> FilesystemCapability {
    let prefix = FileKey::new(VFS_STORE_PREFIX).expect("static VFS store prefix must be valid");
    FilesystemCapability::scoped(0, FilesystemRights::all(), prefix)
}

fn vfs_snapshot_key() -> Result<FileKey, &'static str> {
    FileKey::new(VFS_SNAPSHOT_KEY).map_err(|_| "Invalid VFS snapshot key")
}

fn vfs_journal_key() -> Result<FileKey, &'static str> {
    FileKey::new(VFS_JOURNAL_KEY).map_err(|_| "Invalid VFS journal key")
}

fn inode_payload_key_for_namespace(
    storage_namespace: u64,
    inode_id: InodeId,
) -> Result<FileKey, &'static str> {
    FileKey::new(&alloc::format!(
        "vfs/ns/{}/inode/{}/data",
        storage_namespace,
        inode_id
    ))
    .map_err(|_| "Invalid VFS payload key")
}

fn rights_bits(rights: &FilesystemRights) -> u32 {
    let mut bits = 0u32;
    if rights.has(FilesystemRights::READ) {
        bits |= FilesystemRights::READ;
    }
    if rights.has(FilesystemRights::WRITE) {
        bits |= FilesystemRights::WRITE;
    }
    if rights.has(FilesystemRights::DELETE) {
        bits |= FilesystemRights::DELETE;
    }
    if rights.has(FilesystemRights::LIST) {
        bits |= FilesystemRights::LIST;
    }
    bits
}

fn encode_option_u64(out: &mut Vec<u8>, value: Option<usize>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&(value as u64).to_le_bytes());
        }
        None => out.push(0),
    }
}

fn decode_option_u64(data: &[u8], cursor: &mut usize) -> Option<Option<usize>> {
    let present = *data.get(*cursor)?;
    *cursor += 1;
    if present == 0 {
        return Some(None);
    }
    let value = read_u64(data, *cursor)?;
    *cursor += 8;
    usize::try_from(value).ok().map(Some)
}

fn encode_capability(
    out: &mut Vec<u8>,
    capability: &FilesystemCapability,
) -> Result<(), &'static str> {
    out.extend_from_slice(&capability.cap_id.to_le_bytes());
    out.extend_from_slice(&rights_bits(&capability.rights).to_le_bytes());

    match capability.key_prefix.as_ref() {
        Some(prefix) => {
            out.push(1);
            let prefix_bytes = prefix.as_str().as_bytes();
            let prefix_len =
                u16::try_from(prefix_bytes.len()).map_err(|_| "Persistent key prefix too long")?;
            out.extend_from_slice(&prefix_len.to_le_bytes());
            out.extend_from_slice(prefix_bytes);
        }
        None => out.push(0),
    }

    match capability.quota {
        Some(quota) => {
            out.push(1);
            encode_option_u64(out, quota.max_total_bytes);
            encode_option_u64(out, quota.max_file_count);
            encode_option_u64(out, quota.max_single_file_bytes);
        }
        None => out.push(0),
    }
    Ok(())
}

fn decode_capability(data: &[u8], cursor: &mut usize) -> Option<FilesystemCapability> {
    let cap_id = read_u32(data, *cursor)?;
    *cursor += 4;
    let rights_bits = read_u32(data, *cursor)?;
    *cursor += 4;

    let key_prefix = match *data.get(*cursor)? {
        0 => {
            *cursor += 1;
            None
        }
        1 => {
            *cursor += 1;
            let prefix_len = read_u16(data, *cursor)? as usize;
            *cursor += 2;
            if (*cursor).saturating_add(prefix_len) > data.len() {
                return None;
            }
            let prefix = core::str::from_utf8(&data[*cursor..*cursor + prefix_len])
                .ok()
                .and_then(|s| FileKey::new(s).ok())?;
            *cursor += prefix_len;
            Some(prefix)
        }
        _ => return None,
    };

    let quota = match *data.get(*cursor)? {
        0 => {
            *cursor += 1;
            None
        }
        1 => {
            *cursor += 1;
            Some(FilesystemQuota::bounded(
                decode_option_u64(data, cursor)?,
                decode_option_u64(data, cursor)?,
                decode_option_u64(data, cursor)?,
            ))
        }
        _ => return None,
    };

    Some(FilesystemCapability {
        cap_id,
        rights: FilesystemRights::new(rights_bits),
        key_prefix,
        quota,
    })
}

fn min_option_usize(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => Some(left.min(right)),
    }
}

fn merge_quota(
    left: Option<FilesystemQuota>,
    right: Option<FilesystemQuota>,
) -> Option<FilesystemQuota> {
    match (left, right) {
        (None, None) => None,
        (Some(quota), None) | (None, Some(quota)) => Some(quota),
        (Some(left), Some(right)) => Some(FilesystemQuota::bounded(
            min_option_usize(left.max_total_bytes, right.max_total_bytes),
            min_option_usize(left.max_file_count, right.max_file_count),
            min_option_usize(left.max_single_file_bytes, right.max_single_file_bytes),
        )),
    }
}

fn attenuate_capability(
    mut capability: FilesystemCapability,
    attenuator: &FilesystemCapability,
) -> FilesystemCapability {
    capability = capability.attenuate(attenuator.rights);
    capability.quota = merge_quota(capability.quota, attenuator.quota);
    capability
}

fn capability_allows_path(capability: &FilesystemCapability, path: &str) -> bool {
    let Some(prefix) = capability.key_prefix.as_ref() else {
        return true;
    };
    let prefix = prefix.as_str();
    if prefix.is_empty() || !prefix.starts_with('/') {
        return true;
    }
    path == prefix
        || prefix == "/"
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn access_allowed(capability: &FilesystemCapability, access: VfsAccess) -> bool {
    match access {
        VfsAccess::Read => capability.rights.has(FilesystemRights::READ),
        VfsAccess::Write => capability.rights.has(FilesystemRights::WRITE),
        VfsAccess::List => {
            capability.rights.has(FilesystemRights::LIST)
                || capability.rights.has(FilesystemRights::READ)
        }
        VfsAccess::Delete => capability.rights.has(FilesystemRights::DELETE),
    }
}

fn rewrite_path_prefix(path: &str, old_path: &str, new_path: &str) -> Option<String> {
    if path == old_path {
        return Some(new_path.to_string());
    }
    let suffix = path.strip_prefix(old_path)?;
    if !suffix.starts_with('/') {
        return None;
    }
    let mut rewritten = new_path.to_string();
    rewritten.push_str(suffix);
    Some(rewritten)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset.saturating_add(4) > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    if offset.saturating_add(8) > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

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

fn watch_kind_code(kind: VfsWatchKind) -> u8 {
    match kind {
        VfsWatchKind::Read => 0,
        VfsWatchKind::Write => 1,
        VfsWatchKind::List => 2,
        VfsWatchKind::Create => 3,
        VfsWatchKind::Delete => 4,
        VfsWatchKind::Rename => 5,
        VfsWatchKind::Link => 6,
        VfsWatchKind::Symlink => 7,
        VfsWatchKind::ReadLink => 8,
        VfsWatchKind::Mkdir => 9,
        VfsWatchKind::Rmdir => 10,
        VfsWatchKind::Mount => 11,
    }
}

fn watch_kind_str(kind: VfsWatchKind) -> &'static str {
    match kind {
        VfsWatchKind::Read => "read",
        VfsWatchKind::Write => "write",
        VfsWatchKind::List => "list",
        VfsWatchKind::Create => "create",
        VfsWatchKind::Delete => "delete",
        VfsWatchKind::Rename => "rename",
        VfsWatchKind::Link => "link",
        VfsWatchKind::Symlink => "symlink",
        VfsWatchKind::ReadLink => "readlink",
        VfsWatchKind::Mkdir => "mkdir",
        VfsWatchKind::Rmdir => "rmdir",
        VfsWatchKind::Mount => "mount",
    }
}

fn append_bounded_utf8(out: &mut String, text: &str, max_bytes: usize) {
    if max_bytes == 0 {
        return;
    }
    for ch in text.chars() {
        let mut encoded = [0u8; 4];
        let width = ch.encode_utf8(&mut encoded).len();
        if out.len().saturating_add(width) > max_bytes {
            break;
        }
        out.push(ch);
    }
}

fn encode_watch_event_payload(event: &VfsWatchEvent) -> Vec<u8> {
    let mut payload = String::new();
    let max_bytes = crate::ipc::MAX_MESSAGE_SIZE;
    let _ = write!(
        payload,
        "seq={} watch={} kind={} path=",
        event.sequence,
        event.watch_id,
        watch_kind_str(event.kind)
    );
    append_bounded_utf8(&mut payload, &event.path, max_bytes);
    if let Some(detail) = event.detail.as_deref() {
        if payload.len() < max_bytes {
            payload.push_str(" detail=");
            append_bounded_utf8(&mut payload, detail, max_bytes);
        }
    }
    if payload.len() > max_bytes {
        payload.truncate(max_bytes);
    }
    payload.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pid(id: u32) -> Pid {
        Pid::new(id)
    }

    #[test]
    fn vfs_symlink_link_rename_roundtrip() {
        let mut vfs = Vfs::new();
        vfs.init();

        let tmp = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "tmp", tmp).unwrap();

        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.write_file_payload(file, b"hello").unwrap();
        vfs.add_dir_entry(tmp, "a", file).unwrap();

        vfs.symlink_path("/tmp/a", "/tmp/link").unwrap();
        assert_eq!(vfs.resolve_path("/tmp/link").unwrap(), file);
        assert_eq!(vfs.readlink_path("/tmp/link").unwrap(), "/tmp/a");

        vfs.link_path("/tmp/a", "/tmp/a2").unwrap();
        let linked = vfs.resolve_path_nofollow("/tmp/a2").unwrap();
        assert_eq!(linked, file);
        assert_eq!(vfs.get_inode(file).unwrap().meta.nlink, 2);

        vfs.rename_path("/tmp/a2", "/tmp/renamed").unwrap();
        assert_eq!(vfs.resolve_path_nofollow("/tmp/renamed").unwrap(), file);
        assert!(vfs.resolve_path_nofollow("/tmp/a2").is_err());
    }

    #[test]
    fn vfs_persistent_state_roundtrip() {
        let mut vfs = Vfs::new();
        vfs.init();

        let dir = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "data", dir).unwrap();
        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.write_file_payload(file, b"payload").unwrap();
        vfs.add_dir_entry(dir, "blob", file).unwrap();
        vfs.symlink_path("/data/blob", "/data/blob.link").unwrap();

        let encoded = vfs.encode_persistent_state().unwrap();
        let mut decoded = Vfs::decode_persistent_state(&encoded).unwrap();

        let resolved = decoded.resolve_path("/data/blob.link").unwrap();
        assert_eq!(resolved, file);
        assert_eq!(
            decoded.readlink_path("/data/blob.link").unwrap(),
            "/data/blob"
        );
        assert_eq!(decoded.read_file_payload(file).unwrap(), b"payload");
    }

    #[test]
    fn vfs_fsck_repairs_dangling_entries_and_orphans() {
        let mut vfs = Vfs::new();
        vfs.init();

        let dir = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "data", dir).unwrap();

        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.write_file_payload(file, b"payload").unwrap();
        {
            let inode = vfs.get_inode_mut(file).unwrap();
            inode.meta.size = 99;
            inode.meta.nlink = 0;
        }

        {
            let dir_inode = vfs.get_inode_mut(dir).unwrap();
            dir_inode.entries.push(DirEntry {
                name: "dangling".to_string(),
                inode: 9999,
            });
        }

        let report = vfs.fsck_and_repair().unwrap();
        assert_eq!(report.dangling_entries_removed, 1);
        assert_eq!(report.orphaned_inodes_relinked, 1);
        assert_eq!(report.size_repairs, 1);
        assert_eq!(vfs.get_inode(file).unwrap().meta.size, 7);
        assert_eq!(vfs.lookup_child(1, "lost+found").is_ok(), true);
    }

    #[test]
    fn vfs_policy_enforces_runtime_file_size_limit() {
        let mut vfs = Vfs::new();
        vfs.policy = Some(VfsPolicy::bounded(4));
        vfs.init();

        let dir = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "tmp", dir).unwrap();
        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.add_dir_entry(dir, "small", file).unwrap();

        assert!(vfs.ensure_file_size_allowed(4).is_ok());
        assert_eq!(
            vfs.ensure_file_size_allowed(5),
            Err("Configured VFS file size limit exceeded")
        );
    }

    #[test]
    fn vfs_capability_mapper_attenuates_directory_rights() {
        let mut vfs = Vfs::new();
        vfs.init();

        let tmp = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "tmp", tmp).unwrap();
        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.write_file_payload(file, b"data").unwrap();
        vfs.add_dir_entry(tmp, "note", file).unwrap();

        let pid = test_pid(7);
        vfs.set_process_capability(pid, FilesystemCapability::new(7, FilesystemRights::all()));
        vfs.set_directory_capability_by_inode(
            tmp,
            FilesystemCapability::new(8, FilesystemRights::read_only()),
        )
        .unwrap();

        let chain = vfs.resolve_path_chain("/tmp/note", true).unwrap();
        assert!(vfs
            .ensure_path_rights(Some(pid), "/tmp/note", &chain, VfsAccess::Read)
            .is_ok());
        assert_eq!(
            vfs.ensure_path_rights(Some(pid), "/tmp/note", &chain, VfsAccess::Write),
            Err("Permission denied")
        );
    }

    #[test]
    fn vfs_capability_quota_limits_subtree_growth() {
        let mut vfs = Vfs::new();
        vfs.init();

        let tmp = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "tmp", tmp).unwrap();
        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.write_file_payload(file, b"abc").unwrap();
        vfs.add_dir_entry(tmp, "one", file).unwrap();

        let quota = FilesystemQuota::bounded(Some(4), Some(1), Some(4));
        vfs.set_directory_capability_by_inode(
            tmp,
            FilesystemCapability::with_quota(9, FilesystemRights::all(), quota),
        )
        .unwrap();

        let existing_chain = vfs.resolve_path_chain("/tmp/one", true).unwrap();
        assert_eq!(
            vfs.ensure_quota_allows(None, &existing_chain, 3, 5, false),
            Err("Capability quota exceeded")
        );

        let create_chain = vfs.resolve_parent_chain("/tmp/two").unwrap();
        assert_eq!(
            vfs.ensure_quota_allows(None, &create_chain, 0, 0, true),
            Err("Capability quota exceeded")
        );
    }

    #[test]
    fn vfs_process_capability_inheritance_can_attenuate() {
        let mut vfs = Vfs::new();
        vfs.init();

        let pid_parent = test_pid(10);
        let pid_child = test_pid(11);
        vfs.set_process_capability(
            pid_parent,
            FilesystemCapability::new(10, FilesystemRights::all()),
        );
        vfs.inherit_process_capability(pid_parent, pid_child, Some(FilesystemRights::read_only()));

        let parent_cap = vfs.resolve_process_capability(Some(pid_parent));
        let child_cap = vfs.resolve_process_capability(Some(pid_child));
        assert!(access_allowed(&parent_cap, VfsAccess::Write));
        assert!(access_allowed(&child_cap, VfsAccess::Read));
        assert!(!access_allowed(&child_cap, VfsAccess::Write));
    }

    #[test]
    fn vfs_handle_revalidation_reflects_revoked_write_access() {
        let mut vfs = Vfs::new();
        vfs.init();

        let tmp = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "tmp", tmp).unwrap();
        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.write_file_payload(file, b"data").unwrap();
        vfs.add_dir_entry(tmp, "note", file).unwrap();

        let pid = test_pid(21);
        vfs.set_process_capability(pid, FilesystemCapability::new(21, FilesystemRights::all()));
        let chain = vfs.resolve_path_chain("/tmp/note", true).unwrap();
        let capability = vfs
            .ensure_path_rights(Some(pid), "/tmp/note", &chain, VfsAccess::Write)
            .unwrap();
        let handle = Handle {
            kind: HandleKind::MemFile {
                inode: file,
                path: "/tmp/note".to_string(),
            },
            pos: 0,
            flags: OpenFlags::READ | OpenFlags::WRITE,
            owner: pid,
            capability,
        };

        vfs.set_directory_capability_by_inode(
            tmp,
            FilesystemCapability::new(22, FilesystemRights::read_only()),
        )
        .unwrap();

        assert!(vfs
            .revalidate_handle_access(pid, &handle.kind, VfsAccess::Read)
            .is_ok());
        assert_eq!(
            vfs.revalidate_handle_access(pid, &handle.kind, VfsAccess::Write),
            Err("Permission denied")
        );
    }

    #[test]
    fn vfs_rename_rewrites_open_handle_paths() {
        let mut vfs = Vfs::new();
        vfs.init();

        let tmp = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "tmp", tmp).unwrap();
        let file = vfs.alloc_inode(InodeKind::File, 0o644);
        vfs.write_file_payload(file, b"data").unwrap();
        vfs.add_dir_entry(tmp, "note", file).unwrap();

        let handle_id = vfs.alloc_handle(Handle {
            kind: HandleKind::MemFile {
                inode: file,
                path: "/tmp/note".to_string(),
            },
            pos: 0,
            flags: OpenFlags::READ,
            owner: test_pid(23),
            capability: FilesystemCapability::new(23, FilesystemRights::read_only()),
        });

        vfs.rename_path("/tmp/note", "/tmp/renamed").unwrap();

        match &vfs.get_handle_mut(handle_id).unwrap().kind {
            HandleKind::MemFile { path, .. } => assert_eq!(path, "/tmp/renamed"),
            other => panic!("unexpected handle kind: {:?}", other),
        }
    }

    #[test]
    fn vfs_persistent_state_roundtrip_preserves_capability_maps() {
        let mut vfs = Vfs::new();
        vfs.init();

        let tmp = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "tmp", tmp).unwrap();
        vfs.set_directory_capability_by_inode(
            tmp,
            FilesystemCapability::with_quota(
                42,
                FilesystemRights::read_only(),
                FilesystemQuota::bounded(Some(64), Some(4), Some(16)),
            ),
        )
        .unwrap();
        vfs.set_process_capability(
            test_pid(33),
            FilesystemCapability::new(77, FilesystemRights::all()),
        );

        let encoded = vfs.encode_persistent_state().unwrap();
        let decoded = Vfs::decode_persistent_state(&encoded).unwrap();

        let dir_cap = decoded.directory_capability_by_inode(tmp).unwrap().unwrap();
        assert_eq!(dir_cap.cap_id, 42);
        assert!(dir_cap.rights.has(FilesystemRights::READ));
        assert!(!dir_cap.rights.has(FilesystemRights::WRITE));
        assert_eq!(
            dir_cap.quota,
            Some(FilesystemQuota::bounded(Some(64), Some(4), Some(16)))
        );

        let proc_cap = decoded.process_capability(test_pid(33)).unwrap();
        assert_eq!(proc_cap.cap_id, 77);
        assert!(proc_cap.rights.has(FilesystemRights::WRITE));
    }

    #[test]
    fn virtio_mount_overlay_supports_real_mutation() {
        let mut vfs = Vfs::new();
        vfs.init();

        let mnt = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "mnt", mnt).unwrap();
        vfs.mounts.push(Mount {
            path: "/mnt".to_string(),
            backend: MountBackend::VirtioBlock,
            state: MountState::VirtioBlock(VirtioMountState::new()),
            health: MountHealthCounters::default(),
        });

        mount_mkdir(&mut vfs, 0, "/docs").unwrap();
        let _ = mount_create_file(&mut vfs, 0, "/docs/note").unwrap();
        assert_eq!(mount_write(&mut vfs, 0, "/docs/note", b"hello").unwrap(), 5);

        let mut buf = [0u8; 8];
        let len = mount_read(&mut vfs, 0, "/docs/note", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");

        mount_symlink(&mut vfs, 0, "/docs/note", "/docs/link").unwrap();
        assert_eq!(
            mount_readlink(&mut vfs, 0, "/docs/link").unwrap(),
            "/docs/note"
        );

        mount_rename(&mut vfs, 0, "/docs/note", "/docs/note2").unwrap();
        let len = mount_read(&mut vfs, 0, "/docs/note2", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello");

        mount_unlink(&mut vfs, 0, "/docs/link").unwrap();
        mount_unlink(&mut vfs, 0, "/docs/note2").unwrap();
        mount_rmdir(&mut vfs, 0, "/docs").unwrap();

        let mut root_list = [0u8; 64];
        let root_len = mount_list(&mut vfs, 0, "/", &mut root_list).unwrap();
        let listing = core::str::from_utf8(&root_list[..root_len]).unwrap();
        assert!(listing.contains("raw"));
        assert!(listing.contains("partitions"));
        assert!(!listing.contains("docs"));
    }

    #[test]
    fn vfs_persistent_state_roundtrip_preserves_mount_overlay() {
        let mut vfs = Vfs::new();
        vfs.init();

        let mnt = vfs.alloc_inode(InodeKind::Directory, 0o755);
        vfs.add_dir_entry(1, "disk", mnt).unwrap();
        vfs.mounts.push(Mount {
            path: "/disk".to_string(),
            backend: MountBackend::VirtioBlock,
            state: MountState::VirtioBlock(VirtioMountState::new()),
            health: MountHealthCounters::default(),
        });
        mount_mkdir(&mut vfs, 0, "/cfg").unwrap();
        let _ = mount_create_file(&mut vfs, 0, "/cfg/settings").unwrap();
        mount_write(&mut vfs, 0, "/cfg/settings", b"ok").unwrap();

        let encoded = vfs.encode_persistent_state().unwrap();
        let mut decoded = Vfs::decode_persistent_state(&encoded).unwrap();

        let mut buf = [0u8; 8];
        let len = mount_read(&mut decoded, 0, "/cfg/settings", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"ok");
        let mut root_list = [0u8; 64];
        let root_len = mount_list(&mut decoded, 0, "/", &mut root_list).unwrap();
        let listing = core::str::from_utf8(&root_list[..root_len]).unwrap();
        assert!(listing.contains("cfg"));
        assert!(listing.contains("raw"));
    }

    #[test]
    fn watch_subscriber_ack_clears_inflight_and_updates_stats() {
        let mut vfs = Vfs::new();
        vfs.init();

        let mut subscriber = VfsWatchSubscriber::new(7);
        subscriber.backlog.push_back(VfsWatchEvent {
            sequence: 41,
            watch_id: 0,
            kind: VfsWatchKind::Write,
            path: "/tmp/note".to_string(),
            detail: None,
        });
        subscriber.in_flight = Some(41);
        vfs.notify_channels.insert(7, subscriber);

        vfs.ack_notify_channel(7, 41).unwrap();

        let stats = vfs.notify_channel_stats(7).unwrap();
        assert_eq!(stats.channel_id, 7);
        assert_eq!(stats.pending_events, 0);
        assert_eq!(stats.in_flight, None);
        assert_eq!(stats.last_acked_sequence, 41);
        assert_eq!(stats.dropped_count, 0);
    }

    #[test]
    fn watch_subscriber_trim_preserves_inflight_event() {
        let mut subscriber = VfsWatchSubscriber::new(9);
        subscriber.backlog.push_back(VfsWatchEvent {
            sequence: 1,
            watch_id: 0,
            kind: VfsWatchKind::Create,
            path: "/a".to_string(),
            detail: None,
        });
        subscriber.backlog.push_back(VfsWatchEvent {
            sequence: 2,
            watch_id: 0,
            kind: VfsWatchKind::Write,
            path: "/b".to_string(),
            detail: None,
        });
        subscriber.backlog.push_back(VfsWatchEvent {
            sequence: 3,
            watch_id: 0,
            kind: VfsWatchKind::Delete,
            path: "/c".to_string(),
            detail: None,
        });
        subscriber.in_flight = Some(1);

        Vfs::trim_notify_backlog(&mut subscriber, 2);

        assert_eq!(subscriber.dropped_count, 1);
        assert_eq!(subscriber.backlog.len(), 2);
        assert_eq!(subscriber.backlog.front().unwrap().sequence, 1);
        assert_eq!(subscriber.backlog.back().unwrap().sequence, 2);
    }
}

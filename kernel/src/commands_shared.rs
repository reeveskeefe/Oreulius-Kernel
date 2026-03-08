/*!
 * Shared cross-architecture command handlers used by both the full x86 shell
 * and the AArch64 runtime shell adapter.
 */

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;

use crate::fs::{FilesystemCapability, FilesystemQuota, FilesystemRights};
use crate::vfs;
use crate::vfs_platform;

fn write_line<W: Write>(out: &mut W, prefix: &str, body: &str) {
    if prefix.is_empty() {
        let _ = writeln!(out, "{}", body);
    } else {
        let _ = writeln!(out, "{} {}", prefix, body);
    }
}

fn parse_u64_auto(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() {
            return None;
        }
        let mut value = 0u64;
        for b in hex.bytes() {
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u64,
                b'a'..=b'f' => (b - b'a' + 10) as u64,
                b'A'..=b'F' => (b - b'A' + 10) as u64,
                _ => return None,
            };
            value = value.checked_mul(16)?;
            value = value.checked_add(digit)?;
        }
        Some(value)
    } else {
        if s.is_empty() {
            return None;
        }
        let mut value = 0u64;
        for b in s.bytes() {
            if !b.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?;
            value = value.checked_add((b - b'0') as u64)?;
        }
        Some(value)
    }
}

fn parse_usize_auto(s: &str) -> Option<usize> {
    usize::try_from(parse_u64_auto(s)?).ok()
}

fn parse_u32_auto(s: &str) -> Option<u32> {
    u32::try_from(parse_u64_auto(s)?).ok()
}

fn print_hexdump<W: Write>(out: &mut W, prefix: &str, label: &str, buf: &[u8]) {
    let rows = core::cmp::min((buf.len() + 15) / 16, 8);
    for row in 0..rows {
        let off = row * 16;
        let end = core::cmp::min(off + 16, buf.len());
        if prefix.is_empty() {
            let _ = write!(out, "{} {:04x}: ", label, off);
        } else {
            let _ = write!(out, "{} {} {:04x}: ", prefix, label, off);
        }
        for i in off..end {
            let _ = write!(out, "{:02x} ", buf[i]);
        }
        for _ in end..(off + 16) {
            let _ = write!(out, "   ");
        }
        let _ = write!(out, " |");
        for &b in &buf[off..end] {
            let ch = if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            };
            let _ = write!(out, "{}", ch);
        }
        let _ = writeln!(out, "|");
    }
}

fn parse_open_flags(mode: &str) -> vfs::OpenFlags {
    match mode {
        "w" => vfs::OpenFlags::WRITE | vfs::OpenFlags::CREATE | vfs::OpenFlags::TRUNC,
        "rw" => vfs::OpenFlags::READ | vfs::OpenFlags::WRITE,
        "rwc" => vfs::OpenFlags::READ | vfs::OpenFlags::WRITE | vfs::OpenFlags::CREATE,
        "append" => vfs::OpenFlags::WRITE | vfs::OpenFlags::CREATE | vfs::OpenFlags::APPEND,
        _ => vfs::OpenFlags::READ,
    }
}

fn format_rights(rights: &FilesystemRights) -> String {
    let mut out = String::new();
    if rights.has(FilesystemRights::READ) {
        out.push('r');
    }
    if rights.has(FilesystemRights::WRITE) {
        out.push('w');
    }
    if rights.has(FilesystemRights::DELETE) {
        out.push('d');
    }
    if rights.has(FilesystemRights::LIST) {
        out.push('l');
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

fn format_quota_bound(value: Option<usize>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn format_capability(capability: &FilesystemCapability) -> String {
    let quota = capability.quota.unwrap_or(FilesystemQuota::unlimited());
    alloc::format!(
        "cap_id={} rights={} prefix={} quota_total={} quota_files={} quota_single={}",
        capability.cap_id,
        format_rights(&capability.rights),
        capability
            .key_prefix
            .as_ref()
            .map(|prefix| prefix.as_str().to_string())
            .unwrap_or_else(|| "-".to_string()),
        format_quota_bound(quota.max_total_bytes),
        format_quota_bound(quota.max_file_count),
        format_quota_bound(quota.max_single_file_bytes),
    )
}

fn format_watch_kind(kind: vfs::VfsWatchKind) -> &'static str {
    match kind {
        vfs::VfsWatchKind::Read => "read",
        vfs::VfsWatchKind::Write => "write",
        vfs::VfsWatchKind::List => "list",
        vfs::VfsWatchKind::Create => "create",
        vfs::VfsWatchKind::Delete => "delete",
        vfs::VfsWatchKind::Rename => "rename",
        vfs::VfsWatchKind::Link => "link",
        vfs::VfsWatchKind::Symlink => "symlink",
        vfs::VfsWatchKind::ReadLink => "readlink",
        vfs::VfsWatchKind::Mkdir => "mkdir",
        vfs::VfsWatchKind::Rmdir => "rmdir",
        vfs::VfsWatchKind::Mount => "mount",
    }
}

fn format_watch_scope(recursive: bool) -> &'static str {
    if recursive {
        "tree"
    } else {
        "exact"
    }
}

fn parse_rights(spec: &str) -> Option<FilesystemRights> {
    if spec.eq_ignore_ascii_case("all") {
        return Some(FilesystemRights::all());
    }
    if spec == "-" || spec.eq_ignore_ascii_case("none") {
        return Some(FilesystemRights::new(0));
    }
    let mut bits = 0u32;
    for ch in spec.chars() {
        match ch {
            'r' | 'R' => bits |= FilesystemRights::READ,
            'w' | 'W' => bits |= FilesystemRights::WRITE,
            'd' | 'D' => bits |= FilesystemRights::DELETE,
            'l' | 'L' => bits |= FilesystemRights::LIST,
            _ => return None,
        }
    }
    Some(FilesystemRights::new(bits))
}

fn parse_quota_bound(token: &str) -> Option<Option<usize>> {
    if matches!(token, "-" | "none" | "unbounded" | "*") {
        Some(None)
    } else {
        parse_usize_auto(token).map(Some)
    }
}

fn parse_quota_args(args: &[&str]) -> Option<Option<FilesystemQuota>> {
    if args.is_empty() {
        return Some(None);
    }
    if args.len() != 3 {
        return None;
    }
    Some(Some(FilesystemQuota::bounded(
        parse_quota_bound(args[0])?,
        parse_quota_bound(args[1])?,
        parse_quota_bound(args[2])?,
    )))
}

fn shell_cap_id(label: &str, salt: u32) -> u32 {
    let mut hash = 0x811c9dc5u32 ^ salt;
    for &b in label.as_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn build_capability(
    identity: &str,
    rights_spec: &str,
    quota_args: &[&str],
    salt: u32,
) -> Option<FilesystemCapability> {
    let rights = parse_rights(rights_spec)?;
    let quota = parse_quota_args(quota_args)?;
    let cap_id = shell_cap_id(identity, salt);
    Some(match quota {
        Some(quota) => FilesystemCapability::with_quota(cap_id, rights, quota),
        None => FilesystemCapability::new(cap_id, rights),
    })
}

pub fn print_help<W: Write>(out: &mut W, prefix: &str) {
    write_line(out, prefix, "shared commands:");
    write_line(out, prefix, "  help-cmd");
    write_line(out, prefix, "  echo <text>");
    write_line(out, prefix, "  vfs-mkdir <path>");
    write_line(out, prefix, "  vfs-write <path> <data>");
    write_line(out, prefix, "  vfs-read <path>");
    write_line(out, prefix, "  vfs-ls <path>");
    write_line(out, prefix, "  vfs-delete <path>");
    write_line(out, prefix, "  vfs-rmdir <path>");
    write_line(out, prefix, "  vfs-rename <old> <new>");
    write_line(out, prefix, "  vfs-link <existing> <new>");
    write_line(out, prefix, "  vfs-symlink <target> <link>");
    write_line(out, prefix, "  vfs-readlink <path>");
    write_line(out, prefix, "  vfs-health");
    write_line(out, prefix, "  vfs-fsck");
    write_line(out, prefix, "  vfs-policy [auto|none|<bytes>]");
    write_line(out, prefix, "  vfs-watch <path> [exact|tree]");
    write_line(out, prefix, "  vfs-unwatch <id>");
    write_line(out, prefix, "  vfs-watch-list");
    write_line(out, prefix, "  vfs-notify [count]");
    write_line(out, prefix, "  vfs-ipc-sub <channel-id>");
    write_line(out, prefix, "  vfs-ipc-unsub <channel-id>");
    write_line(out, prefix, "  vfs-ipc-list");
    write_line(out, prefix, "  vfs-cap-dir-show <path>");
    write_line(
        out,
        prefix,
        "  vfs-cap-dir-set <path> <rights> [quota_total quota_files quota_single]",
    );
    write_line(out, prefix, "  vfs-cap-dir-clear <path>");
    write_line(out, prefix, "  vfs-cap-proc-show <pid>");
    write_line(
        out,
        prefix,
        "  vfs-cap-proc-set <pid> <rights> [quota_total quota_files quota_single]",
    );
    write_line(out, prefix, "  vfs-cap-proc-clear <pid>");
    write_line(out, prefix, "  vfs-cap-effective <path> [pid]");
    write_line(out, prefix, "  vfs-mounts");
    write_line(out, prefix, "  vfs-mount-virtio <path>");
    write_line(out, prefix, "  vfs-open <path> [r|w|rw|rwc|append]");
    write_line(out, prefix, "  vfs-readfd <fd> [n]");
    write_line(out, prefix, "  vfs-writefd <fd> <data>");
    write_line(out, prefix, "  vfs-close <fd>");
    write_line(out, prefix, "  blk-info");
    write_line(out, prefix, "  blk-partitions");
    write_line(out, prefix, "  blk-read <lba>");
    write_line(out, prefix, "  blk-write <lba> <byte>");
    #[cfg(target_arch = "aarch64")]
    {
        write_line(out, prefix, "  pid");
        write_line(out, prefix, "  pid-spawn");
        write_line(out, prefix, "  pid-set <pid>");
        write_line(out, prefix, "  pid-drop <pid>");
    }
}

pub fn try_execute<W: Write>(out: &mut W, input: &str, prefix: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return true;
    }
    let mut parts = trimmed.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let rest = trimmed[cmd.len()..].trim_start();

    match cmd {
        "echo" => {
            write_line(out, prefix, rest);
        }
        "help-cmd" | "commands-help" | "shared-help" => {
            print_help(out, prefix);
        }
        #[cfg(target_arch = "aarch64")]
        "pid" => {
            let (proc_count, fd_count, current_pid) =
                crate::vfs_platform::aarch64_process_fd_stats();
            let _ = writeln!(
                out,
                "{} pid current={} processes={} open_fds={}",
                prefix, current_pid, proc_count, fd_count
            );
        }
        #[cfg(target_arch = "aarch64")]
        "pid-spawn" => {
            match crate::vfs_platform::aarch64_spawn_process(crate::vfs_platform::current_pid()) {
                Ok(pid) => {
                    let _ = writeln!(out, "{} pid-spawn ok pid={}", prefix, pid);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} pid-spawn failed: {}", prefix, e);
                }
            }
            let (proc_count, fd_count, current_pid) =
                crate::vfs_platform::aarch64_process_fd_stats();
            let _ = writeln!(
                out,
                "{} pid current={} processes={} open_fds={}",
                prefix, current_pid, proc_count, fd_count
            );
        }
        #[cfg(target_arch = "aarch64")]
        "pid-set" => {
            let Some(pid) = parse_u64_auto(rest.trim()).and_then(|v| u32::try_from(v).ok()) else {
                let _ = writeln!(out, "{} usage: pid-set <pid>", prefix);
                return true;
            };
            match crate::arch::aarch64_virt::scheduler_note_context_switch(pid) {
                Ok(()) => {
                    let _ = writeln!(out, "{} pid-set ok pid={}", prefix, pid);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} pid-set failed: {}", prefix, e);
                }
            }
            let (proc_count, fd_count, current_pid) =
                crate::vfs_platform::aarch64_process_fd_stats();
            let _ = writeln!(
                out,
                "{} pid current={} processes={} open_fds={}",
                prefix, current_pid, proc_count, fd_count
            );
        }
        #[cfg(target_arch = "aarch64")]
        "pid-drop" => {
            let Some(pid) = parse_u64_auto(rest.trim()).and_then(|v| u32::try_from(v).ok()) else {
                let _ = writeln!(out, "{} usage: pid-drop <pid>", prefix);
                return true;
            };
            match crate::vfs_platform::aarch64_destroy_process(pid) {
                Ok(()) => {
                    let _ = writeln!(out, "{} pid-drop ok pid={}", prefix, pid);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} pid-drop failed: {}", prefix, e);
                }
            }
            let (proc_count, fd_count, current_pid) =
                crate::vfs_platform::aarch64_process_fd_stats();
            let _ = writeln!(
                out,
                "{} pid current={} processes={} open_fds={}",
                prefix, current_pid, proc_count, fd_count
            );
        }
        "blk-info" => {
            let present = crate::virtio_blk::is_present();
            let cap = crate::virtio_blk::capacity_sectors().unwrap_or(0);
            let _ = writeln!(
                out,
                "{} blk present={} cap_sectors={:#x} cap_bytes={:#x}",
                prefix,
                if present { 1 } else { 0 },
                cap,
                cap.saturating_mul(512)
            );
        }
        "blk-partitions" => {
            let mut mbr = [None; 4];
            let mut gpt = [None; 4];
            match crate::virtio_blk::read_partitions(&mut mbr, &mut gpt) {
                Ok(()) => {
                    write_line(out, prefix, "MBR:");
                    for (i, p) in mbr.iter().enumerate() {
                        if let Some(part) = p {
                            let _ = writeln!(
                                out,
                                "{}   {}: type=0x{:02x} lba={} sectors={} boot={}",
                                prefix,
                                i + 1,
                                part.part_type,
                                part.lba_start,
                                part.sectors,
                                if part.bootable { 1 } else { 0 }
                            );
                        }
                    }
                    write_line(out, prefix, "GPT:");
                    for (i, p) in gpt.iter().enumerate() {
                        if let Some(part) = p {
                            let _ = write!(
                                out,
                                "{}   {}: lba {}-{} name=",
                                prefix,
                                i + 1,
                                part.first_lba,
                                part.last_lba
                            );
                            for &b in &part.name {
                                if b == 0 {
                                    break;
                                }
                                let ch = if (0x20..=0x7e).contains(&b) {
                                    b as char
                                } else {
                                    '.'
                                };
                                let _ = write!(out, "{}", ch);
                            }
                            let _ = writeln!(out);
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(out, "{} blk-partitions failed: {}", prefix, e);
                }
            }
        }
        "blk-read" => {
            let Some(lba) = parse_u64_auto(rest.trim()) else {
                let _ = writeln!(out, "{} usage: blk-read <lba>", prefix);
                return true;
            };
            let mut sector = [0u8; 512];
            match crate::virtio_blk::read_sector(lba, &mut sector) {
                Ok(()) => {
                    let _ = writeln!(out, "{} blk-read lba={:#x}", prefix, lba);
                    print_hexdump(out, prefix, "blk", &sector[..64]);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} blk-read failed: {}", prefix, e);
                }
            }
        }
        "blk-write" => {
            let mut args = rest.split_whitespace();
            let (Some(lba_s), Some(byte_s)) = (args.next(), args.next()) else {
                let _ = writeln!(out, "{} usage: blk-write <lba> <byte>", prefix);
                return true;
            };
            let (Some(lba), Some(val)) = (parse_u64_auto(lba_s), parse_u64_auto(byte_s)) else {
                let _ = writeln!(out, "{} invalid blk-write args", prefix);
                return true;
            };
            if val > 0xFF {
                let _ = writeln!(out, "{} blk-write byte must be <= 0xff", prefix);
                return true;
            }
            let sector = [val as u8; 512];
            match crate::virtio_blk::write_sector(lba, &sector) {
                Ok(()) => {
                    let _ = writeln!(
                        out,
                        "{} blk-write ok lba={:#x} byte=0x{:02x}",
                        prefix, lba, val
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} blk-write failed: {}", prefix, e);
                }
            }
        }
        "vfs-mkdir" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-mkdir <path>", prefix);
                return true;
            }
            match vfs::mkdir(path) {
                Ok(()) => {
                    let _ = writeln!(out, "{} vfs-mkdir ok {}", prefix, path);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-mkdir failed: {}", prefix, e);
                }
            }
        }
        "vfs-write" => {
            let mut args = rest.splitn(2, char::is_whitespace);
            let (Some(path), Some(data)) = (args.next(), args.next()) else {
                let _ = writeln!(out, "{} usage: vfs-write <path> <data>", prefix);
                return true;
            };
            match vfs::write_path(path, data.as_bytes()) {
                Ok(n) => {
                    let _ = writeln!(out, "{} vfs-write ok path={} bytes={}", prefix, path, n);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-write failed: {}", prefix, e);
                }
            }
        }
        "vfs-read" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-read <path>", prefix);
                return true;
            }
            let mut buf = [0u8; 1024];
            match vfs::read_path(path, &mut buf) {
                Ok(n) => {
                    let text = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
                    let _ = writeln!(out, "{} vfs-read {} bytes={}", prefix, path, n);
                    let _ = writeln!(out, "{}", text);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-read failed: {}", prefix, e);
                }
            }
        }
        "vfs-ls" => {
            let path = if rest.trim().is_empty() {
                "/"
            } else {
                rest.trim()
            };
            let mut buf = [0u8; 1024];
            match vfs::list_dir(path, &mut buf) {
                Ok(n) => {
                    let text = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
                    let _ = writeln!(out, "{} vfs-ls {} => {}", prefix, path, text);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-ls failed: {}", prefix, e);
                }
            }
        }
        "vfs-delete" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-delete <path>", prefix);
                return true;
            }
            match vfs::unlink(path) {
                Ok(()) => {
                    let _ = writeln!(out, "{} vfs-delete ok {}", prefix, path);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-delete failed: {}", prefix, e);
                }
            }
        }
        "vfs-rmdir" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-rmdir <path>", prefix);
                return true;
            }
            match vfs::rmdir(path) {
                Ok(()) => {
                    let _ = writeln!(out, "{} vfs-rmdir ok {}", prefix, path);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-rmdir failed: {}", prefix, e);
                }
            }
        }
        "vfs-rename" => {
            let mut args = rest.split_whitespace();
            let (Some(old_path), Some(new_path)) = (args.next(), args.next()) else {
                let _ = writeln!(out, "{} usage: vfs-rename <old> <new>", prefix);
                return true;
            };
            match vfs::rename(old_path, new_path) {
                Ok(()) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-rename ok old={} new={}",
                        prefix, old_path, new_path
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-rename failed: {}", prefix, e);
                }
            }
        }
        "vfs-link" => {
            let mut args = rest.split_whitespace();
            let (Some(existing), Some(new_path)) = (args.next(), args.next()) else {
                let _ = writeln!(out, "{} usage: vfs-link <existing> <new>", prefix);
                return true;
            };
            match vfs::link(existing, new_path) {
                Ok(()) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-link ok src={} dst={}",
                        prefix, existing, new_path
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-link failed: {}", prefix, e);
                }
            }
        }
        "vfs-symlink" => {
            let mut args = rest.split_whitespace();
            let (Some(target), Some(link_path)) = (args.next(), args.next()) else {
                let _ = writeln!(out, "{} usage: vfs-symlink <target> <link>", prefix);
                return true;
            };
            match vfs::symlink(target, link_path) {
                Ok(()) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-symlink ok target={} link={}",
                        prefix, target, link_path
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-symlink failed: {}", prefix, e);
                }
            }
        }
        "vfs-readlink" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-readlink <path>", prefix);
                return true;
            }
            match vfs::readlink(path) {
                Ok(target) => {
                    let _ = writeln!(out, "{} vfs-readlink {} => {}", prefix, path, target);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-readlink failed: {}", prefix, e);
                }
            }
        }
        "vfs-health" => {
            let health = vfs::health();
            let _ = writeln!(
                out,
                "{} vfs-health inodes={}/{} files={} dirs={} symlinks={} bytes={} handles={} mounts={} orphans={} max_file_size={}",
                prefix,
                health.live_inodes,
                health.total_inode_slots,
                health.file_count,
                health.directory_count,
                health.symlink_count,
                health.total_bytes,
                health.open_handles,
                health.mount_count,
                health.orphaned_inodes,
                health
                    .max_mem_file_size
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unbounded".to_string())
            );
            for mount in health.mount_health {
                let _ = writeln!(
                    out,
                    "{}   mount path={} backend={} reads={} writes={} mutations={} errors={} last_error={}",
                    prefix,
                    mount.path,
                    mount.backend,
                    mount.reads,
                    mount.writes,
                    mount.mutations,
                    mount.errors,
                    mount.last_error.unwrap_or_else(|| "-".to_string())
                );
            }
        }
        "vfs-fsck" => match vfs::fsck_and_repair() {
            Ok(report) => {
                let _ = writeln!(
                    out,
                    "{} vfs-fsck ok scanned={} dangling_removed={} relinked={} nlink_repairs={} size_repairs={} lost+found_created={}",
                    prefix,
                    report.inodes_scanned,
                    report.dangling_entries_removed,
                    report.orphaned_inodes_relinked,
                    report.nlink_repairs,
                    report.size_repairs,
                    if report.lost_found_created { 1 } else { 0 }
                );
            }
            Err(e) => {
                let _ = writeln!(out, "{} vfs-fsck failed: {}", prefix, e);
            }
        },
        "vfs-policy" => {
            let arg = rest.trim();
            if arg.is_empty() {
                let policy = vfs::policy();
                let _ = writeln!(
                    out,
                    "{} vfs-policy max_mem_file_size={}",
                    prefix,
                    policy
                        .max_mem_file_size
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unbounded".to_string())
                );
                return true;
            }
            let policy = match arg {
                "auto" => vfs::VfsPolicy::runtime_default(),
                "none" | "unbounded" => vfs::VfsPolicy::unbounded(),
                _ => {
                    let Some(limit) = parse_usize_auto(arg) else {
                        let _ = writeln!(out, "{} usage: vfs-policy [auto|none|<bytes>]", prefix);
                        return true;
                    };
                    vfs::VfsPolicy::bounded(limit)
                }
            };
            vfs::set_policy(policy);
            let effective = vfs::policy();
            let _ = writeln!(
                out,
                "{} vfs-policy ok max_mem_file_size={}",
                prefix,
                effective
                    .max_mem_file_size
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unbounded".to_string())
            );
        }
        "vfs-watch" => {
            let mut args = rest.split_whitespace();
            let Some(path) = args.next() else {
                let _ = writeln!(out, "{} usage: vfs-watch <path> [exact|tree]", prefix);
                return true;
            };
            let recursive = match args.next().unwrap_or("exact") {
                "exact" => false,
                "tree" | "recursive" => true,
                _ => {
                    let _ = writeln!(out, "{} usage: vfs-watch <path> [exact|tree]", prefix);
                    return true;
                }
            };
            match vfs::watch(path, recursive) {
                Ok(id) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-watch ok id={} path={} scope={}",
                        prefix,
                        id,
                        path,
                        format_watch_scope(recursive)
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-watch failed: {}", prefix, e);
                }
            }
        }
        "vfs-unwatch" => {
            let Some(id) = parse_u64_auto(rest.trim()) else {
                let _ = writeln!(out, "{} usage: vfs-unwatch <id>", prefix);
                return true;
            };
            let removed = vfs::unwatch(id);
            let _ = writeln!(
                out,
                "{} vfs-unwatch {}",
                prefix,
                if removed { "ok" } else { "miss" }
            );
        }
        "vfs-watch-list" => {
            let watches = vfs::watches();
            if watches.is_empty() {
                let _ = writeln!(out, "{} vfs-watch-list <none>", prefix);
                return true;
            }
            let _ = writeln!(out, "{} vfs-watch-list count={}", prefix, watches.len());
            for watch in watches {
                let _ = writeln!(
                    out,
                    "{}   id={} path={} scope={}",
                    prefix,
                    watch.id,
                    watch.path,
                    format_watch_scope(watch.recursive)
                );
            }
        }
        "vfs-notify" => {
            let count = parse_usize_auto(rest.trim().trim())
                .unwrap_or(16)
                .clamp(1, 128);
            let events = vfs::notify(count);
            if events.is_empty() {
                let _ = writeln!(out, "{} vfs-notify <none>", prefix);
                return true;
            }
            let _ = writeln!(out, "{} vfs-notify count={}", prefix, events.len());
            for event in events {
                let _ = writeln!(
                    out,
                    "{}   seq={} watch={} kind={} path={} detail={}",
                    prefix,
                    event.sequence,
                    event.watch_id,
                    format_watch_kind(event.kind),
                    event.path,
                    event.detail.unwrap_or_else(|| "-".to_string())
                );
            }
        }
        "vfs-ipc-sub" => {
            let Some(channel_id) = parse_u32_auto(rest.trim()) else {
                let _ = writeln!(out, "{} usage: vfs-ipc-sub <channel-id>", prefix);
                return true;
            };
            match vfs::subscribe_notify_channel(crate::ipc::ChannelId::new(channel_id)) {
                Ok(()) => {
                    let _ = writeln!(out, "{} vfs-ipc-sub ok channel={}", prefix, channel_id);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-ipc-sub failed: {}", prefix, e);
                }
            }
        }
        "vfs-ipc-unsub" => {
            let Some(channel_id) = parse_u32_auto(rest.trim()) else {
                let _ = writeln!(out, "{} usage: vfs-ipc-unsub <channel-id>", prefix);
                return true;
            };
            let removed = vfs::unsubscribe_notify_channel(crate::ipc::ChannelId::new(channel_id));
            let _ = writeln!(
                out,
                "{} vfs-ipc-unsub {} channel={}",
                prefix,
                if removed { "ok" } else { "miss" },
                channel_id
            );
        }
        "vfs-ipc-list" => {
            let channels = vfs::notify_channels();
            if channels.is_empty() {
                let _ = writeln!(out, "{} vfs-ipc-list <none>", prefix);
                return true;
            }
            let _ = writeln!(out, "{} vfs-ipc-list count={}", prefix, channels.len());
            for channel in channels {
                let _ = writeln!(out, "{}   channel={}", prefix, channel.0);
            }
        }
        "vfs-cap-dir-show" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-cap-dir-show <path>", prefix);
                return true;
            }
            match vfs::directory_capability(path) {
                Ok(Some(capability)) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-cap-dir-show {} => {}",
                        prefix,
                        path,
                        format_capability(&capability)
                    );
                }
                Ok(None) => {
                    let _ = writeln!(out, "{} vfs-cap-dir-show {} => <none>", prefix, path);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-cap-dir-show failed: {}", prefix, e);
                }
            }
        }
        "vfs-cap-dir-set" => {
            let args: Vec<&str> = rest.split_whitespace().collect();
            if args.len() != 2 && args.len() != 5 {
                let _ = writeln!(
                    out,
                    "{} usage: vfs-cap-dir-set <path> <rights> [quota_total quota_files quota_single]",
                    prefix
                );
                return true;
            }
            let Some(capability) = build_capability(args[0], args[1], &args[2..], 0x5646_4400)
            else {
                let _ = writeln!(
                    out,
                    "{} vfs-cap-dir-set failed: invalid capability spec",
                    prefix
                );
                return true;
            };
            match vfs::set_directory_capability(args[0], capability.clone()) {
                Ok(()) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-cap-dir-set ok {} => {}",
                        prefix,
                        args[0],
                        format_capability(&capability)
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-cap-dir-set failed: {}", prefix, e);
                }
            }
        }
        "vfs-cap-dir-clear" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-cap-dir-clear <path>", prefix);
                return true;
            }
            match vfs::clear_directory_capability(path) {
                Ok(()) => {
                    let _ = writeln!(out, "{} vfs-cap-dir-clear ok {}", prefix, path);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-cap-dir-clear failed: {}", prefix, e);
                }
            }
        }
        "vfs-cap-proc-show" => {
            let Some(raw_pid) = parse_u64_auto(rest.trim()).and_then(|v| u32::try_from(v).ok())
            else {
                let _ = writeln!(out, "{} usage: vfs-cap-proc-show <pid>", prefix);
                return true;
            };
            let pid = vfs_platform::pid_from_raw(raw_pid);
            match vfs::process_capability(pid) {
                Some(capability) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-cap-proc-show {} => {}",
                        prefix,
                        raw_pid,
                        format_capability(&capability)
                    );
                }
                None => {
                    let _ = writeln!(out, "{} vfs-cap-proc-show {} => <none>", prefix, raw_pid);
                }
            }
        }
        "vfs-cap-proc-set" => {
            let args: Vec<&str> = rest.split_whitespace().collect();
            if args.len() != 2 && args.len() != 5 {
                let _ = writeln!(
                    out,
                    "{} usage: vfs-cap-proc-set <pid> <rights> [quota_total quota_files quota_single]",
                    prefix
                );
                return true;
            }
            let Some(raw_pid) = parse_u64_auto(args[0]).and_then(|v| u32::try_from(v).ok()) else {
                let _ = writeln!(out, "{} vfs-cap-proc-set failed: invalid pid", prefix);
                return true;
            };
            let Some(capability) = build_capability(args[0], args[1], &args[2..], 0x5646_5000)
            else {
                let _ = writeln!(
                    out,
                    "{} vfs-cap-proc-set failed: invalid capability spec",
                    prefix
                );
                return true;
            };
            let pid = vfs_platform::pid_from_raw(raw_pid);
            vfs::set_process_capability(pid, capability.clone());
            let _ = writeln!(
                out,
                "{} vfs-cap-proc-set ok {} => {}",
                prefix,
                raw_pid,
                format_capability(&capability)
            );
        }
        "vfs-cap-proc-clear" => {
            let Some(raw_pid) = parse_u64_auto(rest.trim()).and_then(|v| u32::try_from(v).ok())
            else {
                let _ = writeln!(out, "{} usage: vfs-cap-proc-clear <pid>", prefix);
                return true;
            };
            vfs::clear_process_capability(vfs_platform::pid_from_raw(raw_pid));
            let _ = writeln!(out, "{} vfs-cap-proc-clear ok {}", prefix, raw_pid);
        }
        "vfs-cap-effective" => {
            let mut args = rest.split_whitespace();
            let Some(path) = args.next() else {
                let _ = writeln!(out, "{} usage: vfs-cap-effective <path> [pid]", prefix);
                return true;
            };
            let pid = match args.next() {
                Some(raw) => {
                    let Some(raw_pid) = parse_u64_auto(raw).and_then(|v| u32::try_from(v).ok())
                    else {
                        let _ = writeln!(out, "{} vfs-cap-effective failed: invalid pid", prefix);
                        return true;
                    };
                    Some(vfs_platform::pid_from_raw(raw_pid))
                }
                None => vfs_platform::current_pid(),
            };
            match vfs::effective_capability_for_pid(pid, path) {
                Ok(capability) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-cap-effective {} => {}",
                        prefix,
                        path,
                        format_capability(&capability)
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-cap-effective failed: {}", prefix, e);
                }
            }
        }
        "vfs-mounts" => {
            let mounts = vfs::mounts();
            if mounts.is_empty() {
                let _ = writeln!(out, "{} vfs-mounts <none>", prefix);
                return true;
            }
            let _ = writeln!(out, "{} vfs-mounts count={}", prefix, mounts.len());
            for mount in mounts {
                let special = if mount.contract.special_entries.is_empty() {
                    "-".to_string()
                } else {
                    mount.contract.special_entries.join(",")
                };
                let _ = writeln!(
                    out,
                    "{}   path={} backend={} mutable={} dirs={} links={} symlinks={} specials={} reads={} writes={} mutations={} errors={} last_error={}",
                    prefix,
                    mount.contract.path,
                    mount.contract.backend,
                    if mount.contract.mutable { 1 } else { 0 },
                    if mount.contract.supports_directories { 1 } else { 0 },
                    if mount.contract.supports_links { 1 } else { 0 },
                    if mount.contract.supports_symlinks { 1 } else { 0 },
                    special,
                    mount.health.reads,
                    mount.health.writes,
                    mount.health.mutations,
                    mount.health.errors,
                    mount.health.last_error.unwrap_or_else(|| "-".to_string())
                );
            }
        }
        "vfs-mount-virtio" => {
            let path = rest.trim();
            if path.is_empty() {
                let _ = writeln!(out, "{} usage: vfs-mount-virtio <path>", prefix);
                return true;
            }
            match vfs::mount_virtio(path) {
                Ok(()) => {
                    let _ = writeln!(out, "{} vfs-mount-virtio ok {}", prefix, path);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-mount-virtio failed: {}", prefix, e);
                }
            }
        }
        "vfs-open" => {
            let mut args = rest.split_whitespace();
            let Some(path) = args.next() else {
                let _ = writeln!(out, "{} usage: vfs-open <path> [mode]", prefix);
                return true;
            };
            let flags = parse_open_flags(args.next().unwrap_or("r"));
            match vfs::open_for_current(path, flags) {
                Ok(fd) => {
                    let _ = writeln!(out, "{} vfs-open ok fd={}", prefix, fd);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-open failed: {}", prefix, e);
                }
            }
        }
        "vfs-readfd" => {
            let mut args = rest.split_whitespace();
            let (Some(fd_s), n_s) = (args.next(), args.next()) else {
                let _ = writeln!(out, "{} usage: vfs-readfd <fd> [n]", prefix);
                return true;
            };
            let Some(fd) = parse_usize_auto(fd_s) else {
                let _ = writeln!(out, "{} usage: vfs-readfd <fd> [n]", prefix);
                return true;
            };
            let n = n_s.and_then(parse_usize_auto).unwrap_or(256).clamp(1, 1024);
            let Some(pid) = crate::vfs_platform::current_pid() else {
                let _ = writeln!(out, "{} vfs-readfd failed: no current process", prefix);
                return true;
            };
            let mut buf = [0u8; 1024];
            match vfs::read_fd(pid, fd, &mut buf[..n]) {
                Ok(read) => {
                    let text = core::str::from_utf8(&buf[..read]).unwrap_or("<non-utf8>");
                    let _ = writeln!(out, "{} vfs-readfd fd={} bytes={}", prefix, fd, read);
                    let _ = writeln!(out, "{}", text);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-readfd failed: {}", prefix, e);
                }
            }
        }
        "vfs-writefd" => {
            let mut args = rest.splitn(2, char::is_whitespace);
            let (Some(fd_s), Some(data)) = (args.next(), args.next()) else {
                let _ = writeln!(out, "{} usage: vfs-writefd <fd> <data>", prefix);
                return true;
            };
            let Some(fd) = parse_usize_auto(fd_s) else {
                let _ = writeln!(out, "{} vfs-writefd: invalid fd", prefix);
                return true;
            };
            let Some(pid) = crate::vfs_platform::current_pid() else {
                let _ = writeln!(out, "{} vfs-writefd failed: no current process", prefix);
                return true;
            };
            match vfs::write_fd(pid, fd, data.as_bytes()) {
                Ok(n) => {
                    let _ = writeln!(out, "{} vfs-writefd ok fd={} bytes={}", prefix, fd, n);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-writefd failed: {}", prefix, e);
                }
            }
        }
        "vfs-close" => {
            let Some(fd) = parse_usize_auto(rest.trim()) else {
                let _ = writeln!(out, "{} usage: vfs-close <fd>", prefix);
                return true;
            };
            let Some(pid) = crate::vfs_platform::current_pid() else {
                let _ = writeln!(out, "{} vfs-close failed: no current process", prefix);
                return true;
            };
            match vfs::close_fd(pid, fd) {
                Ok(()) => {
                    let _ = writeln!(out, "{} vfs-close ok fd={}", prefix, fd);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-close failed: {}", prefix, e);
                }
            }
        }
        _ => return false,
    }

    true
}

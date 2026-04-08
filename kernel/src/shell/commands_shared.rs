/*!
 * Shared cross-architecture command handlers used by both the full x86 shell
 * and the AArch64 runtime shell adapter.
 */

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;

use crate::fs::{FilesystemCapability, FilesystemQuota, FilesystemRights};
use crate::fs::vfs;
use crate::fs::vfs_platform;

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

#[cfg(target_arch = "aarch64")]
fn aarch64_process_fd_stats() -> (usize, usize, u32) {
    let (proc_count, fd_count, current_pid) = crate::scheduler::process::runtime_fd_stats();
    (
        proc_count,
        fd_count,
        current_pid.map(|pid| pid.0).unwrap_or(1),
    )
}

#[cfg(target_arch = "aarch64")]
fn aarch64_spawn_process(parent_pid: Option<u32>) -> Result<u32, &'static str> {
    let parent = parent_pid.map(crate::scheduler::process::Pid::new);
    let spawned = crate::scheduler::process::process_manager()
        .spawn("a64-task", parent)
        .map_err(|e| e.as_str())?;
    if let Some(parent_pid) = parent {
        let _ = crate::fs::vfs::inherit_process_capability(parent_pid, spawned, None);
    }
    Ok(spawned.0)
}

#[cfg(target_arch = "aarch64")]
fn aarch64_destroy_process(pid: u32) -> Result<(), &'static str> {
    let pid = crate::scheduler::process::Pid::new(pid);
    crate::scheduler::process::process_manager()
        .terminate(pid)
        .map_err(|e| e.as_str())?;
    crate::fs::vfs::clear_process_capability(pid);
    if crate::scheduler::process::current_pid() == Some(pid) {
        let _ = crate::scheduler::process::set_current_runtime_pid(crate::scheduler::process::Pid::new(0));
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn aarch64_print_syscall_stats<W: Write>(out: &mut W, prefix: &str) {
    let stats = crate::platform::syscall::get_stats();
    let _ = writeln!(
        out,
        "{} syscall total={} denied={} errors={}",
        prefix, stats.total_calls, stats.denied, stats.errors
    );
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
    write_line(out, prefix, "  vfs-ipc-stats <channel-id>");
    write_line(out, prefix, "  vfs-ipc-ack <channel-id> <sequence>");
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
    write_line(
        out,
        prefix,
        "  blk-bench [sectors] [start_lba]  -- timed sequential read",
    );
    crate::shell::network_commands_shared::print_help(out, prefix);
    #[cfg(target_arch = "aarch64")]
    {
        write_line(out, prefix, "  pid");
        write_line(out, prefix, "  pid-spawn");
        write_line(out, prefix, "  pid-set <pid>");
        write_line(out, prefix, "  pid-drop <pid>");
        write_line(out, prefix, "  syscall-test");
        write_line(out, prefix, "  user-test");
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
        "netstack-info" => {
            crate::shell::network_commands_shared::cmd_netstack_info(out);
        }
        "eth-status" => {
            crate::shell::network_commands_shared::cmd_eth_status(out);
        }
        "dns-resolve" => {
            crate::shell::network_commands_shared::cmd_dns_resolve(out, parts.next());
        }
        "http-get" => {
            crate::shell::network_commands_shared::cmd_http_get(out, parts.next());
        }
        "net-static" => {
            cmd_net_static(out, prefix, parts);
        }
        #[cfg(target_arch = "aarch64")]
        "pid" => {
            let (proc_count, fd_count, current_pid) = aarch64_process_fd_stats();
            let _ = writeln!(
                out,
                "{} pid current={} processes={} open_fds={}",
                prefix, current_pid, proc_count, fd_count
            );
        }
        #[cfg(target_arch = "aarch64")]
        "pid-spawn" => {
            match aarch64_spawn_process(crate::scheduler::process::current_pid().map(|pid| pid.0)) {
                Ok(pid) => {
                    let _ = writeln!(out, "{} pid-spawn ok pid={}", prefix, pid);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} pid-spawn failed: {}", prefix, e);
                }
            }
            let (proc_count, fd_count, current_pid) = aarch64_process_fd_stats();
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
            match crate::arch::aarch64::aarch64_virt::scheduler_note_context_switch(pid) {
                Ok(()) => {
                    let _ = writeln!(out, "{} pid-set ok pid={}", prefix, pid);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} pid-set failed: {}", prefix, e);
                }
            }
            let (proc_count, fd_count, current_pid) = aarch64_process_fd_stats();
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
            match aarch64_destroy_process(pid) {
                Ok(()) => {
                    let _ = writeln!(out, "{} pid-drop ok pid={}", prefix, pid);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} pid-drop failed: {}", prefix, e);
                }
            }
            let (proc_count, fd_count, current_pid) = aarch64_process_fd_stats();
            let _ = writeln!(
                out,
                "{} pid current={} processes={} open_fds={}",
                prefix, current_pid, proc_count, fd_count
            );
        }
        #[cfg(target_arch = "aarch64")]
        "syscall-test" => {
            aarch64_print_syscall_stats(out, prefix);
            match crate::platform::syscall::aarch64_smoke_test_current_process() {
                Ok(pid) => {
                    let _ = writeln!(out, "{} syscall smoke getpid ok pid={}", prefix, pid);
                }
                Err(e) => {
                    let _ = writeln!(out, "{} syscall smoke failed: {}", prefix, e);
                }
            }
            aarch64_print_syscall_stats(out, prefix);
        }
        #[cfg(target_arch = "aarch64")]
        "user-test" => match crate::platform::usermode::enter_user_mode_test() {
            Ok(()) => {
                let _ = writeln!(out, "{} user-test ok", prefix);
            }
            Err(e) => {
                let _ = writeln!(out, "{} user-test failed: {}", prefix, e);
            }
        },
        "blk-info" => {
            let present = crate::fs::virtio_blk::is_present();
            let cap = crate::fs::virtio_blk::capacity_sectors().unwrap_or(0);
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
            match crate::fs::virtio_blk::read_partitions(&mut mbr, &mut gpt) {
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
            match crate::fs::virtio_blk::read_sector(lba, &mut sector) {
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
            match crate::fs::virtio_blk::write_sector(lba, &sector) {
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
        "blk-bench" => {
            // Timed sequential read throughput benchmark.
            // Usage: blk-bench [sectors] [start_lba]
            // Reads `sectors` consecutive sectors starting at `start_lba` and
            // reports elapsed ticks and a throughput estimate.
            let mut args = rest.split_whitespace();
            let sectors: u64 = args.next().and_then(|s| parse_u64_auto(s)).unwrap_or(64);
            let start_lba: u64 = args.next().and_then(|s| parse_u64_auto(s)).unwrap_or(0);

            if !crate::fs::virtio_blk::is_present() {
                let _ = writeln!(out, "{} blk-bench: no block device present", prefix);
                return true;
            }

            let tick_start = crate::fs::vfs_platform::ticks_now();
            let mut errors: u64 = 0;
            let mut sector = [0u8; 512];
            for i in 0..sectors {
                if crate::fs::virtio_blk::read_sector(start_lba + i, &mut sector).is_err() {
                    errors += 1;
                }
            }
            let tick_end = crate::fs::vfs_platform::ticks_now();
            let elapsed = tick_end.saturating_sub(tick_start);
            // PIT tick ≈ 1 ms on x86; on AArch64 timer_ticks() returns the
            // CNTVCT_EL0 counter at 62.5 MHz (QEMU virt default).
            let bytes = sectors.saturating_mul(512);
            let _ = writeln!(
                out,
                "{} blk-bench sectors={} start_lba={:#x} errors={} ticks={} bytes={}",
                prefix, sectors, start_lba, errors, elapsed, bytes
            );
            // Report as bytes/tick (caller can convert to MB/s if they know tick rate)
            if elapsed > 0 {
                let bpt = bytes / elapsed;
                let _ = writeln!(out, "{} blk-bench throughput bytes/tick={}", prefix, bpt);
            } else {
                let _ = writeln!(out, "{} blk-bench throughput <1 tick", prefix);
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
            let subscribers = vfs::notify_subscribers();
            if subscribers.is_empty() {
                let _ = writeln!(out, "{} vfs-ipc-list <none>", prefix);
                return true;
            }
            let _ = writeln!(out, "{} vfs-ipc-list count={}", prefix, subscribers.len());
            for subscriber in subscribers {
                let _ = writeln!(
                    out,
                    "{}   channel={} pending={} inflight={} acked={} dropped={}",
                    prefix,
                    subscriber.channel_id,
                    subscriber.pending_events,
                    subscriber
                        .in_flight
                        .map(|seq| seq.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    subscriber.last_acked_sequence,
                    subscriber.dropped_count,
                );
            }
        }
        "vfs-ipc-stats" => {
            let Some(channel_id) = parse_u32_auto(rest.trim()) else {
                let _ = writeln!(out, "{} usage: vfs-ipc-stats <channel-id>", prefix);
                return true;
            };
            match vfs::notify_channel_stats(crate::ipc::ChannelId::new(channel_id)) {
                Ok(subscriber) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-ipc-stats channel={} pending={} inflight={} acked={} dropped={}",
                        prefix,
                        subscriber.channel_id,
                        subscriber.pending_events,
                        subscriber
                            .in_flight
                            .map(|seq| seq.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        subscriber.last_acked_sequence,
                        subscriber.dropped_count,
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-ipc-stats failed: {}", prefix, e);
                }
            }
        }
        "vfs-ipc-ack" => {
            let args: Vec<&str> = rest.split_whitespace().collect();
            if args.len() != 2 {
                let _ = writeln!(out, "{} usage: vfs-ipc-ack <channel-id> <sequence>", prefix);
                return true;
            }
            let Some(channel_id) = parse_u32_auto(args[0]) else {
                let _ = writeln!(out, "{} vfs-ipc-ack failed: invalid channel", prefix);
                return true;
            };
            let Some(sequence) = parse_u64_auto(args[1]) else {
                let _ = writeln!(out, "{} vfs-ipc-ack failed: invalid sequence", prefix);
                return true;
            };
            match vfs::ack_notify_channel(crate::ipc::ChannelId::new(channel_id), sequence) {
                Ok(()) => {
                    let _ = writeln!(
                        out,
                        "{} vfs-ipc-ack ok channel={} sequence={}",
                        prefix, channel_id, sequence
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "{} vfs-ipc-ack failed: {}", prefix, e);
                }
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
            let Some(pid) = crate::fs::vfs_platform::current_pid() else {
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
            let Some(pid) = crate::fs::vfs_platform::current_pid() else {
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
            let Some(pid) = crate::fs::vfs_platform::current_pid() else {
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
        "capnet-local" => {
            cmd_capnet_local(out, prefix);
        }
        "capnet-peer-add" => {
            cmd_capnet_peer_add(out, prefix, parts);
        }
        "capnet-peer-show" => {
            cmd_capnet_peer_show(out, prefix, parts);
        }
        "capnet-peer-list" => {
            cmd_capnet_peer_list(out, prefix);
        }
        "capnet-lease-list" => {
            cmd_capnet_lease_list(out, prefix);
        }
        "capnet-fuzz" => {
            cmd_capnet_fuzz(out, prefix, parts);
        }
        "capnet-fuzz-fixed" | "cfd" => {
            cmd_capnet_fuzz_fixed(out, prefix, parts);
        }
        "capnet-fuzz-corpus" | "cfc" => {
            cmd_capnet_fuzz_corpus(out, prefix, parts);
        }
        "capnet-fuzz-soak" | "cfs" => {
            cmd_capnet_fuzz_soak(out, prefix, parts);
        }
        "capnet-stats" => {
            cmd_capnet_stats(out, prefix);
        }
        "capnet-hello" => {
            cmd_capnet_hello(out, prefix, parts);
        }
        "capnet-heartbeat" => {
            cmd_capnet_heartbeat(out, prefix, parts);
        }
        "capnet-lend" => {
            cmd_capnet_lend(out, prefix, parts);
        }
        "capnet-accept" => {
            cmd_capnet_accept(out, prefix, parts);
        }
        "capnet-revoke" => {
            cmd_capnet_revoke(out, prefix, parts);
        }
        "capnet-demo" => {
            cmd_capnet_demo(out, prefix);
        }
        "capnet-session-key" => {
            cmd_capnet_session_key(out, prefix, parts);
        }
        _ => return false,
    }

    true
}

// =============================================================================
// CapNet shared command implementations
// =============================================================================

fn cmd_net_static<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let ip = match parts.next().and_then(parse_ipv4_netstack) {
        Some(v) => v,
        None => {
            let _ = writeln!(out, "{} usage: net-static <ip> <gateway>", prefix);
            return;
        }
    };
    let gw = match parts.next().and_then(parse_ipv4_netstack) {
        Some(v) => v,
        None => {
            let _ = writeln!(out, "{} usage: net-static <ip> <gateway>", prefix);
            return;
        }
    };
    match crate::net::net_reactor::configure_static(ip, gw) {
        Ok(()) => {
            let o = ip.octets();
            let g = gw.octets();
            let _ = writeln!(
                out,
                "{} net-static ip={}.{}.{}.{} gw={}.{}.{}.{} ok",
                prefix, o[0], o[1], o[2], o[3], g[0], g[1], g[2], g[3]
            );
        }
        Err(e) => {
            let _ = writeln!(out, "{} net-static failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_session_key<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let peer_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => {
            let _ = writeln!(
                out,
                "{} usage: capnet-session-key <peer_id> <epoch> <k0_hex> <k1_hex>",
                prefix
            );
            return;
        }
    };
    let epoch = match parts.next().and_then(parse_u32_auto) {
        Some(v) if v != 0 => v,
        _ => {
            let _ = writeln!(
                out,
                "{} usage: capnet-session-key <peer_id> <epoch> <k0_hex> <k1_hex>",
                prefix
            );
            return;
        }
    };
    let k0 = match parts.next().and_then(parse_u64_auto) {
        Some(v) => v,
        None => {
            let _ = writeln!(
                out,
                "{} usage: capnet-session-key <peer_id> <epoch> <k0_hex> <k1_hex>",
                prefix
            );
            return;
        }
    };
    let k1 = match parts.next().and_then(parse_u64_auto) {
        Some(v) => v,
        None => {
            let _ = writeln!(
                out,
                "{} usage: capnet-session-key <peer_id> <epoch> <k0_hex> <k1_hex>",
                prefix
            );
            return;
        }
    };
    match crate::net::capnet::install_peer_session_key(peer_id, epoch, k0, k1, 0) {
        Ok(()) => {
            let _ = writeln!(
                out,
                "{} capnet session-key installed peer=0x{:016x} epoch={}",
                prefix, peer_id, epoch
            );
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet session-key failed: {}", prefix, e.as_str());
        }
    }
}

fn parse_capnet_policy(s: &str) -> Option<crate::net::capnet::PeerTrustPolicy> {
    if s.eq_ignore_ascii_case("disabled") {
        return Some(crate::net::capnet::PeerTrustPolicy::Disabled);
    }
    if s.eq_ignore_ascii_case("audit") {
        return Some(crate::net::capnet::PeerTrustPolicy::Audit);
    }
    if s.eq_ignore_ascii_case("enforce") {
        return Some(crate::net::capnet::PeerTrustPolicy::Enforce);
    }
    None
}

fn parse_capnet_cap_type(s: &str) -> Option<u8> {
    if s.eq_ignore_ascii_case("channel") {
        return Some(crate::capability::CapabilityType::Channel as u8);
    }
    if s.eq_ignore_ascii_case("task") {
        return Some(crate::capability::CapabilityType::Task as u8);
    }
    if s.eq_ignore_ascii_case("spawner") {
        return Some(crate::capability::CapabilityType::Spawner as u8);
    }
    if s.eq_ignore_ascii_case("console") {
        return Some(crate::capability::CapabilityType::Console as u8);
    }
    if s.eq_ignore_ascii_case("clock") {
        return Some(crate::capability::CapabilityType::Clock as u8);
    }
    if s.eq_ignore_ascii_case("store") {
        return Some(crate::capability::CapabilityType::Store as u8);
    }
    if s.eq_ignore_ascii_case("filesystem") || s.eq_ignore_ascii_case("fs") {
        return Some(crate::capability::CapabilityType::Filesystem as u8);
    }
    if s.eq_ignore_ascii_case("service-pointer")
        || s.eq_ignore_ascii_case("servicepointer")
        || s.eq_ignore_ascii_case("svcptr")
    {
        return Some(crate::capability::CapabilityType::ServicePointer as u8);
    }
    let numeric = parse_u32_auto(s)?;
    if numeric <= u8::MAX as u32 {
        Some(numeric as u8)
    } else {
        None
    }
}

fn parse_ipv4_netstack(s: &str) -> Option<crate::net::netstack::Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for part in s.split('.') {
        if count >= 4 {
            return None;
        }
        let val = parse_u32_auto(part)?;
        if val > 255 {
            return None;
        }
        octets[count] = val as u8;
        count += 1;
    }
    if count != 4 {
        return None;
    }
    Some(crate::net::netstack::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}

fn print_capnet_fuzz_failure<W: Write>(out: &mut W, failure: crate::net::capnet::CapNetFuzzFailure) {
    let _ = write!(out, "Iter: {}  Stage: {}\nReason: {}\nSample bytes:\n",
        failure.iteration, failure.stage, failure.reason);
    let mut i = 0usize;
    while i < failure.sample_len as usize {
        let _ = write!(out, "{:02x} ", failure.sample[i]);
        if (i + 1) % 16 == 0 {
            let _ = write!(out, "\n");
        }
        i += 1;
    }
    if (failure.sample_len as usize) % 16 != 0 {
        let _ = write!(out, "\n");
    }
}

fn run_capnet_with_irqs_masked<T>(f: impl FnOnce() -> T) -> T {
    let irq_flags = unsafe { crate::scheduler::scheduler_platform::irq_save_disable() };
    let out = f();
    unsafe { crate::scheduler::scheduler_platform::irq_restore(irq_flags) };
    out
}

const CAPNET_SHARED_FIXED_REGRESSION_SEED: u64 = 3_870_443_198;

fn run_capnet_fuzz_with_seed<W: Write>(out: &mut W, prefix: &str, iters: u32, seed: u64) {
    const MAX_FUZZ_ITERS: u32 = 10_000;
    if iters == 0 || iters > MAX_FUZZ_ITERS {
        let _ = writeln!(out, "{} iterations must be 1..=10000", prefix);
        return;
    }
    let _ = writeln!(out, "{} ===== CapNet Fuzz =====", prefix);
    let _ = writeln!(out, "{} iterations={} seed={}", prefix, iters, seed);
    match run_capnet_with_irqs_masked(|| crate::net::capnet::capnet_fuzz(iters, seed)) {
        Ok(stats) => {
            let _ = writeln!(out,
                "{} valid_ok={} replay_rej={} constraint_rej={} tok_ok/err={}/{} ctrl_ok/err={}/{} proc_ok/err={}/{} failures={}",
                prefix, stats.valid_path_ok, stats.replay_rejects, stats.constraint_rejects,
                stats.token_decode_ok, stats.token_decode_err,
                stats.control_decode_ok, stats.control_decode_err,
                stats.process_ok, stats.process_err, stats.failures);
            if let Some(failure) = stats.first_failure {
                let _ = writeln!(out, "{} first failure:", prefix);
                print_capnet_fuzz_failure(out, failure);
            }
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet-fuzz failed: {}", prefix, e);
        }
    }
}

fn trust_policy_str(trust: crate::net::capnet::PeerTrustPolicy) -> &'static str {
    match trust {
        crate::net::capnet::PeerTrustPolicy::Disabled => "disabled",
        crate::net::capnet::PeerTrustPolicy::Audit => "audit",
        crate::net::capnet::PeerTrustPolicy::Enforce => "enforce",
    }
}

fn cmd_capnet_local<W: Write>(out: &mut W, prefix: &str) {
    let _ = writeln!(out, "{} ===== CapNet Local Identity =====", prefix);
    match crate::net::capnet::local_device_id() {
        Some(id) => {
            let _ = writeln!(out, "{} Device ID: 0x{:016x}", prefix, id);
        }
        None => {
            let _ = writeln!(out, "{} Local CapNet identity not initialized", prefix);
        }
    }
}

fn cmd_capnet_peer_add<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let peer_str = match parts.next() {
        Some(v) => v,
        None => {
            let _ = writeln!(out, "{} usage: capnet-peer-add <peer_id> <disabled|audit|enforce> [measurement]", prefix);
            return;
        }
    };
    let policy_str = match parts.next() {
        Some(v) => v,
        None => {
            let _ = writeln!(out, "{} usage: capnet-peer-add <peer_id> <disabled|audit|enforce> [measurement]", prefix);
            return;
        }
    };
    let peer_id = match parse_u64_auto(peer_str) {
        Some(v) if v != 0 => v,
        _ => {
            let _ = writeln!(out, "{} invalid peer_id (non-zero u64, decimal or 0xhex)", prefix);
            return;
        }
    };
    let policy = match parse_capnet_policy(policy_str) {
        Some(p) => p,
        None => {
            let _ = writeln!(out, "{} invalid policy: use disabled, audit, or enforce", prefix);
            return;
        }
    };
    let measurement = parts.next().and_then(parse_u64_auto).unwrap_or(0);
    match crate::net::capnet::register_peer(peer_id, policy, measurement) {
        Ok(()) => {
            let _ = writeln!(out, "{} capnet peer registered: peer=0x{:016x} policy={} measurement=0x{:016x}",
                prefix, peer_id, trust_policy_str(policy), measurement);
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet peer add failed: {}", prefix, e.as_str());
        }
    }
}

fn cmd_capnet_peer_show<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let peer_str = match parts.next() {
        Some(v) => v,
        None => {
            let _ = writeln!(out, "{} usage: capnet-peer-show <peer_id>", prefix);
            return;
        }
    };
    let peer_id = match parse_u64_auto(peer_str) {
        Some(v) if v != 0 => v,
        _ => {
            let _ = writeln!(out, "{} invalid peer_id (non-zero u64)", prefix);
            return;
        }
    };
    match crate::net::capnet::peer_snapshot(peer_id) {
        Some(s) => {
            let _ = writeln!(out, "{} ===== CapNet Peer =====", prefix);
            let _ = writeln!(out, "{} Peer:              0x{:016x}", prefix, s.peer_device_id);
            let _ = writeln!(out, "{} Policy:            {}", prefix, trust_policy_str(s.trust));
            let _ = writeln!(out, "{} Measurement:       0x{:016x}", prefix, s.measurement_hash);
            let _ = writeln!(out, "{} Key epoch:         {}", prefix, s.key_epoch);
            let _ = writeln!(out, "{} Replay high nonce: {}", prefix, s.replay_high_nonce);
            let _ = writeln!(out, "{} Last seen epoch:   {}", prefix, s.last_seen_epoch);
        }
        None => {
            let _ = writeln!(out, "{} capnet peer not found", prefix);
        }
    }
}

fn cmd_capnet_peer_list<W: Write>(out: &mut W, prefix: &str) {
    let peers = crate::net::capnet::peer_snapshots();
    let mut active = 0usize;
    let _ = writeln!(out, "{} ===== CapNet Peer Table =====", prefix);
    for i in 0..peers.len() {
        if let Some(p) = peers[i] {
            let _ = writeln!(out, "{} [{}] peer=0x{:016x} policy={} key_epoch={}",
                prefix, active, p.peer_device_id, trust_policy_str(p.trust), p.key_epoch);
            active += 1;
        }
    }
    if active == 0 {
        let _ = writeln!(out, "{} (no active peers)", prefix);
    } else {
        let _ = writeln!(out, "{} total active: {}", prefix, active);
    }
}

fn cmd_capnet_lease_list<W: Write>(out: &mut W, prefix: &str) {
    let leases = crate::capability::capability_manager().remote_lease_snapshots();
    let mut active = 0usize;
    let _ = writeln!(out, "{} ===== CapNet Remote Leases =====", prefix);
    for i in 0..leases.len() {
        if let Some(l) = leases[i] {
            if !l.active || l.revoked {
                continue;
            }
            if l.owner_any {
                let _ = writeln!(out,
                    "{} [{}] token=0x{:016x} cap={} owner=* type={} obj=0x{:016x} exp={}",
                    prefix, active, l.token_id, l.mapped_cap_id, l.cap_type as u32, l.object_id, l.expires_at);
            } else {
                let _ = writeln!(out,
                    "{} [{}] token=0x{:016x} cap={} owner={} type={} obj=0x{:016x} exp={}",
                    prefix, active, l.token_id, l.mapped_cap_id, l.owner_pid.0, l.cap_type as u32, l.object_id, l.expires_at);
            }
            active += 1;
        }
    }
    if active == 0 {
        let _ = writeln!(out, "{} (no active leases)", prefix);
    } else {
        let _ = writeln!(out, "{} total active: {}", prefix, active);
    }
}

fn cmd_capnet_fuzz<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let iters = match parts.next().and_then(parse_usize_auto) {
        Some(v) => v as u32,
        None => {
            let _ = writeln!(out, "{} usage: capnet-fuzz <iters> [seed]", prefix);
            return;
        }
    };
    let seed = parts
        .next()
        .and_then(parse_u64_auto)
        .unwrap_or_else(|| crate::security::security().random_u32() as u64);
    run_capnet_fuzz_with_seed(out, prefix, iters, seed);
}

fn cmd_capnet_fuzz_fixed<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let iters = match parts.next().and_then(parse_usize_auto) {
        Some(v) => v as u32,
        None => {
            let _ = writeln!(out, "{} usage: capnet-fuzz-fixed <iters>", prefix);
            return;
        }
    };
    run_capnet_fuzz_with_seed(out, prefix, iters, CAPNET_SHARED_FIXED_REGRESSION_SEED);
}

fn cmd_capnet_fuzz_corpus<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let iters = parts
        .next()
        .and_then(parse_usize_auto)
        .map(|v| v as u32)
        .unwrap_or(1000);
    const MAX_FUZZ_ITERS: u32 = 10_000;
    if iters == 0 || iters > MAX_FUZZ_ITERS {
        let _ = writeln!(out, "{} usage: capnet-fuzz-corpus [iters]  (1..=10000)", prefix);
        return;
    }
    let _ = writeln!(out, "{} ===== CapNet Regression Corpus =====", prefix);
    let _ = writeln!(out, "{} seeds={} iters_per_seed={}",
        prefix, crate::net::capnet::CAPNET_FUZZ_REGRESSION_SEEDS.len(), iters);
    match run_capnet_with_irqs_masked(|| crate::net::capnet::capnet_fuzz_regression_default(iters)) {
        Ok(stats) => {
            let _ = writeln!(out, "{} seeds_passed={}/{} seeds_failed={} total_failures={}",
                prefix, stats.seeds_passed, stats.seeds_total, stats.seeds_failed, stats.total_failures);
            let _ = writeln!(out, "{} valid_ok={} replay_rej={} constraint_rej={} tok_err={} ctrl_err={} proc_err={}",
                prefix, stats.total_valid_path_ok, stats.total_replay_rejects,
                stats.total_constraint_rejects, stats.total_token_decode_err,
                stats.total_control_decode_err, stats.total_process_err);
            if let Some(seed) = stats.first_failed_seed {
                let _ = writeln!(out, "{} first_failing_seed={}", prefix, seed);
                if let Some(failure) = stats.first_failure {
                    print_capnet_fuzz_failure(out, failure);
                }
            }
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet-fuzz-corpus failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_fuzz_soak<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let iters = match parts.next().and_then(parse_usize_auto) {
        Some(v) => v as u32,
        None => {
            let _ = writeln!(out, "{} usage: capnet-fuzz-soak <iters> <rounds>", prefix);
            return;
        }
    };
    let rounds = match parts.next().and_then(parse_usize_auto) {
        Some(v) => v as u32,
        None => {
            let _ = writeln!(out, "{} usage: capnet-fuzz-soak <iters> <rounds>", prefix);
            return;
        }
    };
    const MAX_FUZZ_ITERS: u32 = 10_000;
    const MAX_SOAK_ROUNDS: u32 = 100;
    if iters == 0 || iters > MAX_FUZZ_ITERS {
        let _ = writeln!(out, "{} iterations must be 1..=10000", prefix);
        return;
    }
    if rounds == 0 || rounds > MAX_SOAK_ROUNDS {
        let _ = writeln!(out, "{} rounds must be 1..=100", prefix);
        return;
    }
    let _ = writeln!(out, "{} ===== CapNet Corpus Soak =====", prefix);
    let _ = writeln!(out, "{} rounds={} iters_per_seed={} seeds={}",
        prefix, rounds, iters, crate::net::capnet::CAPNET_FUZZ_REGRESSION_SEEDS.len());
    match run_capnet_with_irqs_masked(|| crate::net::capnet::capnet_fuzz_regression_soak_default(iters, rounds)) {
        Ok(stats) => {
            let _ = writeln!(out, "{} rounds_passed={}/{} rounds_failed={} seed_passes={} seed_failures={} total_failures={}",
                prefix, stats.rounds_passed, stats.rounds, stats.rounds_failed,
                stats.seed_passes, stats.seed_failures, stats.total_failures);
            let _ = writeln!(out, "{} valid_ok={} replay_rej={} constraint_rej={}",
                prefix, stats.total_valid_path_ok, stats.total_replay_rejects, stats.total_constraint_rejects);
            if let Some(round_idx) = stats.first_failed_round {
                let _ = writeln!(out, "{} first_failed_round={}", prefix, round_idx);
                if let Some(seed) = stats.first_failed_seed {
                    let _ = writeln!(out, "{} first_failed_seed={}", prefix, seed);
                }
                if let Some(failure) = stats.first_failure {
                    print_capnet_fuzz_failure(out, failure);
                }
            }
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet-fuzz-soak failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_stats<W: Write>(out: &mut W, prefix: &str) {
    let peers = crate::net::capnet::peer_snapshots();
    let mut peer_active = 0usize;
    let mut peer_keyed = 0usize;
    let mut peer_policy_disabled = 0usize;
    let mut peer_policy_audit = 0usize;
    let mut peer_policy_enforce = 0usize;
    for i in 0..peers.len() {
        if let Some(peer) = peers[i] {
            peer_active += 1;
            if peer.key_epoch != 0 { peer_keyed += 1; }
            match peer.trust {
                crate::net::capnet::PeerTrustPolicy::Disabled => peer_policy_disabled += 1,
                crate::net::capnet::PeerTrustPolicy::Audit => peer_policy_audit += 1,
                crate::net::capnet::PeerTrustPolicy::Enforce => peer_policy_enforce += 1,
            }
        }
    }
    let leases = crate::capability::capability_manager().remote_lease_snapshots();
    let mut lease_active = 0usize;
    let mut lease_owner_any = 0usize;
    let mut lease_owner_bound = 0usize;
    let mut lease_bounded_use = 0usize;
    for i in 0..leases.len() {
        if let Some(lease) = leases[i] {
            if !lease.active || lease.revoked { continue; }
            lease_active += 1;
            if lease.owner_any { lease_owner_any += 1; } else { lease_owner_bound += 1; }
            if lease.enforce_use_budget { lease_bounded_use += 1; }
        }
    }
    let journal = crate::net::capnet::journal_stats();
    let _ = writeln!(out, "{} ===== CapNet Stats =====", prefix);
    match crate::net::capnet::local_device_id() {
        Some(id) => { let _ = writeln!(out, "{} local_device=0x{:016x}", prefix, id); }
        None => { let _ = writeln!(out, "{} local_device=(uninitialized)", prefix); }
    }
    let _ = writeln!(out, "{} peers: active={} keyed={} disabled/audit/enforce={}/{}/{}",
        prefix, peer_active, peer_keyed, peer_policy_disabled, peer_policy_audit, peer_policy_enforce);
    let _ = writeln!(out, "{} leases: active={} owner_any/bound={}/{} bounded_use={}",
        prefix, lease_active, lease_owner_any, lease_owner_bound, lease_bounded_use);
    let _ = writeln!(out, "{} journal: delegations_active={} tombstones_active={} revok_epoch_max/next={}/{}",
        prefix, journal.delegation_records_active, journal.revocation_tombstones_active,
        journal.max_revocation_epoch, journal.next_revocation_epoch);
}

fn cmd_capnet_hello<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let ip = match parts.next().and_then(parse_ipv4_netstack) {
        Some(ip) => ip,
        None => {
            let _ = writeln!(out, "{} usage: capnet-hello <ip> <port> <peer_id>", prefix);
            return;
        }
    };
    let port = match parts.next().and_then(parse_u32_auto) {
        Some(v) if v <= u16::MAX as u32 => v as u16,
        _ => {
            let _ = writeln!(out, "{} invalid port", prefix);
            return;
        }
    };
    let peer_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => {
            let _ = writeln!(out, "{} invalid peer_id", prefix);
            return;
        }
    };
    match crate::net::net_reactor::capnet_send_hello(peer_id, ip, port) {
        Ok(seq) => {
            let _ = writeln!(out, "{} capnet HELLO sent seq={}", prefix, seq);
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet HELLO failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_heartbeat<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let ip = match parts.next().and_then(parse_ipv4_netstack) {
        Some(ip) => ip,
        None => {
            let _ = writeln!(out, "{} usage: capnet-heartbeat <ip> <port> <peer_id> [ack] [ack_only]", prefix);
            return;
        }
    };
    let port = match parts.next().and_then(parse_u32_auto) {
        Some(v) if v <= u16::MAX as u32 => v as u16,
        _ => {
            let _ = writeln!(out, "{} invalid port", prefix);
            return;
        }
    };
    let peer_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => {
            let _ = writeln!(out, "{} invalid peer_id", prefix);
            return;
        }
    };
    let ack = parts.next().and_then(parse_u32_auto).unwrap_or(0);
    let ack_only = parts.next().and_then(parse_u32_auto).map(|v| v != 0).unwrap_or(false);
    match crate::net::net_reactor::capnet_send_heartbeat(peer_id, ip, port, ack, ack_only) {
        Ok(seq) => {
            let _ = writeln!(out, "{} capnet heartbeat sent seq={}", prefix, seq);
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet heartbeat failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_lend<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let ip = match parts.next().and_then(parse_ipv4_netstack) {
        Some(ip) => ip,
        None => {
            let _ = writeln!(out, "{} usage: capnet-lend <ip> <port> <peer_id> <cap_type> <object_id> <rights> <ttl_ticks> [context_pid] [max_uses] [max_bytes] [measurement] [session_id]", prefix);
            return;
        }
    };
    let port = match parts.next().and_then(parse_u32_auto) {
        Some(v) if v <= u16::MAX as u32 => v as u16,
        _ => { let _ = writeln!(out, "{} invalid port", prefix); return; }
    };
    let peer_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => { let _ = writeln!(out, "{} invalid peer_id", prefix); return; }
    };
    let cap_type = match parts.next().and_then(parse_capnet_cap_type) {
        Some(v) => v,
        None => {
            let _ = writeln!(out, "{} invalid cap_type (channel/task/spawner/console/clock/store/filesystem or numeric)", prefix);
            return;
        }
    };
    let object_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) => v,
        None => { let _ = writeln!(out, "{} invalid object_id", prefix); return; }
    };
    let rights = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v <= u32::MAX as u64 => v as u32,
        _ => { let _ = writeln!(out, "{} invalid rights (u32)", prefix); return; }
    };
    let ttl_ticks = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v > 0 => v,
        _ => { let _ = writeln!(out, "{} invalid ttl_ticks (must be > 0)", prefix); return; }
    };
    let context_pid = parts.next().and_then(parse_u32_auto).unwrap_or(0);
    let max_uses = match parts.next().and_then(parse_u32_auto) {
        Some(v) if v <= u16::MAX as u32 => v as u16,
        Some(_) => { let _ = writeln!(out, "{} invalid max_uses (<=65535)", prefix); return; }
        None => 0,
    };
    let max_bytes = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v <= u32::MAX as u64 => v as u32,
        Some(_) => { let _ = writeln!(out, "{} invalid max_bytes (<=u32::MAX)", prefix); return; }
        None => 0,
    };
    let measurement_hash = parts.next().and_then(parse_u64_auto).unwrap_or(0);
    let session_id = parts.next().and_then(parse_u32_auto).unwrap_or(0);

    let issuer_device_id = match crate::net::capnet::local_device_id() {
        Some(id) => id,
        None => {
            let _ = writeln!(out, "{} capnet local identity not initialized", prefix);
            return;
        }
    };
    let now = crate::scheduler::pit::get_ticks() as u64;
    let nonce_hi = crate::security::security().random_u32() as u64;
    let nonce_lo = crate::security::security().random_u32() as u64;

    let mut token = crate::net::capnet::CapabilityTokenV1::empty();
    token.cap_type = cap_type;
    token.issuer_device_id = issuer_device_id;
    token.subject_device_id = peer_id;
    token.object_id = object_id;
    token.rights = rights;
    token.issued_at = now;
    token.not_before = now;
    token.expires_at = now.saturating_add(ttl_ticks);
    token.nonce = (nonce_hi << 32) | nonce_lo;
    token.context = context_pid;
    token.max_uses = max_uses;
    token.max_bytes = max_bytes;
    token.measurement_hash = measurement_hash;
    token.session_id = session_id;
    token.constraints_flags = 0;
    if max_uses > 0 { token.constraints_flags |= crate::net::capnet::CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE; }
    if max_bytes > 0 { token.constraints_flags |= crate::net::capnet::CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA; }
    if measurement_hash != 0 { token.constraints_flags |= crate::net::capnet::CAPNET_CONSTRAINT_MEASUREMENT_BOUND; }
    if session_id != 0 { token.constraints_flags |= crate::net::capnet::CAPNET_CONSTRAINT_SESSION_BOUND; }

    match crate::net::net_reactor::capnet_send_token_offer(peer_id, ip, port, token) {
        Ok(token_id) => {
            let _ = writeln!(out, "{} capnet token offer sent: token_id=0x{:016x} cap_type={} rights=0x{:08x} ttl={}",
                prefix, token_id, cap_type, rights, ttl_ticks);
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet token offer failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_accept<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let ip = match parts.next().and_then(parse_ipv4_netstack) {
        Some(ip) => ip,
        None => {
            let _ = writeln!(out, "{} usage: capnet-accept <ip> <port> <peer_id> <token_id> [ack]", prefix);
            return;
        }
    };
    let port = match parts.next().and_then(parse_u32_auto) {
        Some(v) if v <= u16::MAX as u32 => v as u16,
        _ => { let _ = writeln!(out, "{} invalid port", prefix); return; }
    };
    let peer_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => { let _ = writeln!(out, "{} invalid peer_id", prefix); return; }
    };
    let token_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => { let _ = writeln!(out, "{} invalid token_id", prefix); return; }
    };
    let ack = parts.next().and_then(parse_u32_auto).unwrap_or(0);
    match crate::net::net_reactor::capnet_send_token_accept(peer_id, ip, port, token_id, ack) {
        Ok(seq) => {
            let _ = writeln!(out, "{} capnet token accept sent: seq={} token_id=0x{:016x}",
                prefix, seq, token_id);
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet token accept failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_revoke<W: Write>(
    out: &mut W,
    prefix: &str,
    mut parts: core::str::SplitWhitespace,
) {
    let ip = match parts.next().and_then(parse_ipv4_netstack) {
        Some(ip) => ip,
        None => {
            let _ = writeln!(out, "{} usage: capnet-revoke <ip> <port> <peer_id> <token_id>", prefix);
            return;
        }
    };
    let port = match parts.next().and_then(parse_u32_auto) {
        Some(v) if v <= u16::MAX as u32 => v as u16,
        _ => { let _ = writeln!(out, "{} invalid port", prefix); return; }
    };
    let peer_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => { let _ = writeln!(out, "{} invalid peer_id", prefix); return; }
    };
    let token_id = match parts.next().and_then(parse_u64_auto) {
        Some(v) if v != 0 => v,
        _ => { let _ = writeln!(out, "{} invalid token_id", prefix); return; }
    };
    match crate::net::net_reactor::capnet_send_token_revoke(peer_id, ip, port, token_id) {
        Ok(seq) => {
            let _ = writeln!(out, "{} capnet token revoke sent: seq={} token_id=0x{:016x}",
                prefix, seq, token_id);
        }
        Err(e) => {
            let _ = writeln!(out, "{} capnet token revoke failed: {}", prefix, e);
        }
    }
}

fn cmd_capnet_demo<W: Write>(out: &mut W, prefix: &str) {
    let local_id = match crate::net::capnet::local_device_id() {
        Some(id) => id,
        None => {
            let _ = writeln!(out, "{} capnet local identity not initialized", prefix);
            return;
        }
    };
    let _ = writeln!(out, "{} ===== CapNet End-to-End Demo =====", prefix);

    let loopback_peer = local_id;
    if let Err(e) = crate::net::capnet::register_peer(loopback_peer, crate::net::capnet::PeerTrustPolicy::Audit, 0) {
        let _ = writeln!(out, "{} demo failed: peer registration: {}", prefix, e.as_str());
        return;
    }

    let mut k0 = ((crate::security::security().random_u32() as u64) << 32)
        | (crate::security::security().random_u32() as u64);
    let mut k1 = ((crate::security::security().random_u32() as u64) << 32)
        | (crate::security::security().random_u32() as u64);
    if k0 == 0 && k1 == 0 { k1 = 1; } else if k0 == 0 { k0 = 1; }
    let key_epoch = (crate::security::security().random_u32() | 1).max(1);
    if let Err(e) = crate::net::capnet::install_peer_session_key(loopback_peer, key_epoch, k0, k1, 0) {
        let _ = writeln!(out, "{} demo failed: session install: {}", prefix, e.as_str());
        return;
    }

    let now = crate::scheduler::pit::get_ticks() as u64;
    let mut token = crate::net::capnet::CapabilityTokenV1::empty();
    token.cap_type = crate::capability::CapabilityType::Filesystem as u8;
    token.object_id = 0x4341_504E_4554_0000u64 ^ now.rotate_left(7);
    token.rights = crate::capability::Rights::FS_READ;
    token.issued_at = now;
    token.not_before = now;
    token.expires_at = now.saturating_add(512);
    token.nonce = ((crate::security::security().random_u32() as u64) << 32)
        | (crate::security::security().random_u32() as u64);
    token.constraints_flags = crate::net::capnet::CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE;
    token.max_uses = 2;
    token.context = 0;

    if token.validate_semantics().is_err() {
        let _ = writeln!(out, "{} demo failed: token semantic validation", prefix);
        return;
    }

    let _ = writeln!(out, "{} step 1: build+process TOKEN_OFFER...", prefix);
    let offer = match crate::net::capnet::build_token_offer_frame(loopback_peer, 0, &mut token) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(out, "{} demo failed: build offer: {}", prefix, e.as_str());
            return;
        }
    };
    let offer_rx = match crate::net::capnet::process_incoming_control_payload(
        &offer.bytes[..offer.len],
        crate::scheduler::pit::get_ticks() as u64,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(out, "{} demo failed: process offer: {}", prefix, e.as_str());
            return;
        }
    };
    if offer_rx.msg_type != crate::net::capnet::CapNetControlType::TokenOffer {
        let _ = writeln!(out, "{} demo failed: unexpected rx type for offer", prefix);
        return;
    }

    let mut lease_present = false;
    let leases_after_offer = crate::capability::capability_manager().remote_lease_snapshots();
    let mut i = 0usize;
    while i < leases_after_offer.len() {
        if let Some(lease) = leases_after_offer[i] {
            if lease.active && !lease.revoked && lease.token_id == offer.token_id {
                lease_present = true;
                break;
            }
        }
        i += 1;
    }
    if !lease_present {
        let _ = writeln!(out, "{} demo failed: lease not installed after offer", prefix);
        return;
    }

    let _ = writeln!(out, "{} step 2: use leased capability before revoke...", prefix);
    let demo_pid = crate::ipc::ProcessId(1);
    let allow_before_revoke = crate::capability::check_capability(
        demo_pid,
        token.object_id,
        crate::capability::CapabilityType::Filesystem,
        crate::capability::Rights::new(crate::capability::Rights::FS_READ),
    );
    if !allow_before_revoke {
        let _ = writeln!(out, "{} demo failed: capability denied before revoke", prefix);
        return;
    }

    let _ = writeln!(out, "{} step 3: build+process TOKEN_REVOKE...", prefix);
    let revoke = match crate::net::capnet::build_token_revoke_frame(loopback_peer, offer.seq, offer.token_id) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(out, "{} demo failed: build revoke: {}", prefix, e.as_str());
            return;
        }
    };
    let revoke_rx = match crate::net::capnet::process_incoming_control_payload(
        &revoke.bytes[..revoke.len],
        crate::scheduler::pit::get_ticks() as u64,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(out, "{} demo failed: process revoke: {}", prefix, e.as_str());
            return;
        }
    };
    if revoke_rx.msg_type != crate::net::capnet::CapNetControlType::TokenRevoke {
        let _ = writeln!(out, "{} demo failed: unexpected rx type for revoke", prefix);
        return;
    }

    let allow_after_revoke = crate::capability::check_capability(
        demo_pid,
        token.object_id,
        crate::capability::CapabilityType::Filesystem,
        crate::capability::Rights::new(crate::capability::Rights::FS_READ),
    );
    if allow_after_revoke {
        let _ = writeln!(out, "{} demo failed: capability still allowed after revoke", prefix);
        return;
    }

    let mut lease_still_present = false;
    let leases_after_revoke = crate::capability::capability_manager().remote_lease_snapshots();
    let mut j = 0usize;
    while j < leases_after_revoke.len() {
        if let Some(lease) = leases_after_revoke[j] {
            if lease.active && !lease.revoked && lease.token_id == offer.token_id {
                lease_still_present = true;
                break;
            }
        }
        j += 1;
    }
    if lease_still_present {
        let _ = writeln!(out, "{} demo failed: lease still active after revoke", prefix);
        return;
    }

    let _ = writeln!(out, "{} step 4: result", prefix);
    let _ = writeln!(out, "{} token_id=0x{:016x}", prefix, offer.token_id);
    let _ = writeln!(out, "{} use before revoke: allowed", prefix);
    let _ = writeln!(out, "{} use after revoke: denied", prefix);
    let _ = writeln!(out, "{} lease install/revoke: verified", prefix);
    let _ = writeln!(out, "{} capnet end-to-end demo PASSED", prefix);
}


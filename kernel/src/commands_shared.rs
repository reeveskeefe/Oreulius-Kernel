/*!
 * Shared cross-architecture command handlers used by both the full x86 shell
 * and the AArch64 runtime shell adapter.
 */

extern crate alloc;

use core::fmt::Write;

use crate::vfs;

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

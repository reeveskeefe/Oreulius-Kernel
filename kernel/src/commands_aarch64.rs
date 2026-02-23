/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 *
 * AArch64-selective commands module used during bring-up. This intentionally
 * exposes only a subset of the x86-centric `commands.rs` surface and routes
 * output to PL011 instead of VGA.
 */

extern crate alloc;

use core::fmt::{self, Write};

use crate::vfs;

struct UartWriter;

impl UartWriter {
    #[inline]
    fn new() -> Self {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.init_early();
        Self
    }

    #[inline]
    fn line(&mut self, s: &str) {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.write_str(s);
        uart.write_str("\n");
    }
}

impl Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::arch::aarch64_pl011::early_uart().write_str(s);
        Ok(())
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
        let mut value = 0u64;
        if s.is_empty() {
            return None;
        }
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

fn print_hexdump(prefix: &str, buf: &[u8]) {
    let mut out = UartWriter::new();
    let rows = core::cmp::min((buf.len() + 15) / 16, 8);
    for row in 0..rows {
        let off = row * 16;
        let end = core::cmp::min(off + 16, buf.len());
        let _ = write!(out, "[A64-CMD] {} {:04x}: ", prefix, off);
        for i in off..end {
            let _ = write!(out, "{:02x} ", buf[i]);
        }
        for _ in end..(off + 16) {
            let _ = write!(out, "   ");
        }
        let _ = write!(out, " |");
        for &b in &buf[off..end] {
            let ch = if (0x20..=0x7e).contains(&b) { b as char } else { '.' };
            let _ = write!(out, "{}", ch);
        }
        let _ = writeln!(out, "|");
    }
}

fn cmd_help() {
    let mut out = UartWriter::new();
    out.line("[A64-CMD] commands:");
    out.line("  help");
    out.line("  echo <text>");
    out.line("  pid");
    out.line("  pid-spawn");
    out.line("  pid-set <pid>");
    out.line("  pid-drop <pid>");
    out.line("  vfs-mkdir <path>");
    out.line("  vfs-write <path> <data>");
    out.line("  vfs-read <path>");
    out.line("  vfs-ls <path>");
    out.line("  vfs-mount-virtio <path>");
    out.line("  vfs-open <path> [r|w|rw|rwc|append]");
    out.line("  vfs-readfd <fd> [n]");
    out.line("  vfs-writefd <fd> <data>");
    out.line("  vfs-close <fd>");
    out.line("  blk-info");
    out.line("  blk-partitions");
    out.line("  blk-read <lba>");
    out.line("  blk-write <lba> <byte>");
}

fn cmd_pid_info() {
    let mut out = UartWriter::new();
    let (proc_count, fd_count, current_pid) = crate::vfs_platform::aarch64_process_fd_stats();
    let _ = writeln!(
        out,
        "[A64-CMD] pid current={} processes={} open_fds={}",
        current_pid, proc_count, fd_count
    );
}

fn cmd_pid_spawn() {
    let mut out = UartWriter::new();
    match crate::vfs_platform::aarch64_spawn_process(crate::vfs_platform::current_pid()) {
        Ok(pid) => {
            let _ = writeln!(out, "[A64-CMD] pid-spawn ok pid={}", pid);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] pid-spawn failed: {}", e);
        }
    }
    cmd_pid_info();
}

fn cmd_pid_set(args: &str) {
    let mut out = UartWriter::new();
    let Some(pid) = parse_u64_auto(args.trim()).and_then(|v| u32::try_from(v).ok()) else {
        out.line("[A64-CMD] usage: pid-set <pid>");
        return;
    };
    match crate::arch::aarch64_virt::scheduler_note_context_switch(pid) {
        Ok(()) => {
            let _ = writeln!(out, "[A64-CMD] pid-set ok pid={}", pid);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] pid-set failed: {}", e);
        }
    }
    cmd_pid_info();
}

fn cmd_pid_drop(args: &str) {
    let mut out = UartWriter::new();
    let Some(pid) = parse_u64_auto(args.trim()).and_then(|v| u32::try_from(v).ok()) else {
        out.line("[A64-CMD] usage: pid-drop <pid>");
        return;
    };
    match crate::vfs_platform::aarch64_destroy_process(pid) {
        Ok(()) => {
            let _ = writeln!(out, "[A64-CMD] pid-drop ok pid={}", pid);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] pid-drop failed: {}", e);
        }
    }
    cmd_pid_info();
}

fn cmd_blk_info() {
    let mut out = UartWriter::new();
    let present = crate::virtio_blk::is_present();
    let cap = crate::virtio_blk::capacity_sectors().unwrap_or(0);
    let _ = writeln!(
        out,
        "[A64-CMD] blk present={} cap_sectors={:#x} cap_bytes={:#x}",
        if present { 1 } else { 0 },
        cap,
        cap.saturating_mul(512)
    );
}

fn cmd_blk_partitions() {
    let mut out = UartWriter::new();
    let mut mbr = [None; 4];
    let mut gpt = [None; 4];
    match crate::virtio_blk::read_partitions(&mut mbr, &mut gpt) {
        Ok(()) => {
            out.line("[A64-CMD] MBR:");
            for (i, p) in mbr.iter().enumerate() {
                if let Some(part) = p {
                    let _ = writeln!(
                        out,
                        "  {}: type=0x{:02x} lba={} sectors={} boot={}",
                        i + 1,
                        part.part_type,
                        part.lba_start,
                        part.sectors,
                        if part.bootable { 1 } else { 0 }
                    );
                }
            }
            out.line("[A64-CMD] GPT:");
            for (i, p) in gpt.iter().enumerate() {
                if let Some(part) = p {
                    let _ = write!(out, "  {}: lba {}-{} name=", i + 1, part.first_lba, part.last_lba);
                    for &b in &part.name {
                        if b == 0 {
                            break;
                        }
                        let ch = if (0x20..=0x7e).contains(&b) { b as char } else { '.' };
                        let _ = write!(out, "{}", ch);
                    }
                    let _ = writeln!(out);
                }
            }
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] blk-partitions failed: {}", e);
        }
    }
}

fn cmd_blk_read(args: &str) {
    let mut out = UartWriter::new();
    let Some(lba) = parse_u64_auto(args.trim()) else {
        out.line("[A64-CMD] usage: blk-read <lba>");
        return;
    };
    let mut sector = [0u8; 512];
    match crate::virtio_blk::read_sector(lba, &mut sector) {
        Ok(()) => {
            let _ = writeln!(out, "[A64-CMD] blk-read lba={:#x}", lba);
            print_hexdump("blk", &sector[..64]);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] blk-read failed: {}", e);
        }
    }
}

fn cmd_blk_write(args: &str) {
    let mut out = UartWriter::new();
    let mut parts = args.split_whitespace();
    let (Some(lba_s), Some(byte_s)) = (parts.next(), parts.next()) else {
        out.line("[A64-CMD] usage: blk-write <lba> <byte>");
        return;
    };
    let (Some(lba), Some(val)) = (parse_u64_auto(lba_s), parse_u64_auto(byte_s)) else {
        out.line("[A64-CMD] invalid blk-write args");
        return;
    };
    if val > 0xFF {
        out.line("[A64-CMD] blk-write byte must be <= 0xff");
        return;
    }
    let sector = [val as u8; 512];
    match crate::virtio_blk::write_sector(lba, &sector) {
        Ok(()) => {
            let _ = writeln!(out, "[A64-CMD] blk-write ok lba={:#x} byte=0x{:02x}", lba, val);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] blk-write failed: {}", e);
        }
    }
}

fn cmd_vfs_mkdir(args: &str) {
    let mut out = UartWriter::new();
    let path = args.trim();
    if path.is_empty() {
        out.line("[A64-CMD] usage: vfs-mkdir <path>");
        return;
    }
    match vfs::mkdir(path) {
        Ok(()) => {
            let _ = writeln!(out, "[A64-CMD] vfs-mkdir ok {}", path);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-mkdir failed: {}", e);
        }
    }
}

fn cmd_vfs_write(args: &str) {
    let mut out = UartWriter::new();
    let mut parts = args.splitn(2, char::is_whitespace);
    let Some(path) = parts.next() else {
        out.line("[A64-CMD] usage: vfs-write <path> <data>");
        return;
    };
    let Some(data) = parts.next() else {
        out.line("[A64-CMD] usage: vfs-write <path> <data>");
        return;
    };
    match vfs::write_path(path, data.as_bytes()) {
        Ok(n) => {
            let _ = writeln!(out, "[A64-CMD] vfs-write ok path={} bytes={}", path, n);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-write failed: {}", e);
        }
    }
}

fn cmd_vfs_read(args: &str) {
    let mut out = UartWriter::new();
    let path = args.trim();
    if path.is_empty() {
        out.line("[A64-CMD] usage: vfs-read <path>");
        return;
    }
    let mut buf = [0u8; 1024];
    match vfs::read_path(path, &mut buf) {
        Ok(n) => {
            let text = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
            let _ = writeln!(out, "[A64-CMD] vfs-read {} bytes={}", path, n);
            let _ = writeln!(out, "{}", text);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-read failed: {}", e);
        }
    }
}

fn cmd_vfs_ls(args: &str) {
    let mut out = UartWriter::new();
    let path = if args.trim().is_empty() { "/" } else { args.trim() };
    let mut buf = [0u8; 1024];
    match vfs::list_dir(path, &mut buf) {
        Ok(n) => {
            let text = core::str::from_utf8(&buf[..n]).unwrap_or("<non-utf8>");
            let _ = writeln!(out, "[A64-CMD] vfs-ls {} => {}", path, text);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-ls failed: {}", e);
        }
    }
}

fn cmd_vfs_mount_virtio(args: &str) {
    let mut out = UartWriter::new();
    let path = args.trim();
    if path.is_empty() {
        out.line("[A64-CMD] usage: vfs-mount-virtio <path>");
        return;
    }
    match vfs::mount_virtio(path) {
        Ok(()) => {
            let _ = writeln!(out, "[A64-CMD] vfs-mount-virtio ok {}", path);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-mount-virtio failed: {}", e);
        }
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

fn cmd_vfs_open(args: &str) {
    let mut out = UartWriter::new();
    let mut parts = args.split_whitespace();
    let Some(path) = parts.next() else {
        out.line("[A64-CMD] usage: vfs-open <path> [mode]");
        return;
    };
    let flags = parse_open_flags(parts.next().unwrap_or("r"));
    match vfs::open_for_current(path, flags) {
        Ok(fd) => {
            let _ = writeln!(out, "[A64-CMD] vfs-open ok fd={}", fd);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-open failed: {}", e);
        }
    }
}

fn cmd_vfs_readfd(args: &str) {
    let mut out = UartWriter::new();
    let mut parts = args.split_whitespace();
    let (Some(fd_s), n_s) = (parts.next(), parts.next()) else {
        out.line("[A64-CMD] usage: vfs-readfd <fd> [n]");
        return;
    };
    let Some(fd) = parse_usize_auto(fd_s) else {
        out.line("[A64-CMD] usage: vfs-readfd <fd> [n]");
        return;
    };
    let n = n_s.and_then(parse_usize_auto).unwrap_or(256).clamp(1, 1024);
    let pid = crate::vfs_platform::current_pid().unwrap_or(1);
    let mut buf = [0u8; 1024];
    match vfs::read_fd(pid, fd, &mut buf[..n]) {
        Ok(read) => {
            let text = core::str::from_utf8(&buf[..read]).unwrap_or("<non-utf8>");
            let _ = writeln!(out, "[A64-CMD] vfs-readfd fd={} bytes={}", fd, read);
            let _ = writeln!(out, "{}", text);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-readfd failed: {}", e);
        }
    }
}

fn cmd_vfs_writefd(args: &str) {
    let mut out = UartWriter::new();
    let mut parts = args.splitn(2, char::is_whitespace);
    let Some(fd_s) = parts.next() else {
        out.line("[A64-CMD] usage: vfs-writefd <fd> <data>");
        return;
    };
    let Some(data) = parts.next() else {
        out.line("[A64-CMD] usage: vfs-writefd <fd> <data>");
        return;
    };
    let Some(fd) = parse_usize_auto(fd_s) else {
        out.line("[A64-CMD] vfs-writefd: invalid fd");
        return;
    };
    let pid = crate::vfs_platform::current_pid().unwrap_or(1);
    match vfs::write_fd(pid, fd, data.as_bytes()) {
        Ok(n) => {
            let _ = writeln!(out, "[A64-CMD] vfs-writefd ok fd={} bytes={}", fd, n);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-writefd failed: {}", e);
        }
    }
}

fn cmd_vfs_close(args: &str) {
    let mut out = UartWriter::new();
    let Some(fd) = parse_usize_auto(args.trim()) else {
        out.line("[A64-CMD] usage: vfs-close <fd>");
        return;
    };
    let pid = crate::vfs_platform::current_pid().unwrap_or(1);
    match vfs::close_fd(pid, fd) {
        Ok(()) => {
            let _ = writeln!(out, "[A64-CMD] vfs-close ok fd={}", fd);
        }
        Err(e) => {
            let _ = writeln!(out, "[A64-CMD] vfs-close failed: {}", e);
        }
    }
}

pub fn try_execute(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return true;
    }
    let mut parts = trimmed.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let rest = trimmed[cmd.len()..].trim_start();

    match cmd {
        "help-cmd" | "commands-help" => cmd_help(),
        "echo" => {
            let mut out = UartWriter::new();
            let _ = writeln!(out, "[A64-CMD] {}", rest);
        }
        "pid" => cmd_pid_info(),
        "pid-spawn" => cmd_pid_spawn(),
        "pid-set" => cmd_pid_set(rest),
        "pid-drop" => cmd_pid_drop(rest),
        "blk-info" => cmd_blk_info(),
        "blk-partitions" => cmd_blk_partitions(),
        "blk-read" => cmd_blk_read(rest),
        "blk-write" => cmd_blk_write(rest),
        "vfs-mkdir" => cmd_vfs_mkdir(rest),
        "vfs-write" => cmd_vfs_write(rest),
        "vfs-read" => cmd_vfs_read(rest),
        "vfs-ls" => cmd_vfs_ls(rest),
        "vfs-mount-virtio" => cmd_vfs_mount_virtio(rest),
        "vfs-open" => cmd_vfs_open(rest),
        "vfs-readfd" => cmd_vfs_readfd(rest),
        "vfs-writefd" => cmd_vfs_writefd(rest),
        "vfs-close" => cmd_vfs_close(rest),
        _ => return false,
    }

    true
}

pub fn execute(input: &str) {
    let _ = try_execute(input);
}

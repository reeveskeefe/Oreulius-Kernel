/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 */

use core::ptr;
use core::str;

const FDT_MAGIC: u32 = 0xD00D_FEED;
const MIN_DTB_SIZE: usize = 40;
const MAX_DTB_SIZE: usize = 16 * 1024 * 1024;

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

const MAX_TREE_DEPTH: usize = 16;
const MAX_BUS_RANGES: usize = 8;
const MAX_INTERRUPT_CONTROLLERS: usize = 16;
const MAX_VIRTIO_MMIO_DEVICES: usize = 16;

const CLASS_PL011: u8 = 1 << 0;
const CLASS_GICV2: u8 = 1 << 1;
const CLASS_TIMER: u8 = 1 << 2;
const CLASS_VIRTIO_MMIO: u8 = 1 << 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct FdtHeaderRaw {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DtbHeaderInfo {
    pub ptr: usize,
    pub total_size: usize,
    pub off_dt_struct: usize,
    pub off_dt_strings: usize,
    pub off_mem_rsvmap: usize,
    pub version: u32,
    pub last_comp_version: u32,
    pub size_dt_strings: usize,
    pub size_dt_struct: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DtbRange {
    pub base: usize,
    pub size: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DtbMmioIrqDevice {
    pub base: usize,
    pub size: usize,
    pub irq_intid: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DtbPlatformInfo {
    pub header: DtbHeaderInfo,
    pub memory: Option<DtbRange>,
    pub uart_pl011_base: Option<usize>,
    pub uart_pl011_irq_intid: Option<u32>,
    pub gic_dist_base: Option<usize>,
    pub gic_cpu_base: Option<usize>,
    pub timer_irq_intid: Option<u32>,
    pub virtio_mmio: [DtbMmioIrqDevice; MAX_VIRTIO_MMIO_DEVICES],
    pub virtio_mmio_count: usize,
    pub chosen_bootargs_ptr: Option<usize>,
    pub chosen_bootargs_len: usize,
}

impl DtbPlatformInfo {
    #[inline]
    pub fn chosen_bootargs_str(&self) -> Option<&'static str> {
        bootargs_str(self.chosen_bootargs_ptr, self.chosen_bootargs_len)
    }
}

#[derive(Clone, Copy)]
struct NodeState {
    addr_cells: u32,
    size_cells: u32,
    interrupt_cells: u32,
    interrupt_parent_phandle: Option<u32>,
    self_phandle: Option<u32>,
    is_interrupt_controller: bool,
    class_bits: u8,
    is_chosen: bool,
    is_memory: bool,
    reg_first: Option<DtbRange>,
    reg_second: Option<DtbRange>,
    irq_first_candidate: Option<u32>,
    timer_irq_candidate: Option<u32>,
    bus_ranges: [BusRange; MAX_BUS_RANGES],
    bus_range_count: usize,
}

#[derive(Clone, Copy, Debug)]
struct BusRange {
    child_base: u64,
    cpu_base: u64,
    size: u64,
}

#[derive(Clone, Copy, Debug)]
struct InterruptControllerInfo {
    phandle: u32,
    interrupt_cells: u32,
}

impl Default for NodeState {
    fn default() -> Self {
        Self {
            addr_cells: 2,
            size_cells: 1,
            interrupt_cells: 3,
            interrupt_parent_phandle: None,
            self_phandle: None,
            is_interrupt_controller: false,
            class_bits: 0,
            is_chosen: false,
            is_memory: false,
            reg_first: None,
            reg_second: None,
            irq_first_candidate: None,
            timer_irq_candidate: None,
            bus_ranges: [BusRange {
                child_base: 0,
                cpu_base: 0,
                size: 0,
            }; MAX_BUS_RANGES],
            bus_range_count: 0,
        }
    }
}

#[inline]
fn be32(v: u32) -> u32 {
    u32::from_be(v)
}

#[inline]
fn align4(v: usize) -> usize {
    (v + 3) & !3
}

#[inline]
fn read_be_u32(ptr_addr: usize) -> u32 {
    be32(unsafe { ptr::read_unaligned(ptr_addr as *const u32) })
}

fn bytes_at(base: usize, total_size: usize, rel_off: usize, len: usize) -> Option<&'static [u8]> {
    let end = rel_off.checked_add(len)?;
    if end > total_size {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts((base + rel_off) as *const u8, len) })
}

fn cstr_from_bytes(bytes: &'static [u8]) -> Option<&'static [u8]> {
    let len = bytes.iter().position(|&b| b == 0)?;
    Some(&bytes[..len])
}

fn fdt_string(header: &DtbHeaderInfo, nameoff: usize) -> Option<&'static [u8]> {
    let strings = bytes_at(
        header.ptr,
        header.total_size,
        header.off_dt_strings,
        header.size_dt_strings,
    )?;
    if nameoff >= strings.len() {
        return None;
    }
    cstr_from_bytes(&strings[nameoff..])
}

fn bytes_eq(a: &'static [u8], b: &[u8]) -> bool {
    a == b
}

fn bytes_starts_with(a: &'static [u8], b: &[u8]) -> bool {
    a.len() >= b.len() && &a[..b.len()] == b
}

fn compat_list_contains(data: &'static [u8], needle: &[u8]) -> bool {
    let mut i = 0usize;
    while i < data.len() {
        let rest = &data[i..];
        let Some(end) = rest.iter().position(|&b| b == 0) else {
            break;
        };
        if &rest[..end] == needle {
            return true;
        }
        i = i.saturating_add(end + 1);
    }
    false
}

fn parse_u32_prop(data: &'static [u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(be32(unsafe {
        ptr::read_unaligned(data.as_ptr() as *const u32)
    }))
}

fn parse_cells_u64(data: &'static [u8], cells: u32, offset_cells: usize) -> Option<u64> {
    if cells == 0 || cells > 2 {
        return None;
    }
    let start = offset_cells.checked_mul(4)?;
    let count_bytes = (cells as usize).checked_mul(4)?;
    let end = start.checked_add(count_bytes)?;
    if end > data.len() {
        return None;
    }
    let mut value = 0u64;
    for i in 0..(cells as usize) {
        let word =
            be32(unsafe { ptr::read_unaligned(data[start + i * 4..].as_ptr() as *const u32) });
        value = (value << 32) | (word as u64);
    }
    Some(value)
}

fn parse_reg_first(data: &'static [u8], addr_cells: u32, size_cells: u32) -> Option<DtbRange> {
    let base = parse_cells_u64(data, addr_cells, 0)? as usize;
    let size = parse_cells_u64(data, size_cells, addr_cells as usize)? as usize;
    Some(DtbRange { base, size })
}

fn parse_reg_two(
    data: &'static [u8],
    addr_cells: u32,
    size_cells: u32,
) -> Option<(DtbRange, DtbRange)> {
    let cells_per = (addr_cells as usize).checked_add(size_cells as usize)?;
    let first = parse_reg_first(data, addr_cells, size_cells)?;
    let second_base = parse_cells_u64(data, addr_cells, cells_per)? as usize;
    let second_size = parse_cells_u64(data, size_cells, cells_per + addr_cells as usize)? as usize;
    Some((
        first,
        DtbRange {
            base: second_base,
            size: second_size,
        },
    ))
}

fn parse_timer_interrupts(data: &'static [u8], interrupt_cells: u32) -> Option<u32> {
    let cells = if interrupt_cells == 0 {
        3
    } else {
        interrupt_cells
    } as usize;
    if cells < 2 {
        return None;
    }
    let tuple_bytes = cells.checked_mul(4)?;
    if tuple_bytes == 0 {
        return None;
    }

    let mut fallback: Option<u32> = None;
    let mut off = 0usize;
    while off + tuple_bytes <= data.len() {
        let ty = be32(unsafe { ptr::read_unaligned(data[off..].as_ptr() as *const u32) });
        let num = be32(unsafe { ptr::read_unaligned(data[off + 4..].as_ptr() as *const u32) });
        let intid = match ty {
            0 => 32u32.checked_add(num)?, // SPI
            1 => 16u32.checked_add(num)?, // PPI
            _ => {
                off += tuple_bytes;
                continue;
            }
        };
        if ty == 1 && num == 14 {
            return Some(intid); // EL1 physical non-secure timer on qemu virt
        }
        if fallback.is_none() {
            fallback = Some(intid);
        }
        off += tuple_bytes;
    }
    fallback
}

fn parse_first_interrupt_intid(data: &'static [u8], interrupt_cells: u32) -> Option<u32> {
    let cells = if interrupt_cells == 0 {
        3
    } else {
        interrupt_cells
    } as usize;
    if cells < 2 {
        return None;
    }
    let tuple_bytes = cells.checked_mul(4)?;
    if tuple_bytes == 0 || data.len() < tuple_bytes {
        return None;
    }

    let ty = be32(unsafe { ptr::read_unaligned(data.as_ptr() as *const u32) });
    let num = be32(unsafe { ptr::read_unaligned(data[4..].as_ptr() as *const u32) });
    match ty {
        0 => 32u32.checked_add(num), // SPI
        1 => 16u32.checked_add(num), // PPI
        _ => None,
    }
}

fn parse_interrupts_extended_first(
    data: &'static [u8],
    controllers: &[Option<InterruptControllerInfo>; MAX_INTERRUPT_CONTROLLERS],
    prefer_timer_ppi14: bool,
) -> Option<u32> {
    let mut off = 0usize;
    let mut fallback = None;
    while off + 4 <= data.len() {
        let phandle = be32(unsafe { ptr::read_unaligned(data[off..].as_ptr() as *const u32) });
        off += 4;
        let Some(cells_u32) = lookup_interrupt_cells(controllers, phandle) else {
            break;
        };
        let cells = cells_u32 as usize;
        let bytes = cells.checked_mul(4)?;
        if cells < 2 || off + bytes > data.len() {
            return fallback;
        }
        let spec = &data[off..off + bytes];
        if prefer_timer_ppi14 {
            if let Some(intid) = parse_timer_interrupts(spec, cells as u32) {
                if intid == 16 + 14 {
                    return Some(intid);
                }
                if fallback.is_none() {
                    fallback = Some(intid);
                }
            }
        } else if let Some(intid) = parse_first_interrupt_intid(spec, cells as u32) {
            return Some(intid);
        }
        off += bytes;
    }
    fallback
}

#[inline]
fn translate_addr_via_parent(parent: &NodeState, addr: u64) -> Option<u64> {
    if parent.bus_range_count == 0 {
        return Some(addr);
    }
    for range in &parent.bus_ranges[..parent.bus_range_count] {
        if range.size == 0 {
            continue;
        }
        let end = range.child_base.checked_add(range.size)?;
        if addr >= range.child_base && addr < end {
            let delta = addr - range.child_base;
            return range.cpu_base.checked_add(delta);
        }
    }
    None
}

fn parse_reg_first_translated(data: &'static [u8], parent: &NodeState) -> Option<DtbRange> {
    let raw = parse_reg_first(data, parent.addr_cells, parent.size_cells)?;
    let cpu = translate_addr_via_parent(parent, raw.base as u64)? as usize;
    Some(DtbRange {
        base: cpu,
        size: raw.size,
    })
}

fn parse_reg_two_translated(
    data: &'static [u8],
    parent: &NodeState,
) -> Option<(DtbRange, DtbRange)> {
    let (first_raw, second_raw) = parse_reg_two(data, parent.addr_cells, parent.size_cells)?;
    let first_base = translate_addr_via_parent(parent, first_raw.base as u64)? as usize;
    let second_base = translate_addr_via_parent(parent, second_raw.base as u64)? as usize;
    Some((
        DtbRange {
            base: first_base,
            size: first_raw.size,
        },
        DtbRange {
            base: second_base,
            size: second_raw.size,
        },
    ))
}

fn parse_ranges_into_state(state: &mut NodeState, parent: &NodeState, data: &'static [u8]) {
    state.bus_range_count = 0;
    if data.is_empty() {
        // Empty ranges property => identity mapping for children.
        return;
    }

    let child_cells = state.addr_cells as usize;
    let parent_cells = parent.addr_cells as usize;
    let size_cells = state.size_cells as usize;
    let tuple_cells = match child_cells
        .checked_add(parent_cells)
        .and_then(|v| v.checked_add(size_cells))
    {
        Some(v) if v > 0 => v,
        _ => return,
    };
    let tuple_bytes = match tuple_cells.checked_mul(4) {
        Some(v) if v > 0 => v,
        _ => return,
    };

    let mut off = 0usize;
    while off + tuple_bytes <= data.len() && state.bus_range_count < MAX_BUS_RANGES {
        let child = match parse_cells_u64(data, state.addr_cells, off / 4) {
            Some(v) => v,
            None => break,
        };
        let parent_addr = match parse_cells_u64(data, parent.addr_cells, off / 4 + child_cells) {
            Some(v) => v,
            None => break,
        };
        let size =
            match parse_cells_u64(data, state.size_cells, off / 4 + child_cells + parent_cells) {
                Some(v) => v,
                None => break,
            };
        let Some(cpu_base) = translate_addr_via_parent(parent, parent_addr) else {
            off += tuple_bytes;
            continue;
        };
        state.bus_ranges[state.bus_range_count] = BusRange {
            child_base: child,
            cpu_base,
            size,
        };
        state.bus_range_count += 1;
        off += tuple_bytes;
    }
}

fn register_interrupt_controller(
    table: &mut [Option<InterruptControllerInfo>; MAX_INTERRUPT_CONTROLLERS],
    phandle: u32,
    interrupt_cells: u32,
) {
    if phandle == 0 {
        return;
    }
    for slot in table.iter_mut() {
        if let Some(info) = slot {
            if info.phandle == phandle {
                *info = InterruptControllerInfo {
                    phandle,
                    interrupt_cells,
                };
                return;
            }
        }
    }
    for slot in table.iter_mut() {
        if slot.is_none() {
            *slot = Some(InterruptControllerInfo {
                phandle,
                interrupt_cells,
            });
            return;
        }
    }
}

fn lookup_interrupt_cells(
    table: &[Option<InterruptControllerInfo>; MAX_INTERRUPT_CONTROLLERS],
    phandle: u32,
) -> Option<u32> {
    if phandle == 0 {
        return None;
    }
    table
        .iter()
        .flatten()
        .find(|it| it.phandle == phandle)
        .map(|it| it.interrupt_cells)
}

fn maybe_record_virtio_mmio(info: &mut DtbPlatformInfo, state: &NodeState) {
    if (state.class_bits & CLASS_VIRTIO_MMIO) == 0 {
        return;
    }
    let Some(reg) = state.reg_first else {
        return;
    };
    for slot in &mut info.virtio_mmio[..info.virtio_mmio_count] {
        if slot.base == reg.base {
            slot.size = reg.size;
            if slot.irq_intid.is_none() {
                slot.irq_intid = state.irq_first_candidate;
            }
            return;
        }
    }
    if info.virtio_mmio_count >= info.virtio_mmio.len() {
        return;
    }
    let idx = info.virtio_mmio_count;
    info.virtio_mmio[idx] = DtbMmioIrqDevice {
        base: reg.base,
        size: reg.size,
        irq_intid: state.irq_first_candidate,
    };
    info.virtio_mmio_count += 1;
}

pub(crate) fn parse_dtb_header(ptr_addr: usize) -> Option<DtbHeaderInfo> {
    if ptr_addr == 0 {
        return None;
    }
    let raw = unsafe { ptr::read_unaligned(ptr_addr as *const FdtHeaderRaw) };
    if be32(raw.magic) != FDT_MAGIC {
        return None;
    }

    let total_size = be32(raw.totalsize) as usize;
    if !(MIN_DTB_SIZE..=MAX_DTB_SIZE).contains(&total_size) {
        return None;
    }

    let off_dt_struct = be32(raw.off_dt_struct) as usize;
    let off_dt_strings = be32(raw.off_dt_strings) as usize;
    let off_mem_rsvmap = be32(raw.off_mem_rsvmap) as usize;
    let size_dt_strings = be32(raw.size_dt_strings) as usize;
    let size_dt_struct = be32(raw.size_dt_struct) as usize;
    let version = be32(raw.version);
    let last_comp_version = be32(raw.last_comp_version);

    if off_dt_struct >= total_size || off_dt_strings >= total_size || off_mem_rsvmap >= total_size {
        return None;
    }
    if off_dt_struct.checked_add(size_dt_struct)? > total_size {
        return None;
    }
    if off_dt_strings.checked_add(size_dt_strings)? > total_size {
        return None;
    }

    Some(DtbHeaderInfo {
        ptr: ptr_addr,
        total_size,
        off_dt_struct,
        off_dt_strings,
        off_mem_rsvmap,
        version,
        last_comp_version,
        size_dt_strings,
        size_dt_struct,
    })
}

pub(crate) fn parse_platform_info(ptr_addr: usize) -> Option<DtbPlatformInfo> {
    let header = parse_dtb_header(ptr_addr)?;
    let struct_start = header.ptr.checked_add(header.off_dt_struct)?;
    let struct_end = struct_start.checked_add(header.size_dt_struct)?;
    if struct_end < struct_start {
        return None;
    }

    let mut info = DtbPlatformInfo {
        header,
        memory: None,
        uart_pl011_base: None,
        uart_pl011_irq_intid: None,
        gic_dist_base: None,
        gic_cpu_base: None,
        timer_irq_intid: None,
        virtio_mmio: [DtbMmioIrqDevice {
            base: 0,
            size: 0,
            irq_intid: None,
        }; MAX_VIRTIO_MMIO_DEVICES],
        virtio_mmio_count: 0,
        chosen_bootargs_ptr: None,
        chosen_bootargs_len: 0,
    };

    let mut stack = [NodeState::default(); MAX_TREE_DEPTH];
    let mut interrupt_controllers: [Option<InterruptControllerInfo>; MAX_INTERRUPT_CONTROLLERS] =
        [None; MAX_INTERRUPT_CONTROLLERS];
    let mut depth = 0usize;
    stack[0] = NodeState {
        addr_cells: 2,
        size_cells: 2, // QEMU virt root default; may be overwritten by root props
        interrupt_cells: 3,
        interrupt_parent_phandle: None,
        self_phandle: None,
        is_interrupt_controller: false,
        class_bits: 0,
        is_chosen: false,
        is_memory: false,
        reg_first: None,
        reg_second: None,
        irq_first_candidate: None,
        timer_irq_candidate: None,
        bus_ranges: [BusRange {
            child_base: 0,
            cpu_base: 0,
            size: 0,
        }; MAX_BUS_RANGES],
        bus_range_count: 0,
    };

    let mut cur = struct_start;
    while cur + 4 <= struct_end {
        let token = read_be_u32(cur);
        cur += 4;
        match token {
            FDT_BEGIN_NODE => {
                let name_start = cur;
                while cur < struct_end && unsafe { *(cur as *const u8) } != 0 {
                    cur += 1;
                }
                if cur >= struct_end {
                    return None;
                }
                let name_len = cur - name_start;
                cur += 1; // skip NUL
                cur = align4(cur);

                let name =
                    unsafe { core::slice::from_raw_parts(name_start as *const u8, name_len) };
                let parent = stack[depth];
                if depth + 1 >= MAX_TREE_DEPTH {
                    return None;
                }
                depth += 1;
                stack[depth] = NodeState {
                    addr_cells: parent.addr_cells,
                    size_cells: parent.size_cells,
                    interrupt_cells: parent.interrupt_cells,
                    interrupt_parent_phandle: parent.interrupt_parent_phandle,
                    self_phandle: None,
                    is_interrupt_controller: false,
                    class_bits: 0,
                    is_chosen: bytes_eq(name, b"chosen"),
                    is_memory: bytes_eq(name, b"memory") || bytes_starts_with(name, b"memory@"),
                    reg_first: None,
                    reg_second: None,
                    irq_first_candidate: None,
                    timer_irq_candidate: None,
                    bus_ranges: [BusRange {
                        child_base: 0,
                        cpu_base: 0,
                        size: 0,
                    }; MAX_BUS_RANGES],
                    bus_range_count: 0,
                };
            }
            FDT_END_NODE => {
                if depth == 0 {
                    return None;
                }
                let closing = stack[depth];
                if closing.is_interrupt_controller {
                    if let Some(phandle) = closing.self_phandle {
                        register_interrupt_controller(
                            &mut interrupt_controllers,
                            phandle,
                            closing.interrupt_cells.max(1),
                        );
                    }
                }
                depth -= 1;
            }
            FDT_PROP => {
                if cur + 8 > struct_end {
                    return None;
                }
                let len = read_be_u32(cur) as usize;
                let nameoff = read_be_u32(cur + 4) as usize;
                cur += 8;
                let data_start = cur;
                let data_end = data_start.checked_add(len)?;
                if data_end > struct_end {
                    return None;
                }
                let data = unsafe { core::slice::from_raw_parts(data_start as *const u8, len) };
                cur = align4(data_end);

                let Some(name) = fdt_string(&header, nameoff) else {
                    continue;
                };

                let parent_snapshot = if depth > 0 {
                    stack[depth - 1]
                } else {
                    stack[depth]
                };
                let state = &mut stack[depth];
                if bytes_eq(name, b"#address-cells") {
                    if let Some(v) = parse_u32_prop(data) {
                        state.addr_cells = v;
                    }
                    continue;
                }
                if bytes_eq(name, b"#size-cells") {
                    if let Some(v) = parse_u32_prop(data) {
                        state.size_cells = v;
                    }
                    continue;
                }
                if bytes_eq(name, b"#interrupt-cells") {
                    if let Some(v) = parse_u32_prop(data) {
                        state.interrupt_cells = v;
                    }
                    continue;
                }
                if bytes_eq(name, b"interrupt-parent") {
                    state.interrupt_parent_phandle = parse_u32_prop(data);
                    continue;
                }
                if bytes_eq(name, b"phandle") || bytes_eq(name, b"linux,phandle") {
                    if let Some(v) = parse_u32_prop(data) {
                        state.self_phandle = Some(v);
                        if state.is_interrupt_controller {
                            register_interrupt_controller(
                                &mut interrupt_controllers,
                                v,
                                state.interrupt_cells.max(1),
                            );
                        }
                    }
                    continue;
                }
                if bytes_eq(name, b"interrupt-controller") {
                    state.is_interrupt_controller = true;
                    if let Some(ph) = state.self_phandle {
                        register_interrupt_controller(
                            &mut interrupt_controllers,
                            ph,
                            state.interrupt_cells.max(1),
                        );
                    }
                    continue;
                }
                if bytes_eq(name, b"ranges") {
                    parse_ranges_into_state(state, &parent_snapshot, data);
                    continue;
                }
                if bytes_eq(name, b"compatible") {
                    let mut bits = 0u8;
                    if compat_list_contains(data, b"arm,pl011") {
                        bits |= CLASS_PL011;
                    }
                    if compat_list_contains(data, b"arm,cortex-a15-gic")
                        || compat_list_contains(data, b"arm,gic-400")
                        || compat_list_contains(data, b"arm,gic-v2")
                    {
                        bits |= CLASS_GICV2;
                    }
                    if compat_list_contains(data, b"arm,armv8-timer") {
                        bits |= CLASS_TIMER;
                    }
                    if compat_list_contains(data, b"virtio,mmio") {
                        bits |= CLASS_VIRTIO_MMIO;
                    }
                    state.class_bits |= bits;

                    if (state.class_bits & CLASS_PL011) != 0 && info.uart_pl011_base.is_none() {
                        if let Some(r) = state.reg_first {
                            info.uart_pl011_base = Some(r.base);
                        }
                    }
                    if (state.class_bits & CLASS_PL011) != 0 && info.uart_pl011_irq_intid.is_none()
                    {
                        info.uart_pl011_irq_intid = state.irq_first_candidate;
                    }
                    if (state.class_bits & CLASS_GICV2) != 0
                        && (info.gic_dist_base.is_none() || info.gic_cpu_base.is_none())
                    {
                        if let (Some(dist), Some(cpu)) = (state.reg_first, state.reg_second) {
                            info.gic_dist_base = Some(dist.base);
                            info.gic_cpu_base = Some(cpu.base);
                        }
                    }
                    if (state.class_bits & CLASS_TIMER) != 0 && info.timer_irq_intid.is_none() {
                        if let Some(intid) = state.timer_irq_candidate {
                            info.timer_irq_intid = Some(intid);
                        }
                    }
                    maybe_record_virtio_mmio(&mut info, state);
                    continue;
                }

                if bytes_eq(name, b"bootargs") && state.is_chosen {
                    let len_no_nul = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                    info.chosen_bootargs_ptr = Some(data_start);
                    info.chosen_bootargs_len = len_no_nul;
                    continue;
                }

                if bytes_eq(name, b"reg") {
                    if state.is_memory && info.memory.is_none() {
                        info.memory = parse_reg_first_translated(data, &parent_snapshot);
                    }
                    state.reg_first = parse_reg_first_translated(data, &parent_snapshot);
                    state.reg_second =
                        parse_reg_two_translated(data, &parent_snapshot).map(|(_, second)| second);
                    if (state.class_bits & CLASS_PL011) != 0 && info.uart_pl011_base.is_none() {
                        if let Some(r) = state.reg_first {
                            info.uart_pl011_base = Some(r.base);
                        }
                    }
                    if (state.class_bits & CLASS_GICV2) != 0
                        && (info.gic_dist_base.is_none() || info.gic_cpu_base.is_none())
                    {
                        if let (Some(dist), Some(cpu)) = (state.reg_first, state.reg_second) {
                            info.gic_dist_base = Some(dist.base);
                            info.gic_cpu_base = Some(cpu.base);
                        }
                    }
                    maybe_record_virtio_mmio(&mut info, state);
                    continue;
                }

                if bytes_eq(name, b"interrupts") {
                    let parent_interrupt_cells = state
                        .interrupt_parent_phandle
                        .and_then(|ph| lookup_interrupt_cells(&interrupt_controllers, ph))
                        .unwrap_or(parent_snapshot.interrupt_cells.max(1));
                    state.irq_first_candidate =
                        parse_first_interrupt_intid(data, parent_interrupt_cells);
                    state.timer_irq_candidate =
                        parse_timer_interrupts(data, parent_interrupt_cells);
                    if (state.class_bits & CLASS_PL011) != 0 && info.uart_pl011_irq_intid.is_none()
                    {
                        info.uart_pl011_irq_intid = state.irq_first_candidate;
                    }
                    if (state.class_bits & CLASS_TIMER) != 0 && info.timer_irq_intid.is_none() {
                        info.timer_irq_intid = state.timer_irq_candidate;
                    }
                    if (state.class_bits & CLASS_VIRTIO_MMIO) != 0 {
                        maybe_record_virtio_mmio(&mut info, state);
                    }
                    continue;
                }

                if bytes_eq(name, b"interrupts-extended") {
                    state.irq_first_candidate =
                        parse_interrupts_extended_first(data, &interrupt_controllers, false);
                    state.timer_irq_candidate =
                        parse_interrupts_extended_first(data, &interrupt_controllers, true);
                    if (state.class_bits & CLASS_PL011) != 0 && info.uart_pl011_irq_intid.is_none()
                    {
                        info.uart_pl011_irq_intid = state.irq_first_candidate;
                    }
                    if (state.class_bits & CLASS_TIMER) != 0 && info.timer_irq_intid.is_none() {
                        info.timer_irq_intid = state.timer_irq_candidate;
                    }
                    if (state.class_bits & CLASS_VIRTIO_MMIO) != 0 {
                        maybe_record_virtio_mmio(&mut info, state);
                    }
                    continue;
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => return None,
        }
    }

    Some(info)
}

#[inline]
pub(crate) fn bootargs_str(ptr: Option<usize>, len: usize) -> Option<&'static str> {
    let ptr = ptr?;
    if ptr == 0 || len == 0 {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    str::from_utf8(bytes).ok()
}

#[inline]
pub(crate) fn is_valid_dtb(ptr_addr: usize) -> bool {
    parse_dtb_header(ptr_addr).is_some()
}

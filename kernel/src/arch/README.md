# `kernel/src/arch` — Architecture Abstraction Layer

The `arch` module is the hardware portability boundary for the Oreulius kernel. It exposes a single stable `ArchPlatform` trait that `rust_main` calls for every platform-specific boot step, decoupling the rest of the kernel from CPU architecture, interrupt controller hardware, timer registers, and page-table format. The public facade now routes through target-owned backend roots: `arch::x86` for the x86-family bring-up path and `arch::aarch64` for the AArch64 bring-up path. The older leaf files remain in place behind `#[path]` shims during the transition.

---

## Table of Contents

1. [File Map](#file-map)
2. [Architecture Overview](#architecture-overview)
3. [Boot Abstraction — `mod.rs`](#boot-abstraction--modrs)
4. [MMU Subsystem — `mmu.rs`](#mmu-subsystem--mmurs)
   - [x86-64 MMU Backend — `mmu_x86_64.rs`](#x86-64-mmu-backend--mmu_x86_64rs)
   - [AArch64 MMU Backend — `mmu_aarch64.rs`](#aarch64-mmu-backend--mmu_aarch64rs)
   - [x86 Legacy MMU Shim — `mmu_x86_legacy.rs`](#x86-legacy-mmu-shim--mmu_x86_legacyrs)
5. [FPU Context — `fpu.rs`](#fpu-context--fpurs)
6. [x86 Platform](#x86-platform)
   - [Multiboot Boot Layer — `x86_legacy.rs`](#multiboot-boot-layer--x86_legacyrs)
   - [x86 Runtime — `x86_runtime.rs`](#x86-runtime--x86_runtimers)
   - [x86-64 Runtime — `x86_64_runtime.rs`](#x86-64-runtime--x86_64_runtimers)
7. [AArch64 Platform](#aarch64-platform)
   - [Device Tree Blob Parser — `aarch64_dtb.rs`](#device-tree-blob-parser--aarch64_dtbrs)
   - [PL011 UART — `aarch64_pl011.rs`](#pl011-uart--aarch64_pl011rs)
   - [Exception Vectors — `aarch64_vectors.rs`](#exception-vectors--aarch64_vectorsrs)
   - [QEMU Virt Platform — `aarch64_virt.rs`](#qemu-virt-platform--aarch64_virtrs)
   - [AArch64 Runtime — `aarch64_runtime.rs`](#aarch64-runtime--aarch64_runtimers)
8. [Unsupported Arch Stub — `unsupported.rs`](#unsupported-arch-stub--unsupportedrs)
9. [Feature Matrix](#feature-matrix)

---

## File Map

| File | Lines | Role |
|---|---|---|
| `mod.rs` | 192 | Public facade; `ArchPlatform` trait; `BootInfo`/`BootProtocol`; backend selection |
| `x86/mod.rs` | 98 | x86-family backend root; platform/runtime wrappers; legacy and x86_64 shims |
| `aarch64/mod.rs` | 84 | AArch64 backend root; boot/runtime wrappers; DTB/UART/vectors/virt shims |
| `aarch64_virt.rs` | 3,226 | QEMU `virt` board: GICv2, timer, VirtIO-MMIO, DTB walk, shell, boot handoff |
| `x86_64_runtime.rs` | 2,501 | x86-64 long-mode: GDT, IDT, PIC 8259A, COM1, PS/2, keyboard, trap dispatch |
| `mmu_x86_64.rs` | 1,209 | x86-64 4-level paging, CoW, JIT sandbox, MMIO identity map |
| `mmu_aarch64.rs` | 967 | AArch64 4-level (L0–L3) page tables, MAIR, TCR, TLB maintenance |
| `aarch64_dtb.rs` | 907 | FDT/DTB parser: memory, GICv2, PL011, VirtIO discovery |
| `x86_runtime.rs` | 862 | x86 32-bit runtime: COM1, Multiboot handoff, job table, shell |
| `aarch64_vectors.rs` | 351 | AArch64 vector table stub, exception dispatch, ESR/ELR capture |
| `mmu.rs` | 426 | MMU abstraction: `PhysAddr`, `PageAttribute`, `ArchMmu` trait, dispatch shims |
| `aarch64_pl011.rs` | 244 | ARM PrimeCell PL011 UART: TX, RX with 2 KiB ring buffer, interrupt control |
| `x86_legacy.rs` | 234 | Multiboot1/2 info parsing; `X86LegacyPlatform` implementing `ArchPlatform` |
| `fpu.rs` | 217 | FPU/SIMD state: FXSAVE/FXRSTOR (x86), NEON (AArch64), `ExtFpuState` |
| `aarch64_runtime.rs` | 165 | AArch64 high-level `enter_runtime()` |
| `mmu_x86_legacy.rs` | 88 | x86 32-bit MMU shim delegating to `crate::fs::paging::AddressSpace` |
| `mmu_unsupported.rs` | 74 | Stub `ArchMmu` impl returning `Err("unsupported")` |
| `unsupported.rs` | 48 | Stub `ArchPlatform` halting the CPU |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  rust_main                                                       │
│    arch::platform_name()    arch::boot_info()                    │
│    arch::init_cpu_tables()  arch::init_interrupts()              │
│    arch::init_timer()       arch::enable_interrupts()            │
│    arch::enter_runtime()    arch::halt_loop()                    │
└───────────────────────┬──────────────────────────────────────────┘
                        │  static dispatch via PLATFORM: &dyn ArchPlatform
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
  arch::x86 backend root   arch::aarch64 backend root   UnsupportedPlatform
     (x86 / x86_64)              (AArch64)               (stub: loop hlt)
          │                            │
          │                            ├─ aarch64_dtb
          │                            ├─ aarch64_pl011
          │                            ├─ aarch64_vectors
          │                            ├─ aarch64_virt
          │                            └─ aarch64_runtime
          │
          ├─ x86_legacy
          ├─ x86_runtime
          └─ x86_64_runtime
```

```
┌─────────────────────────────────────────────────────┐
│  arch::mmu (stable cross-arch interface)            │
│  PhysAddr · PageAttribute · ArchMmu trait           │
│  alloc_user_pages · map_user_range_phys             │
│  new_jit_sandbox · flush_tlb_page · flush_tlb_all   │
└──────────┬───────────────┬──────────────────────────┘
           ▼               ▼
   mmu_x86_64          mmu_aarch64
   4-level PT           L0–L3 4K pages
   CoW (bit 9)          MAIR/TCR config
   JIT sandbox          TTBR0/TTBR1
```

---

## Boot Abstraction — `mod.rs`

### `BootProtocol`

```rust
pub enum BootProtocol {
    Unknown,
    Multiboot1,
    Multiboot2,
}
```

### `BootInfo`

`BootInfo` is the normalised handoff from the bootloader-specific parsing code to the rest of the kernel. It contains only raw pointers and optional values; no heap allocation.

```rust
pub struct BootInfo {
    pub protocol:             BootProtocol,
    pub raw_boot_magic:       Option<u32>,   // MB1 magic = 0x2BADB002, MB2 = 0x36D76289
    pub raw_info_ptr:         Option<usize>, // MB1/MB2 info structure address
    pub cmdline_ptr:          Option<usize>, // kernel command line C string
    pub boot_loader_name_ptr: Option<usize>, // bootloader name C string
    pub acpi_rsdp_ptr:        Option<usize>, // ACPI RSDP physical address (x86 path)
    pub dtb_ptr:              Option<usize>, // Device Tree Blob address (AArch64 path)
}
```

`BootInfo` methods:

| Method | Description |
|---|---|
| `cmdline_str()` | Bounded scan of `cmdline_ptr` → `Option<&'static str>` |
| `boot_loader_name_str()` | Bounded scan of `boot_loader_name_ptr` → `Option<&'static str>` |

Both methods scan at most `MAX_BOOT_STRING_BYTES = 1024` bytes to prevent unbounded memory walks on malformed bootloader structures.

### `ArchPlatform` Trait

```rust
pub trait ArchPlatform {
    fn name(&self) -> &'static str;
    fn boot_info(&self) -> BootInfo { BootInfo::default() }
    fn init_cpu_tables(&self);           // GDT/TSS (x86) or TTBR setup (AArch64)
    fn init_trap_table(&self);           // IDT (x86) or VBAR_EL1 (AArch64)
    fn init_interrupt_controller(&self); // 8259A PIC (x86) or GICv2 init (AArch64)
    fn init_interrupts(&self) {          // default: calls init_trap_table + init_interrupt_controller
        self.init_trap_table();
        self.init_interrupt_controller();
    }
    fn init_timer(&self);                // PIT (x86) or generic timer EL1 (AArch64)
    fn enable_interrupts(&self);         // STI (x86) or MSR DAIF clear (AArch64)
    fn halt_loop(&self) -> !;            // CLI + HLT loop (x86) or WFI loop (AArch64)
}
```

The module provides top-level free functions that forward to a `static PLATFORM: &dyn ArchPlatform` selected at compile time:

In the current layout, those calls are owned by `arch::x86` on x86-family targets and by `arch::aarch64` on AArch64. `mod.rs` stays as the stable facade that selects the backend and keeps the old leaf-file names available during the transition.

| Free Function | Forwards To |
|---|---|
| `platform_name()` | `ArchPlatform::name` |
| `boot_info()` | `ArchPlatform::boot_info` |
| `init_cpu_tables()` | `ArchPlatform::init_cpu_tables` |
| `init_interrupts()` | `ArchPlatform::init_interrupts` |
| `init_trap_table()` | `ArchPlatform::init_trap_table` |
| `init_interrupt_controller()` | `ArchPlatform::init_interrupt_controller` |
| `init_timer()` | `ArchPlatform::init_timer` |
| `enable_interrupts()` | `ArchPlatform::enable_interrupts` |
| `halt_loop()` | `ArchPlatform::halt_loop` |

Additionally, `enter_runtime() -> !` and `shell_loop() -> !` are arch-gated free functions (not trait methods) dispatched directly:

```
cfg(x86)       → x86_runtime::enter_runtime / x86_runtime::shell_loop
cfg(x86_64)    → x86_64_runtime::enter_runtime / x86_64_runtime::run_serial_shell
cfg(aarch64)   → aarch64_runtime::enter_runtime
cfg(unknown)   → halt_loop()
```

---

## MMU Subsystem — `mmu.rs`

`mmu.rs` defines the cross-arch page-table interface and routes all calls to the active MMU backend at compile time. The types `PhysAddr` and `AddressSpace` are re-exported from the backend so the rest of the kernel uses a single type regardless of architecture.

### `PhysAddr`

```rust
#[repr(transparent)]
pub struct PhysAddr(usize);

impl PhysAddr {
    pub const fn new(raw: usize) -> Self
    pub const fn as_usize(self) -> usize
    pub const fn as_u64(self) -> u64
    pub const fn is_zero(self) -> bool
    pub fn try_as_u32(self) -> Result<u32, &'static str>
}
```

`PhysAddr` is a zero-cost wrapper that prevents physical/virtual address confusion. `try_as_u32` returns an error if the address exceeds 32-bit range (relevant on x86 32-bit targets).

### `PageAttribute`

```rust
pub enum PageAttribute {
    Writable,
}
```

Currently the only non-execute attribute expressible through the abstract interface. Architecture-specific implementations map this to `PTE_WRITABLE` (x86) or `DESC_AP_EL0_RW` (AArch64).

### `ArchMmu` Trait

```rust
pub trait ArchMmu {
    type AddressSpace: Send + Sync + 'static;
    type PageTable:    Send + Sync + 'static;

    fn name(&self) -> &'static str;
    fn init(&self) -> Result<(), &'static str>;
    fn page_size(&self) -> usize;
    fn kernel_page_table_root_addr(&self) -> Option<usize>;
    fn current_page_table_root_addr(&self) -> usize;
    fn set_page_table_root(&self, phys_addr: usize) -> Result<(), &'static str>;
    fn flush_tlb_page(&self, virt_addr: usize);
    fn flush_tlb_all(&self);
    fn set_page_attribute_range(&self, virt_addr, size, attr, enabled) -> Result<()>;
    fn set_page_writable_range(&self, virt_addr, size, writable) -> Result<()>; // default impl
}
```

### Public MMU Functions

| Function | Description |
|---|---|
| `backend_name()` | Name string from the active MMU backend |
| `init()` | Initialise the MMU backend (called once at boot) |
| `page_size()` | Page size in bytes (4096 for all targets) |
| `kernel_page_table_root_addr()` | Physical address of the kernel root page table, if identifiable |
| `current_page_table_root_addr()` | Physical address of the currently loaded page table |
| `set_page_table_root(phys_addr)` | Load a page-table root (CR3 on x86-64, TTBR0_EL1 on AArch64) |
| `flush_tlb_page(virt_addr)` | Invalidate one TLB entry (INVLPG on x86-64, `tlbi vaae1is` on AArch64) |
| `flush_tlb_all()` | Full TLB flush |
| `set_page_attribute_range(...)` | Set a page attribute over a virtual address range |
| `set_page_writable_range(...)` | Convenience wrapper for the `Writable` attribute |
| `new_jit_sandbox()` | Create an `AddressSpace` pre-configured for JIT-compiled code isolation |
| `alloc_user_pages(space, virt, pages, exec)` | Allocate `pages` pages at virtual address `virt` in user space |
| `map_user_range_phys(space, virt, phys, bytes, writable)` | Map a physical range into a user address space |
| `unmap_page(space, virt_addr)` | Remove a single page mapping |
| `map_mmio_identity_range(phys, size)` | Create an identity mapping for MMIO regions (x86-64 only, no-op elsewhere) |

#### Debug/Diagnostic (x86-64)

```rust
pub(crate) fn handle_page_fault(fault_addr, error) -> bool   // true = handled by CoW
pub(crate) fn x86_64_debug_mark_page_cow(virt_addr)
pub(crate) fn x86_64_debug_virt_to_phys(virt_addr) -> Option<usize>
pub(crate) fn x86_64_debug_pf_stats() -> (u64, u64, u64)     // (faults, cow, copies)
pub(crate) fn x86_64_debug_recover_stats() -> (...)
```

#### Debug/Diagnostic (AArch64)

```rust
pub(crate) fn aarch64_alloc_debug_page() -> Result<usize>
pub(crate) fn aarch64_debug_virt_to_phys(virt_addr) -> Option<usize>
pub(crate) fn aarch64_debug_walk(virt_addr) -> (root, l0, l1, l2, l3, phys)
```

---

### x86-64 MMU Backend — `mmu_x86_64.rs`

Implements 4-level IA-32e paging with a 512-entry pool of pre-allocated page tables (`BOOT_PT_POOL_PAGES = 1024` pages). Supports Copy-on-Write using the software-available PTE bit 9 (`PTE_COW_SOFT`).

#### PTE Flags

| Constant | Bit | Meaning |
|---|---|---|
| `PTE_PRESENT` | 0 | Page is present |
| `PTE_WRITABLE` | 1 | Page is writable |
| `PTE_USER` | 2 | Accessible in user mode |
| `PTE_PS` | 7 | 2 MiB huge page |
| `PTE_COW_SOFT` | 9 | Software CoW marker |
| `PTE_NX` | 63 | No-execute |

#### `AddressSpace` (x86-64)

```rust
pub struct AddressSpace {
    pub fn current() -> Self              // capture currently loaded CR3
    pub fn new() -> Result<Self>          // allocate fresh PML4
    pub fn new_jit_sandbox() -> Result<Self>   // JIT-region pre-mapped space
    pub fn clone_cow(&mut self) -> Result<Self> // CoW fork
    pub fn page_table_root_addr(&self) -> usize
    pub fn phys_addr(&self) -> usize
    pub unsafe fn activate(&self)         // mov cr3, ...
    pub fn virt_to_phys(&self, virt_addr) -> Option<usize>
    pub fn is_mapped(&self, virt_addr) -> bool
    pub fn map_user_range_phys(...)
    pub fn alloc_user_pages(virt, pages, exec) -> Result<()>
    pub fn map_page(virt, phys, writable, exec) -> Result<()>
    pub fn unmap_page(&mut self, virt_addr) -> Result<()>
}
```

**CoW fork sequence:**
1. `clone_cow` copies the PML4 and marks all writable leaves `PTE_COW_SOFT | !PTE_WRITABLE`.
2. On write fault, `handle_page_fault` detects `PTE_COW_SOFT`, copies the physical page, maps the copy writable in the faulting address space, and returns `true`.
3. The kernel page fault handler re-enters the faulting instruction.

**`extern "C"` helpers for assembly linkage:**

```rust
pub extern "C" fn set_page_flags(pte_addr, flags)
pub extern "C" fn clear_page_flags(pte_addr, flags)
pub extern "C" fn mark_page_cow(pte_addr)
pub extern "C" fn is_page_cow(pte_value) -> u32
pub extern "C" fn clear_page_cow(pte_addr)
pub extern "C" fn atomic_set_page_flags(pte_addr, flags)
pub extern "C" fn atomic_clear_page_flags(pte_addr, flags)
pub extern "C" fn copy_page_fast(src, dst)
pub extern "C" fn copy_page_physical(src_phys, dst_phys)
pub extern "C" fn zero_page(addr)
pub extern "C" fn zero_page_fast(addr)
pub extern "C" fn page_fault_handler()
pub extern "C" fn disable_paging()
pub extern "C" fn get_page_fault_count() -> u32
pub extern "C" fn get_cow_fault_count() -> u32
pub extern "C" fn get_page_copy_count() -> u32
```

---

### AArch64 MMU Backend — `mmu_aarch64.rs`

Implements AArch64 4-level (L0→L1→L2→L3) translation with 4 KiB granule. Both TTBR0_EL1 (user/process) and TTBR1_EL1 (kernel) are supported. MAIR and TCR are configured once at boot.

#### MAIR Configuration

| Attribute Index | Memory Type |
|---|---|
| `0` | Normal Write-Back/Write-Allocate (MAIR = `0xFF`) |
| `1` | Device nGnRnE (MAIR = `0x00`) |

```
MAIR_VALUE = 0x00_00_00_00_00_00_00_FF
```

#### TCR_EL1 Configuration

| Field | Value | Meaning |
|---|---|---|
| `T0SZ` | 16 | 48-bit VA for TTBR0 (EL0) |
| `T1SZ` | 16 | 48-bit VA for TTBR1 (EL1) |
| `IRGN0/1` | Write-Back WA | Inner cacheability |
| `ORGN0/1` | Write-Back WA | Outer cacheability |
| `SH0/1` | Inner Shareable | Shareability |
| `TG0/TG1` | 4 KiB | Granule size |
| `IPS` | 40-bit | Intermediate physical address size |

#### Descriptor Flags

| Constant | Bit | Meaning |
|---|---|---|
| `DESC_VALID` | 0 | Entry is valid |
| `DESC_TABLE_OR_PAGE` | 1 | Table or page (not block) |
| `DESC_AF` | 10 | Access flag |
| `DESC_SH_INNER` | 8–9 | Inner shareable |
| `DESC_AP_EL1_RW` | 6–7 = 00 | EL1 read-write |
| `DESC_AP_EL0_RW` | 6–7 = 01 | EL0 read-write |
| `DESC_AP_EL1_RO` | 6–7 = 10 | EL1 read-only |
| `DESC_AP_EL0_RO` | 6–7 = 11 | EL0 read-only |
| `DESC_ATTRIDX_NORMAL` | 2–4 = 0 | Normal memory |
| `DESC_ATTRIDX_DEVICE` | 2–4 = 1 | Device memory |
| `DESC_PXN` | 53 | Privileged execute never |
| `DESC_UXN` | 54 | Unprivileged execute never |

`MAX_LIVE_PT_SCAN_TABLES = 2048` limits the scan depth during debug walks.

#### `AddressSpace` (AArch64)

```rust
pub struct AddressSpace {
    pub fn new() -> Result<Self>                  // fresh user-space L0
    pub fn new_from_kernel_root() -> Result<Self>
    pub fn new_kernel_template() -> Result<Self>
    pub fn new_jit_sandbox() -> Result<Self>
    pub fn page_table_root_addr(&self) -> usize   // TTBR0_EL1 value
    pub fn phys_addr(&self) -> usize
    pub unsafe fn activate(&self)                 // MSR TTBR0_EL1, ISB
    pub fn virt_to_phys(&self, virt_addr) -> Option<usize>
    pub fn is_mapped(&self, virt_addr) -> bool
    pub fn map_user_range_phys(...)
    pub fn alloc_user_pages(...)
    pub fn map_page(virt, phys, writable, exec) -> Result<()>
    pub fn unmap_page(&mut self, virt_addr) -> Result<()>
}
```

#### Debug Walk

```rust
pub(crate) struct DebugWalk {
    pub root_phys: usize,
    pub l0_desc:   u64,
    pub l1_desc:   u64,
    pub l2_desc:   u64,
    pub l3_desc:   u64,
    pub phys_addr: Option<usize>,
}

pub(crate) fn debug_translate_current(virt_addr) -> Option<usize>
pub(crate) fn debug_walk_current(virt_addr) -> DebugWalk
```

---

### x86 Legacy MMU Shim — `mmu_x86_legacy.rs`

On `target_arch = "x86"`, `AddressSpace` is simply type-aliased to `crate::fs::paging::AddressSpace`, which is the existing 32-bit two-level page directory implementation from the original kernel. This shim is intentionally minimal — the 32-bit paging abstraction lives in `kernel/src/paging/`, and `mmu_x86_legacy.rs` just ensures the `AddressSpace` type is available through the `arch::mmu` path.

---

## FPU Context — `fpu.rs`

FPU/SIMD state save and restore for context switching. The implementation is arch-gated into three compile paths.

### `ExtFpuState`

```rust
pub struct ExtFpuState(pub [u8; 2816]);

impl ExtFpuState {
    pub const fn new() -> Self   // zero-initialised
}
```

2,816 bytes is sufficient for the XSAVE area on x86-64 (512 bytes for legacy FXSAVE + AVX extension state) and for ARM NEON/FP register context.

### Functions

```rust
// Save the current FPU/SIMD state into `buf` (must be 16-byte aligned).
pub unsafe fn save_fpu_state_ext(buf: *mut u8)

// Restore FPU/SIMD state from `buf`.
pub unsafe fn restore_fpu_state_ext(buf: *const u8)

// Initialise FPU to a defined state (called once per new thread/process).
pub unsafe fn init_fpu_state()
```

#### x86-64 Implementation

Uses `FXSAVE64` / `FXRSTOR64` instructions operating on a 512-byte `FXSAVE` area. `init_fpu_state` executes `FNINIT` to reset the x87 control word and then zeros the XMM registers via `XORPS`.

#### AArch64 Implementation

Saves and restores the 32 128-bit NEON/FP registers (`q0`–`q31`) plus `FPCR` and `FPSR` using `STP` pairs. `init_fpu_state` zeroes all FP registers and sets `FPCR` to the default round-to-nearest mode.

#### Unsupported Targets

`save_fpu_state_ext`, `restore_fpu_state_ext`, and `init_fpu_state` are no-ops on unsupported targets.

---

## x86 Platform

### Multiboot Boot Layer — `x86_legacy.rs`

`x86_legacy.rs` implements `ArchPlatform` for the `x86` and `x86_64` targets using the Multiboot1 and Multiboot2 boot protocols. The `X86LegacyPlatform` struct holds no state; all boot information is extracted once and stored in a kernel-global `BootInfo` at handoff time.

#### Multiboot Constants

| Constant | Value | Meaning |
|---|---|---|
| `MULTIBOOT1_BOOTLOADER_MAGIC` | `0x2BADB002` | MB1 magic in EBX |
| `MULTIBOOT2_BOOTLOADER_MAGIC` | `0x36D76289` | MB2 magic in EBX |
| `MB1_FLAG_CMDLINE` | `1 << 2` | MB1 info has command line |
| `MB1_FLAG_BOOT_LOADER_NAME` | `1 << 9` | MB1 info has loader name |
| `MB2_TAG_END` | `0` | MB2 tag list terminator |
| `MB2_TAG_CMDLINE` | `1` | MB2 command line tag |
| `MB2_TAG_BOOT_LOADER_NAME` | `2` | MB2 loader name tag |
| `MB2_TAG_ACPI_OLD` | `14` | MB2 ACPI 1.0 RSDP tag |
| `MB2_TAG_ACPI_NEW` | `15` | MB2 ACPI 2.0 RSDP tag |

MB2 tags are 8-byte aligned (`align_up_8` constant fn). The parser iterates the tag list until `MB2_TAG_END`.

#### Boot Handoff

```rust
pub extern "C" fn arch_x86_record_boot_handoff(magic: u32, info_ptr: u32)
```

Called from the 32-bit assembly entry stub (`_start`) immediately at boot. Parses the magic/info-pointer pair and populates the global `BootInfo`. `BootProtocol::Multiboot1` or `Multiboot2` is set accordingly.

---

### x86 Runtime — `x86_runtime.rs`

Implements `enter_runtime()` and `shell_loop()` for `target_arch = "x86"` (32-bit protected mode).

#### Serial Console

| Constant | Value | Description |
|---|---|---|
| `COM1_BASE` | `0x3F8` | I/O base port for COM1 |
| `COM_LSR` | `0x3FD` | Line Status Register |
| `COM_DATA` | `0x3F8` | Data register (TX/RX) |

The COM1 driver is a polled-mode send loop checking the LSR transmit-empty bit before each byte write.

#### Job Table

```rust
const JOB_TABLE_MAX: usize = 8;

pub fn print_jobs()          // dump job table to serial
pub fn fg_last_job() -> bool // bring most-recent background job to foreground
```

`enter_runtime()` — performs the final kernel initialisation sequence for 32-bit x86: enables paging, sets up the TSS, installs the IDT, and transfers control to the scheduler/shell.

`shell_loop()` — runs an interactive command shell over the COM1 serial port.

---

### x86-64 Runtime — `x86_64_runtime.rs`

The most complete runtime implementation. Handles the full x86-64 descriptor table setup, 8259A PIC configuration, PS/2 keyboard decoding, trap/interrupt dispatch, and the serial shell.

#### Segment Selectors

| Constant | Value | Description |
|---|---|---|
| `KERNEL_CS` | `0x08` | 64-bit kernel code segment |
| `KERNEL_DS` | `0x10` | 64-bit kernel data segment |
| `USER_CS` | `0x1B` | 64-bit user code segment (RPL=3) |
| `USER_DS` | `0x23` | 64-bit user data segment (RPL=3) |
| `TSS_SELECTOR` | `0x28` | TSS descriptor (double-word entry) |

#### PIC 8259A Ports

| Constant | Value |
|---|---|
| `PIC1_CMD` | `0x20` |
| `PIC1_DATA` | `0x21` |
| `PIC2_CMD` | `0xA0` |
| `PIC2_DATA` | `0xA1` |
| `PIC_EOI` | `0x20` (End-of-Interrupt) |

#### PS/2 and Keyboard

| Constant | Value |
|---|---|
| `PS2_DATA` | `0x60` |
| `PS2_STATUS` | `0x64` |
| `KBD_FLAG_RELEASE` | `1 << 0` |
| `KBD_FLAG_DECODED` | `1 << 1` |
| `KBD_FLAG_E0_PREFIX` | `1 << 2` |
| `KBD_FLAG_EXTENDED` | `1 << 3` |
| `KBD_FLAG_SHIFT` | `1 << 4` |

#### IDT Gate Types

| Constant | Value | Description |
|---|---|---|
| `IDT_TYPE_INTERRUPT_GATE` | `0x8E` | DPL0 interrupt gate |
| `IDT_TYPE_INTERRUPT_GATE_DPL3` | `0xEE` | DPL3 interrupt gate (user syscall) |

#### `TrapFrameHead64`

```rust
pub(crate) struct TrapFrameHead64 {
    // Saved general-purpose registers pushed by the IDT stubs
    // EIP, CS, EFLAGS, (optionally RSP + SS for privilege change)
}
```

Used by `x86_64_trap_dispatch` and the JIT fault path.

#### CPU Table Management

```rust
pub fn init_cpu_tables()                       // GDT + TSS install
pub fn update_kernel_stack_top(rsp0: usize)    // update TSS.RSP0
pub fn update_jit_kernel_stack_top(rsp0: usize)// update TSS.RSP0 for JIT path
pub fn init_trap_table()                       // install IDT (256 entries)
pub fn init_interrupt_controller()             // PIC remap (master → 0x20, slave → 0x28)
pub fn init_timer()                            // PIT channel 0 at ~100 Hz
pub fn enable_interrupts()                     // STI
```

#### Trap Dispatch

```rust
pub extern "C" fn x86_64_trap_dispatch(vector: u64, error: u64, frame: *mut TrapFrameHead64)
```

Dispatches all 256 IDT vectors. Exceptions 0–31 are decoded to `WasmError` trap codes or forwarded to the page-fault handler. Vectors 32–47 are the remapped PIC IRQs (timer at IRQ0 → vector 32, keyboard at IRQ1 → vector 33). Vector 128 is the user-mode software interrupt gate.

#### Diagnostic Functions

```rust
pub fn exception_count(vector: u8) -> u64  // per-vector exception count
pub fn irq_count(irq: u8) -> u64           // per-IRQ count
pub fn last_vector() -> u8                 // most recent vector delivered
pub fn last_error() -> u64                 // most recent error code
pub fn trigger_breakpoint()                // INT3
pub fn read_ctrl_regs() -> (u64, u64, u64) // CR0, CR2, CR3
pub fn read_efer() -> u64                  // IA32_EFER MSR
```

#### Shell and Self-Test

```rust
pub fn enter_runtime() -> !         // boot into kernel main loop
pub fn run_serial_shell() -> !      // interactive shell over COM1
pub fn wait_for_ticks(min_delta, max_spin_hlt) -> bool  // timer busy-wait
pub fn self_test_traps_and_timer()  // verify IDT, PIT, timer counts
pub fn vector_has_error_code(vector: u8) -> bool
```

The shell responds to commands including `help`, `ticks`, `irq0`, `int3`, `traps`, `pfstats`, `cowtest`, and `vmtest`.

#### Job Table

Identical to the x86 variant:

```rust
const JOB_TABLE_MAX: usize = 8;
pub fn print_jobs()
pub fn fg_last_job() -> bool
pub(crate) static mut FOREGROUND_PID: Option<Pid>
```

---

## AArch64 Platform

### Device Tree Blob Parser — `aarch64_dtb.rs`

Implements a full FDT/DTB (Flattened Device Tree) parser without heap allocation. The parser discovers memory, interrupt controller, UART, timer, and VirtIO-MMIO devices from the tree.

#### FDT Token Constants

| Constant | Value | Meaning |
|---|---|---|
| `FDT_MAGIC` | `0xD00DFEED` | DTB magic number |
| `FDT_BEGIN_NODE` | `1` | Node begin token |
| `FDT_END_NODE` | `2` | Node end token |
| `FDT_PROP` | `3` | Property token |
| `FDT_NOP` | `4` | NOP token |
| `FDT_END` | `9` | Structure block end |
| `MIN_DTB_SIZE` | `40` bytes | Minimum valid DTB |
| `MAX_DTB_SIZE` | `16 MiB` | Safety cap on DTB size |
| `MAX_TREE_DEPTH` | `16` | Parser stack depth |

#### Device Discovery Limits

| Constant | Value |
|---|---|
| `MAX_BUS_RANGES` | `8` |
| `MAX_INTERRUPT_CONTROLLERS` | `16` |
| `MAX_VIRTIO_MMIO_DEVICES` | `16` |

#### Device Class Bitmask

| Constant | Bit | Device |
|---|---|---|
| `CLASS_PL011` | `1 << 0` | ARM PL011 UART |
| `CLASS_GICV2` | `1 << 1` | ARM GICv2 interrupt controller |
| `CLASS_TIMER` | `1 << 2` | ARM generic timer |
| `CLASS_VIRTIO_MMIO` | `1 << 3` | VirtIO MMIO device |

#### Output Types

```rust
pub(crate) struct DtbHeaderInfo {
    pub ptr:               usize,
    pub total_size:        usize,
    pub off_dt_struct:     usize,
    pub off_dt_strings:    usize,
    pub off_mem_rsvmap:    usize,
    pub version:           u32,
    pub last_comp_version: u32,
    pub size_dt_strings:   usize,
    pub size_dt_struct:    usize,
}

pub(crate) struct DtbRange { pub base: usize, pub size: usize }

pub(crate) struct DtbMmioIrqDevice {
    pub base:       usize,
    pub size:       usize,
    pub irq_intid:  Option<u32>,
}

pub(crate) struct DtbPlatformInfo {
    pub header:                DtbHeaderInfo,
    pub memory:                Option<DtbRange>,
    pub uart_pl011_base:       Option<usize>,
    pub uart_pl011_irq_intid:  Option<u32>,
    pub gic_dist_base:         Option<usize>,
    pub gic_cpu_base:          Option<usize>,
    pub timer_irq_intid:       Option<u32>,
    pub virtio_mmio:           [DtbMmioIrqDevice; 16],
    pub virtio_mmio_count:     usize,
    pub chosen_bootargs_ptr:   Option<usize>,
    pub chosen_bootargs_len:   usize,
}
```

#### Functions

```rust
pub(crate) fn parse_dtb_header(ptr_addr: usize) -> Option<DtbHeaderInfo>
pub(crate) fn parse_platform_info(ptr_addr: usize) -> Option<DtbPlatformInfo>
pub(crate) fn bootargs_str(ptr: Option<usize>, len: usize) -> Option<&'static str>
pub(crate) fn is_valid_dtb(ptr_addr: usize) -> bool
```

`parse_platform_info` performs a single-pass depth-first traversal of the FDT structure block. It recognises the following `compatible` strings: `arm,pl011`; `arm,cortex-a15-gic` / `arm,gic-400`; `arm,armv8-timer`; `virtio,mmio`. Each matched node extracts `reg` (base and size) and `interrupts` (IRQ interrupt ID).

---

### PL011 UART — `aarch64_pl011.rs`

A full-featured driver for the ARM PrimeCell PL011 UART with a 2 KiB software receive ring buffer and interrupt-driven RX.

#### Register Map

| Constant | Offset | Register |
|---|---|---|
| `DR` | `0x00` | Data register (TX write / RX read) |
| `FR` | `0x18` | Flag register |
| `CR` | `0x30` | Control register |
| `IMSC` | `0x38` | Interrupt mask set/clear |
| `RIS` | `0x3C` | Raw interrupt status |
| `MIS` | `0x40` | Masked interrupt status |
| `ICR` | `0x44` | Interrupt clear register |

#### Flag and Control Bits

| Constant | Value | Meaning |
|---|---|---|
| `FR_RXFE` | `1 << 4` | RX FIFO empty |
| `FR_TXFF` | `1 << 5` | TX FIFO full |
| `CR_UARTEN` | `1 << 0` | UART enable |
| `CR_TXE` | `1 << 8` | TX enable |
| `CR_RXE` | `1 << 9` | RX enable |
| `INT_RX` | `1 << 4` | RX interrupt |
| `INT_RT` | `1 << 6` | RX timeout interrupt |

`QEMU_VIRT_PL011_BASE = 0x0900_0000` is the base address for the PL011 on the standard QEMU `virt` machine map.

#### `Pl011` Driver

```rust
pub(crate) struct Pl011 {
    pub const fn new(base: usize) -> Self

    pub fn init_early(&self)              // enable UART + TX + RX
    pub fn write_byte(&self, b: u8)       // polled TX (spin on FR_TXFF)
    pub fn write_str(&self, s: &str)
    pub fn try_read_byte(&self) -> Option<u8>          // direct register read
    pub fn try_read_buffered_byte(&self) -> Option<u8> // from ring buffer
    pub fn irq_drain_rx_to_buffer(&self) -> usize      // drain FIFO → ring; returns count
    pub fn enable_rx_interrupts(&self)   // set INT_RX | INT_RT in IMSC
    pub fn disable_interrupts(&self)     // clear IMSC
    pub fn ack_interrupts(&self)         // write ICR
    pub fn masked_interrupt_status(&self) -> u32
    pub fn raw_interrupt_status(&self) -> u32
    pub fn interrupt_mask(&self) -> u32
    pub fn flags(&self) -> u32
    pub fn rx_buffer_len(&self) -> usize
    pub fn rx_buffer_dropped(&self) -> u64  // bytes dropped due to full buffer
    pub fn base(&self) -> usize
    pub fn set_base(&self, base: usize)     // runtime base relocation after DTB parse
}

pub(crate) fn early_uart() -> &'static Pl011
```

`RX_BUF_CAPACITY = 2048` bytes. `irq_drain_rx_to_buffer` is called directly from the GICv2 IRQ handler on the PL011 interrupt ID.

---

### Exception Vectors — `aarch64_vectors.rs`

Installs the AArch64 exception vector table at a 2 KiB-aligned address and dispatches incoming exceptions to the kernel.

#### Layout

```
VECTOR_TABLE_BYTES = 2048   (0x800)
Slots = 16  (4 exception levels × {SError, FIQ, IRQ, Sync})
Each slot = 128 bytes = 32 instructions
```

#### `VectorSlot` Enum

```rust
pub(crate) enum VectorSlot {
    CurrentEl_SpEl0_Sync,
    CurrentEl_SpEl0_Irq,
    CurrentEl_SpEl0_Fiq,
    CurrentEl_SpEl0_SError,
    CurrentEl_SpElx_Sync,
    CurrentEl_SpElx_Irq,
    CurrentEl_SpElx_Fiq,
    CurrentEl_SpElx_SError,
    LowerEl_Aarch64_Sync,
    LowerEl_Aarch64_Irq,
    // ... 16 total slots
}
```

#### ESR_EL1 Exception Class Codes

| Constant | Value | Exception |
|---|---|---|
| `EC_SVC64` | `0x15` | `SVC` from AArch64 |
| `EC_HVC64` | `0x16` | `HVC` from AArch64 |
| `EC_SMC64` | `0x17` | `SMC` from AArch64 |
| `EC_BRK64` | `0x3C` | `BRK` instruction |
| `EC_FP_ASIMD_TRAP` | `0x07` | FP/SIMD access trap |

ESR extraction: `EC = (ESR_EL1 >> ESR_EC_SHIFT) & ESR_EC_MASK` where `ESR_EC_SHIFT = 26` and `ESR_EC_MASK = 0x3F`.

#### `LastExceptionSnapshot`

```rust
pub(crate) struct LastExceptionSnapshot {
    pub slot:     u8,
    pub esr_el1:  u64,
    pub elr_el1:  u64,   // return address
    pub spsr_el1: u64,
    pub far_el1:  u64,   // faulting address (data abort / instruction abort)
}
```

#### Functions

```rust
pub(crate) fn vector_base() -> usize
pub(crate) fn install_stub_vectors()           // write 2 KiB stub table, set VBAR_EL1
pub(crate) fn vectors_installed() -> bool

pub extern "C" fn oreulius_aarch64_vector_dispatch(slot: u8, esr: u64, elr: u64, spsr: u64, far: u64)

pub(crate) fn trigger_breakpoint()             // BRK #0
pub(crate) fn sync_exception_count() -> u64
pub(crate) fn brk_exception_count() -> u64
pub(crate) fn vector_count(slot: u8) -> u64   // per-slot exception count
pub(crate) fn last_exception_snapshot() -> LastExceptionSnapshot
pub(crate) fn last_brk_snapshot() -> LastExceptionSnapshot
pub(crate) fn last_brk_imm16() -> u16         // BRK immediate from ISS field
pub(crate) fn last_exception_ec() -> u8
pub(crate) fn dump_last_exception()            // print to UART
```

---

### QEMU Virt Platform — `aarch64_virt.rs`

The largest single file in the arch module at 3,226 lines. Implements the full `AArch64QemuVirtPlatform` including GICv2, ARM generic timer, VirtIO-MMIO device enumeration and block I/O, and a cooperative scheduler integration hook.

#### Fallback Physical Addresses

Used when DTB is not available or does not contain the expected entries:

| Constant | Value | Device |
|---|---|---|
| `QEMU_VIRT_GICD_BASE_FALLBACK` | `0x0800_0000` | GIC Distributor |
| `QEMU_VIRT_GICC_BASE_FALLBACK` | `0x0801_0000` | GIC CPU Interface |
| `QEMU_VIRT_MEM_BASE_FALLBACK` | `0x4000_0000` | RAM base (1 GiB) |
| `QEMU_VIRT_MEM_SIZE_FALLBACK` | `512 MiB` | RAM size |

#### Timer

```
TIMER_HZ = 100       (100-Hz tick rate)
HEARTBEAT_TICKS = 100  (1-second heartbeat)
```

Timer uses the AArch64 generic timer `CNTP_CTL_EL0`/`CNTP_CVAL_EL0`/`CNTFRQ_EL0` system registers. The interrupt ID is read from the DTB `arm,armv8-timer` node.

#### GICv2 Distributor Registers

| Constant | Offset | Register |
|---|---|---|
| `GICD_CTLR` | `0x000` | Distributor control |
| `GICD_TYPER` | `0x004` | Interrupt controller type |
| `GICD_ISENABLER0` | `0x100` | Interrupt set-enable |
| `GICD_ICENABLER0` | `0x180` | Interrupt clear-enable |
| `GICD_ISPENDR0` | `0x200` | Set-pending |
| `GICD_ICPENDR0` | `0x280` | Clear-pending |
| `GICD_IPRIORITYR` | `0x400` | Priority registers |
| `GICD_ITARGETSR` | `0x800` | Target CPU mask |
| `GICD_ICFGR` | `0xC00` | Edge / level configuration |

#### GICv2 CPU Interface Registers

| Constant | Offset | Register |
|---|---|---|
| `GICC_CTLR` | `0x000` | CPU interface control |
| `GICC_PMR` | `0x004` | Priority mask |
| `GICC_BPR` | `0x008` | Binary point |
| `GICC_IAR` | `0x00C` | Interrupt acknowledge |
| `GICC_EOIR` | `0x010` | End of interrupt |
| `GICC_RPR` | `0x014` | Running priority |
| `GICC_HPPIR` | `0x018` | Highest pending interrupt |

`GIC_SPURIOUS_INTID_MIN = 1020` — interrupt IDs ≥ 1020 are spurious and are not dispatched.

#### VirtIO-MMIO Constants

| Constant | Value |
|---|---|
| `VIRTIO_MMIO_MAGIC_EXPECTED` | `0x74726976` ("virt") |
| `VIRTIO_MMIO_VERSION_LEGACY` | `1` |
| `VIRTIO_MMIO_DEVICE_ID_NET` | `1` |
| `VIRTIO_MMIO_DEVICE_ID_BLOCK` | `2` |
| `VIRTIO_QUEUE_ALIGN_BYTES` | `4096` |
| `VIRTIO_QUEUE_SIZE_TARGET` | `8` entries |
| `VIRTIO_BLK_SECTOR_SIZE` | `512` bytes |
| `VIRTIO_BLK_SYNC_WAIT_SPINS` | `2,000,000` spin iterations |
| `MAX_TRACKED_VIRTIO_MMIO` | `16` devices |

#### VirtIO Block I/O

```rust
pub(crate) fn virtio_blk_shared_present() -> bool
pub(crate) fn virtio_blk_shared_capacity_sectors() -> Option<u64>
pub(crate) fn virtio_blk_shared_read_sector(sector, buf: &mut [u8; 512]) -> bool
pub(crate) fn virtio_blk_shared_write_sector(sector, buf: &[u8; 512]) -> bool
```

I/O uses the virtqueue split ring (descriptor, available, used). The `DRIVER_OK` status sequence follows the VirtIO 1.x legacy specification (version register = 1).

#### Platform Discovery Functions

```rust
pub(crate) fn uart() -> &'static Pl011
pub(crate) fn early_log(msg: &str)
pub(crate) fn for_each_discovered_virtio_mmio(mut f: impl FnMut(base, size, irq))
pub(crate) fn discovered_dtb_ptr() -> Option<usize>
pub(crate) fn discovered_memory_range() -> Option<(base, size)>
pub(crate) fn discovered_gicv2_bases() -> Option<(gicd, gicc)>
pub(crate) fn discovered_timer_intid() -> u32
pub(crate) fn timer_ticks() -> u64
pub(crate) fn timer_frequency_hz() -> u64
pub(crate) fn timer_irq_count() -> u64
pub(crate) fn last_irq_id() -> u32
pub(crate) fn enable_fp_simd_access()
```

#### System Register Accessors

```rust
pub(crate) fn read_currentel() -> u64  // CURRENTEL
pub(crate) fn read_daif() -> u64       // DAIF interrupt mask
pub(crate) fn read_sctlr_el1() -> u64
pub(crate) fn read_vbar_el1() -> u64
```

#### Scheduler Integration

```rust
pub(crate) fn scheduler_timer_tick_hook()
pub(crate) fn scheduler_note_context_switch(pid: u32) -> Result<(), &'static str>
```

`scheduler_timer_tick_hook` is called at every 10ms timer IRQ (100Hz). It increments the tick counter, toggles the heartbeat LED at 1Hz, and calls `wasm_runtime().on_timer_tick()` if the WASM runtime is initialised.

#### Boot Handoff

```rust
pub extern "C" fn arch_aarch64_record_boot_handoff(dtb_ptr: usize)
```

Called from the AArch64 assembly entry (`_start_aarch64`) immediately on boot before the stack is initialised. Stores the DTB pointer for later parsing in `init_cpu_tables`.

#### Self Test

```rust
pub(crate) fn self_test_sync_exception()  // trigger BRK, verify vector dispatch
pub(crate) fn handle_irq_exception(_slot: u8)
pub(crate) fn run_serial_shell() -> !
```

---

### AArch64 Runtime — `aarch64_runtime.rs`

```rust
pub fn enter_runtime() -> !
```

`enter_runtime` is the AArch64 counterpart to the x86 equivalent. It:

1. Calls `install_stub_vectors()` if vectors are not yet installed
2. Enables FP/SIMD access via `enable_fp_simd_access()`
3. Calls `init()` on the memory subsystem
4. Transfers control to the WASM runtime or the serial shell based on compile-time feature flags

---

## Unsupported Arch Stub — `unsupported.rs`

```rust
pub(super) struct UnsupportedPlatform;
pub(super) static PLATFORM: UnsupportedPlatform = UnsupportedPlatform;
```

`UnsupportedPlatform` implements all `ArchPlatform` methods as no-ops except `halt_loop()` which executes an infinite `loop {}`. This ensures the kernel compiles on any target Rust supports, producing a binary that safely spins rather than executing undefined platform code.

---

## Feature Matrix

| Feature | `x86` (i686) | `x86_64` | `aarch64` | Unsupported |
|---|---|---|---|---|
| `ArchPlatform` impl | `X86LegacyPlatform` | `X86LegacyPlatform` | `AArch64QemuVirtPlatform` | `UnsupportedPlatform` |
| Boot protocol | MB1 + MB2 | MB1 + MB2 | FDT/DTB | — |
| Interrupt controller | 8259A PIC | 8259A PIC | GICv2 | — |
| Serial console | COM1 (16550) | COM1 (16550) | PL011 | — |
| Timer | PIT 8253 | PIT 8253 | ARM generic timer | — |
| MMU backend | `paging::AddressSpace` | 4-level IA-32e | L0–L3 4 KiB | stub `Err` |
| Page size | 4 KiB | 4 KiB | 4 KiB | — |
| Huge pages | — | 2 MiB (PTE_PS) | 2 MiB (L2 block) | — |
| CoW fork | — | yes (`PTE_COW_SOFT`) | — | — |
| JIT sandbox | yes | yes | yes (stub) | — |
| FPU save | FXSAVE (512 B) | FXSAVE (512 B) | NEON 32×128 | no-op |
| Exception vectors | IDT (256) | IDT (256) | VBAR_EL1 (16) | — |
| VirtIO block | — | — | MMIO legacy v1 | — |
| DTB/FDT parsing | — | — | yes (full) | — |
| ACPI RSDP | MB2 tag | MB2 tag | — | — |
| Shell | COM1 serial | COM1 serial | PL011 serial | — |
| `enter_runtime()` | `x86_runtime` | `x86_64_runtime` | `aarch64_runtime` | `halt_loop` |
| `shell_loop()` | `x86_runtime` | `x86_64_runtime::run_serial_shell` | — | — |

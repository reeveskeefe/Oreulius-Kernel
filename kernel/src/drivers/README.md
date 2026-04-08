# `drivers` — Hardware Driver Subsystem

This module contains the hardware-driver boundary for the Oreulius kernel:
raw I/O-port access, interrupt-driven input, display plumbing, and the GPU
subsystem. The top-level facade now routes to `drivers::x86` for the current
x86-family hardware tree and to `drivers::aarch64` for the explicit minimal
AArch64 root. The old flat module list remains available through that facade
so existing call sites keep compiling during the transition.

---

## File Map

| Path | Lines | Purpose |
|---|---|---|
| `mod.rs` | 21 | Public facade; target selection boundary; compatibility re-exports |
| `x86/mod.rs` | 39 | x86-family hardware-driver root; current concrete modules |
| `aarch64/mod.rs` | 12 | Minimal AArch64 driver root |
| `pci.rs` | 663 | PCI bus enumeration, configuration-space I/O, device-name table |
| `vga.rs` | 323 | VGA text-mode driver (80×25, MMIO 0xB8000) |
| `framebuffer.rs` | 1 208 | Linear framebuffer + 8×16 bitmap-font console |
| `keyboard.rs` | 809 | PS/2 keyboard: IRQ1, lock-free ring, scancode translation |
| `mouse.rs` | 397 | PS/2 AUX mouse + USB HID mouse; lock-free event ring |
| `input.rs` | 358 | Unified `InputEvent` queue; WASM host functions 38–44 |
| `audio.rs` | 848 | Intel HDA + AC'97 fallback; CORB/RIRB; BDL ping-pong |
| `bluetooth.rs` | 579 | Bluetooth USB HCI transport; LE scan; ACL data |
| `usb.rs` | 4 425 | UHCI / OHCI / EHCI / xHCI; USB enumeration; Mass Storage BOT/SCSI |
| `compositor.rs` | 933 | Layer-based compositing WM; ARGB8888 alpha blend; WASM hooks 28–37 |
| `acpi_asm.rs` | 339 | RSDP/FADT parsing; S0–S5 sleep states; C/P-states; thermal |
| `dma_asm.rs` | 265 | ISA DMA channels 0–7; scatter-gather descriptors |
| `memopt_asm.rs` | 307 | Cache flush/prefetch; non-temporal copies; SSE; CRC32/AES-NI |
| `GPUsupport/` | ~5 000 | Universal GPU substrate (owned by the x86-family driver root) |

---

## PCI Bus (`pci.rs`)

### Configuration-Space Access

PCI configuration space on x86 is accessed through two I/O ports:

| Port | Width | Role |
|---|---|---|
| `0xCF8` | 32-bit | CONFIG_ADDRESS — write the target address |
| `0xCFC` | 32-bit | CONFIG_DATA — read or write the selected register |

The 32-bit address word is:

```
bit 31   : enable bit (must be 1)
bits 23:16: bus number (0–255)
bits 15:11: device/slot (0–31)
bits 10:8 : function (0–7)
bits 7:2  : register offset (aligned to 4 bytes, low 2 bits zero)
```

```rust
let address: u32 = 0x80000000
    | ((bus   as u32) << 16)
    | ((slot  as u32) << 11)
    | ((func  as u32) <<  8)
    | ((offset & 0xFC) as u32);
x86::io::outl(PCI_CONFIG_ADDRESS, address);
let data = x86::io::inl(PCI_CONFIG_DATA);
```

8-bit and 16-bit reads are implemented by masking the 32-bit result:

```rust
fn pci_config_read_u16(bus, slot, func, offset) -> u16 {
    let val = pci_config_read_u32(bus, slot, func, offset);
    ((val >> ((offset & 2) * 8)) & 0xFFFF) as u16
}
```

### `PciDevice`

Every discovered device is stored as a flat `PciDevice`:

```rust
pub struct PciDevice {
    pub bus, slot, func: u8,
    pub vendor_id, device_id: u16,
    pub class_code, subclass, prog_if, revision: u8,
    pub interrupt_line, interrupt_pin: u8,
}
```

A absent device is signalled by `vendor_id == 0xFFFF` (the "invaid vendor"
sentinel guaranteed by the PCI specification).

### PCI Class Hierarchy (FIPS PCI class table)

| `class_code` | Meaning |
|---|---|
| `0x01` | Mass storage (subclass `0x08`/prog-if `0x02` = NVMe) |
| `0x02` | Network (`0x00`=Ethernet, `0x80`=Other) |
| `0x03` | Display controller (GPU) |
| `0x04` | Multimedia / audio |
| `0x0C`/`0x03` | USB host controller |

`PciDevice::is_*` predicates check these fields directly.

### Scanner

`PciScanner::scan()` iterates all 32 slots on bus 0, calling
`probe_device(0, slot, 0)` for each.  The scan is limited to `MAX_PCI_DEVICES = 32`
entries.  Multi-function devices (header type bit 7 set) and bridge-discovered
secondary buses are not yet enumerated — this is a straightforward early-boot
scanner, not a full topology walker.

### Bus Mastering and BAR Access

Before a device can initiate DMA or respond to MMIO reads, two command-register
bits must be set:

- Bit 1 — **Memory Space Enable** — allows MMIO accesses to the BAR ranges
- Bit 2 — **Bus Master Enable** — allows the device to generate PCI transactions

```rust
pub unsafe fn enable_bus_mastering(&self) {
    let cmd = pci_config_read_u16(bus, slot, func, 0x04);
    pci_config_write_u32(bus, slot, func, 0x04, (cmd | 0x04) as u32);
}
```

BAR (`Base Address Register`) values are at configuration offsets
`0x10 + bar_index * 4`.  The driver uses `read_bar(index)` to retrieve the
base address, which may be either MMIO or I/O port depending on bit 0.

---

## VGA Text Mode (`vga.rs`)

### Memory Layout

The VGA text buffer is a 80×25 array of 2-byte cells mapped at physical
address `0xB8000`:

```
byte 0: ASCII character (cp437)
byte 1: color attribute = (background << 4) | foreground
```

Color attributes are 4-bit palette indices (0–15), encoded in `ColorCode` as
`(bg << 4) | fg`.

### `Writer`

`Writer` holds a reference to `&'static mut Buffer` at `0xB8000` and tracks
`(row_position, column_position)`.  On line overflow `new_line()` is called,
which scrolls the whole buffer one row upward by copying rows 1..25 to 0..24
and blanking row 24.

The global `WRITER: Mutex<Writer>` provides a `core::fmt::Write` implementation,
so `write!` / `format_args!` work without heap allocation.

### VGA Macros

```rust
vga_print!(...);
vga_println!(...);
```

Both macros delegate to `_print(args: fmt::Arguments)`, which mirrors output
to both the serial port and the terminal layer (allowing output to appear on
both the VGA console and any attached UART).

### CRT Controller Cursor

The hardware text cursor position is programmed through the CRT Controller:
ports `0x3D4` (index) and `0x3D5` (data).  Cursor registers:

- `0x0E` / `0x0F` — high/low byte of the cursor linear position
  (`row * 80 + col`)

---

## Linear Framebuffer (`framebuffer.rs`)

### Pixel Formats

The driver supports four encoding modes:

| `PixelFormat` | `bytes_per_pixel` | Encoding |
|---|---|---|
| `Bgrx32` | 4 | `[B][G][R][0]` — common on QEMU/KVM VESA |
| `Xrgb32` | 4 | `[0][R][G][B]` — common on UEFI GOP |
| `Bgr24` | 3 | `[B][G][R]` — 24-bit VBE modes |
| `Rgb565` | 2 | 5R 6G 5B packed — embedded |

`PixelFormat::encode(r, g, b) -> u32` converts an (R, G, B) triple into the
raw word for the given format.  For RGB565:

```
r5 = r >> 3;  g6 = g >> 2;  b5 = b >> 3;
pixel = (r5 << 11) | (g6 << 5) | b5
```

### `FramebufferInfo` and Pixel Addressing

Pixel (x, y) is at byte offset:

```
offset = y × pitch + x × bytes_per_pixel
```

where `pitch` (bytes per scan line) may be larger than `width × bpp/8` due
to hardware alignment padding.  The `byte_size = pitch × height` formula gives
the correct DMA allocation size.

### Drawing Primitives

All draw operations (`put_pixel`, `fill_rect`, `draw_rect`, `blit`) are
bounds-checked; out-of-range coordinates are silently dropped.  Writes use
`core::ptr::write_volatile` to prevent the compiler from eliding what looks
like dead stores to MMIO:

```rust
core::ptr::write_volatile(ptr as *mut u32, raw);
```

### Framebuffer Console

`FramebufferConsole` overlays a bitmapped text console (8×16 font, printable
ASCII 0x20–0x7E) on the raw framebuffer.  The font is a hand-coded
`FONT_8X16: [[u8; 16]; 95]` table — each entry is 16 rows of 8 monochrome
pixels, MSB = leftmost pixel.

Glyphs are rendered by testing each bit:

```
for row in 0..16:
    for col in 0..8:
        if FONT[glyph_idx][row] & (0x80 >> col) != 0:
            put_pixel(x + col, y + row, fg_r, fg_g, fg_b)
```

`scroll_up` copies the physical framebuffer scan-lines upward with
`core::ptr::copy` (memmove semantics) and clears the vacated bottom rows —
the only path that does a raw memcopy directly into MMIO.

---

## PS/2 Keyboard (`keyboard.rs`)

### I8042 Controller Interface

The PS/2 keyboard controller (`i8042`) uses two I/O ports:

| Port | R/W | Description |
|---|---|---|
| `0x60` | R | Read scan code / data |
| `0x60` | W | Send command to keyboard |
| `0x64` | R | Read status register |
| `0x64` | W | Send command to controller |

Status register bit 0 = **Output Buffer Full** (data available to read).
Status register bit 1 = **Input Buffer Full** (busy, must not write).

### Initialisation Sequence

1. Disable keyboard port (`0xAD` to 0x64)
2. Read controller config byte (`0x20` to 0x64)
3. Set bit 0 (IRQ1 enable) and bit 6 (translation to Set 1)
4. Clear bit 4 (un-disable keyboard) and bit 5 (disable AUX/mouse IRQ)
5. Write config byte back (`0x60` to 0x64)
6. Re-enable keyboard port (`0xAE` to 0x64)
7. Reset keyboard (`0xFF`), wait for ACK/self-test result

Translation mode (bit 6 of config) means the controller converts Set 2 scan
codes to Set 1 before delivery, so the driver works with Set 1 by default.

### Lock-Free Buffers

Both the raw byte buffer and the decoded event buffer are implemented as
SPSC ring buffers protected purely by `AtomicUsize` head/tail indices (no
`Mutex`), making them safe to push from interrupt context and pop from
process context simultaneously.

```
struct KeyBuffer {
    buf:  UnsafeCell<[u8; 256]>,
    head: AtomicUsize,   // pop side
    tail: AtomicUsize,   // push side (IRQ)
}
```

A push is: compute `next_tail = (tail + 1) % N`; if `next_tail != head`
write and store the new tail; otherwise drop and increment `DROPPED_PACKETS`.

### Scancode Handling

The `handle_scancode` logic:

1. `0xE0` sets the `EXTENDED` flag — the next byte is an extended key code
2. `0xF0` sets `RELEASE_PREFIX` (Set 2 release sequence — ignored in translated mode)
3. For non-extended codes: bit 7 = release, bits 0–6 = make code
4. Extended keys (arrows, Home, End, Delete, PageUp/Down) are decoded after
   the `EXTENDED` flag is set
5. Modifier keys (`Shift`, `Ctrl`, `Alt`, `CapsLock`) update atomic boolean flags
6. Character keys are looked up in `SCANCODE_MAP` and `SCANCODE_MAP_SHIFT` tables
7. The result is a `KeyEvent::{Char, Enter, Backspace, Tab, Escape, Ctrl, AltFn, Up, Down, ...}`

Dropped packets are signalled at the top-right corner of the VGA text buffer
(direct write to 0xB8000) as "DROP!" in red-on-white, without acquiring any lock.

---

## PS/2 Mouse + USB HID Mouse (`mouse.rs`)

### PS/2 AUX Protocol

The PS/2 mouse is attached to the PS/2 controller's auxiliary (AUX) port.
Commands are routed to it by first sending `0xD4` (write-to-aux) to port
`0x64`, then the command byte to port `0x60`:

```rust
cmd(0xD4);   // route to AUX
data(0x60);  // set sample rate
```

**Initialisation:**

1. Enable AUX device (`0xA8` to 0x64)
2. Enable AUX IRQ (bit 1) in the controller config byte
3. `0xFF` (reset) → wait for `0xAA 0x00` (pass + device-id)
4. `0xF6` (set defaults)
5. Detect IntelliMouse: `0xF3 0xC8`, `0xF3 0x64`, `0xF3 0x50` clocking −
   if GET DEVICE ID returns `0x03` then 4-byte packets are enabled (wheel)
6. `0xF4` (enable data reporting)

### Standard 3-Byte Packet

```
byte 0: flags   bit7=y-overflow, bit6=x-overflow, bit5=y-sign, bit4=x-sign
                bit3=1 (always), bit2=middle, bit1=right, bit0=left
byte 1: x movement (low 8 bits; bit4 of byte0 is the 9th sign bit)
byte 2: y movement (low 8 bits; bit5 of byte0 is the 9th sign bit)
```

9-bit signed delta with sign extension:

```rust
let dx = (self.raw[1] as i16) | ((self.raw[0] as i16 & 0x10) << 4);
let dy = (self.raw[2] as i16) | ((self.raw[0] as i16 & 0x20) << 3);
```

Overflow bits (bits 6/7) indicate wrap-around; the driver discards packets
with overflow set.

### USB HID Mouse

`submit_usb_report(report: UsbMouseReport)` converts a HID boot-class mouse
report into a `MouseEvent` and pushes it into the same lock-free event ring,
providing a single consumer interface regardless of the hardware source
(PS/2 vs. USB HID).

---

## Unified Input Queue (`input.rs`)

### `InputEvent` Layout

```rust
#[repr(C)]
pub struct InputEvent {
    pub kind: InputEventKind,   // u8: None=0, Key=1, Mouse=2, Gamepad=3
    _pad: [u8; 3],
    pub data: InputEventData,   // union: KeyInputEvent | MouseInputEvent | raw[u8; 8]
}
```

The union is 8 bytes wide for a total struct size of 12 bytes (aligned to 4).

### `pump()`

Called from both IRQ handlers and the scheduler tick, `pump()` drains:

1. `keyboard::EVENT_BUFFER` → converts `KeyEvent` to `InputEvent` with
   codepoint, scancode, modifiers bitmask
2. `mouse::EVENT_RING` → wraps `MouseEvent` as `InputEvent`

and pushes everything into `INPUT_RING`, the single authoritative queue for
all user input.

### WASM Host Functions (IDs 38–44)

| ID | Name | Semantics |
|---|---|---|
| 38 | `input_poll` | Returns 1 if any event pending; 0 if empty |
| 39 | `input_read(ptr, len)` | Copies one `InputEvent` into WASM memory; returns bytes written |
| 40 | `input_event_type` | Peek `kind` byte of head event; –1 if empty |
| 41 | `input_flush` | Discard all pending events; returns count |
| 42 | `input_key_poll` | Poll, ignoring non-keyboard events |
| 43 | `input_mouse_poll` | Poll, ignoring non-mouse events |
| 44 | `input_gamepad_poll` | Reserved; always 0 |

---

## Intel HDA + AC'97 Audio (`audio.rs`)

### Architecture

```
PCI scan (class 0x04 / sub 0x03)
    ├── Intel HDA  (ICH6+, device 0x2668 and later)
    └── AC'97      (0x8086:0x2415 — QEMU ICH0/ICH2)
```

### Intel HDA — CORB / RIRB

The HDA hardware provides a **Command Output Ring Buffer (CORB)** and a
**Response Input Ring Buffer (RIRB)** for communicating with audio codecs:

- CORB: 256 × 4-byte command words.  MMIO registers: `CORBLBASE/CORBUBASE`
  (64-bit physical address), `CORBWP` (write pointer), `CORBRP` (read
  pointer), `CORBCTL` (run bit).
- RIRB: 256 × 8-byte response words (64-bit: 32-bit response + 32-bit
  solicited response bit).  Registers: `RIRBLBASE/RIRBUBASE`, `RIRBWP`, `RIRBCTL`.

HDA verbs are 32-bit words: `[31:28] codec + [27:20] node + [19:8] verb + [7:0] payload`.

Key verbs used:
- `GET_PARAM` (`0xF00`) — read codec/widget capabilities
- `SET_STREAM_CH` (`0x706`) — assign a stream number to a widget
- `SET_AMP_GAIN` (`0x300`) — set amplifier gain/mute
- `WIDGET_CONTROL` (`0x707`) — enable output EAPD, set PIN mode

### HDA Buffer Descriptor List (BDL)

A **Buffer Descriptor List** entry is:

```c
struct BdlEntry {
    addr_lo: u32,   // physical address, low 32 bits
    addr_hi: u32,   // physical address, high 32 bits
    length:  u32,   // buffer length in bytes
    ioc:     u32,   // interrupt-on-completion flag (bit 0)
}
```

The driver uses 2 entries (ping-pong): while the hardware is playing buffer 0,
the CPU fills buffer 1, swapping at each IOC interrupt.  Each buffer is 16 384
bytes = 4 096 stereo samples at 16-bit depth.

**HDA PCM format word** for 48 kHz 16-bit stereo:

```
bit 14: BASE=1 (48 kHz base clock)
bits 12:11: MULT=0 (×1 multiplier)
bits 10:8: DIV=0 (/1 divider)
bits 6:4: BITS=001 (16-bit)
bits 3:0: CHAN=0001 (2 channels)
→ 0x0011
```

### AC'97 Fallback

AC'97 uses separate **Native Audio Mixer (NAM)** and **Native Audio Bus
Master (NABM)** I/O base addresses obtained from PCI BAR0 and BAR1.  Startup:
write `0x02` to NABM register `0x2C` (Global Control, AC_RESET bit) then poll
until CODEC_READY.  PCM output uses a 32-entry BDL in NABM register group 0x10.

---

## USB Host Controller (`usb.rs`)

### Controller Hierarchy

```
UsbBus (kernel façade)
    ├── UhciController    I/O-port based; frame list; TD/QH linked lists
    ├── OhciController    MMIO; HCCA; ED/TD circular lists
    ├── EhciController    MMIO; async QH schedule; qTD descriptors
    └── XhciController    MMIO; BIOS hand-off; xHCI event ring (port detect only)
```

Identified by PCI class `0x0C` / subclass `0x03`:

| `prog-if` | Standard | Speed |
|---|---|---|
| `0x00` | UHCI | Full (12 Mb/s) + Low (1.5 Mb/s) |
| `0x10` | OHCI | Full (12 Mb/s) + Low |
| `0x20` | EHCI | High (480 Mb/s) |
| `0x30` | xHCI | Super (5 / 10 / 20 Gb/s) |

### USB Device Descriptor

The standard 18-byte `UsbDeviceDescriptor` (`bLength=18`, `bDescriptorType=1`)
is obtained via a `GET_DESCRIPTOR` control transfer (setup packet:
`bmRequestType=0x80, bRequest=6, wValue=0x0100, wIndex=0, wLength=18`).

### Transfer Types

- **Control transfer** — SETUP + optional DATA + STATUS; used for
  enumeration (SET_ADDRESS, GET_DESCRIPTOR) and class-specific commands
- **Bulk transfer** — variable-size data blocks; UHCI uses TD linked lists,
  EHCI uses qTD chained to a QH in the async schedule
- **Interrupt transfer** — periodic polling (mouse, HID); UHCI uses the
  frame list to schedule periodic TDs

### USB Mass Storage (BOT/SCSI)

`MassStorageDevice` implements the Bulk-Only Transport protocol:

```
host → OUT: CBW (Command Block Wrapper, 31 bytes)
              bCBWSignature = 0x43425355 ("USBC")
              dCBWTag, dCBWDataTransferLength, bmCBWFlags, bCBWLUN
              CBWCB[16] — SCSI CDB
host ↔ data: payload transfers (IN for reads, OUT for writes)
host ← IN:  CSW (Command Status Wrapper, 13 bytes)
              bCSWSignature = 0x53425355 ("USBS")
              dCSWTag, dCSWDataResidue, bCSWStatus
```

SCSI commands implemented: `INQUIRY (0x12)`, `TEST UNIT READY (0x00)`,
`READ CAPACITY(10) (0x25)`, `READ(10) (0x28)`, `WRITE(10) (0x2A)`.

---

## Compositor (`compositor.rs`)

### Layer Model

Each window is a `Layer` with:
- `x, y` — screen position of the top-left corner
- `width, height` — dimensions in pixels
- `z_order` — depth (higher = closer to viewer)
- `visible: bool`
- Pixel buffer in ARGB8888 format, allocated from the kernel JIT arena

The kernel supports up to `MAX_LAYERS = 16` simultaneous windows.

### Alpha Compositing

Layers are painted back-to-front (sorted by `z_order`) into a shadow buffer.
For each pixel, the compositor applies standard over-operator alpha blending:

```
out = src × (α / 255) + dst × (1 - α / 255)
```

With integer arithmetic at 8-bit precision: `α = 255` is fully opaque
(no blending cost), `α = 0` produces no contribution.

### JIT Arena Pixel Buffers

Pixel storage is dynamically allocated from the kernel JIT page arena via
`memory::jit_allocate_pages(pages)`.  A `PixelBufPool` table of 16 slots
tracks allocations; slots are reused (zeroed) when a window is destroyed
rather than freed — the JIT arena is bump-allocated and does not support
individual page release.

### WASM Host Functions (IDs 28–37)

| ID | Function | Signature |
|---|---|---|
| 28 | `compositor_create_window` | `(x,y,w,h) → window_id` |
| 29 | `compositor_destroy_window` | `(wid) → i32` |
| 30 | `compositor_set_pixel` | `(wid,x,y,argb) → ()` |
| 31 | `compositor_fill_rect` | `(wid,x,y,w,h,argb) → ()` |
| 32 | `compositor_flush` | `(wid) → ()` — blit to physical FB |
| 33 | `compositor_move_window` | `(wid,x,y) → ()` |
| 34 | `compositor_set_z_order` | `(wid,z) → ()` |
| 35 | `compositor_get_width` | `(wid) → i32` |
| 36 | `compositor_get_height` | `(wid) → i32` |
| 37 | `compositor_draw_text` | `(wid,x,y,ptr,len,argb) → i32` |

---

## Bluetooth (`bluetooth.rs`)

### HCI Over USB

Bluetooth controllers expose themselves as USB class `0xE0` / subclass `0x01`
/ protocol `0x01`.  The HCI is layered directly over the USB device:

| USB endpoint | Direction | HCI usage |
|---|---|---|
| EP0 | Control (host→device) | HCI command packets |
| EP1 (interrupt IN) | Device→host | HCI event packets |
| EP2 (bulk) | Bidirectional | HCI ACL data |

HCI opcodes are 16-bit little-endian words:
`opcode = (OGF << 10) | (OCF & 0x03FF)`.

The OGF (Opcode Group Field) groups:

| OGF | Group |
|---|---|
| `0x01` | Link Control |
| `0x03` | Controller & Baseband |
| `0x04` | Informational Parameters |
| `0x08` | LE Controller |

### Startup Sequence

1. `HCI_RESET` (OGF=0x03, OCF=0x0003) → wait for `HCI_COMMAND_COMPLETE` event
2. `HCI_READ_BD_ADDR` (OGF=0x04, OCF=0x0009) → store in `bd_addr`
3. For LE scanning:
   - `LE_SET_SCAN_PARAMETERS` (passive, 100 ms interval/window)
   - `LE_SET_SCAN_ENABLE` (true)
   - `poll()` loop decodes `HCI_LE_META` / `LE_ADVERTISING_REPORT` sub-events
     into `BluetoothEvent::LeAdvertReport(BluetoothDevice)`

`BluetoothDevice` captures: 6-byte `BdAddr`, RSSI as `i8`, `is_le` flag, and
the first 8 bytes of advertising data.

---

## ACPI (`acpi_asm.rs`)

### Table Discovery

The **Root System Description Pointer (RSDP)** is located by scanning the
memory range `0xE0000–0xFFFFF` for the 8-byte signature `"RSD PTR "`.  The
RSDP points to the RSDT (Root System Description Table), which is an array
of 32-bit physical addresses to ACPI tables identified by 4-byte signatures.

`acpi_find_table(rsdt_addr, signature)` iterates the RSDT to locate a specific
table (e.g., `"FACP"` for the FADT, `"APIC"` for the MADT).

### FADT Layout (Selected Fields)

```
offset 36: FIRMWARE_CTRL  u32
offset 40: DSDT           u32
offset 48: SMI_CMD        u32
offset 52: ACPI_ENABLE    u8
offset 53: ACPI_DISABLE   u8
offset 56: PM1a_EVT_BLK   u32
offset 64: PM1a_CNT_BLK   u32   ← power management control register I/O base
```

### Sleep State Entry (S5 / Soft-Off)

To enter the S5 (soft off) state:

1. Read the `SLP_TYP_A` value from the `\_S5_` DSDT method (vendor-specific,
   typically `0x07`)
2. Write `(SLP_TYP_A << 10) | PM1_SLP_EN(1 << 13)` to `PM1a_CNT_BLK`

For S3 (suspend-to-RAM) and S4 (suspend-to-disk) the value differs and
firmware must be consulted for the correct `SLP_TYP` values.

### C-States and P-States

C-states lower CPU power by halting the clock:
- `C1`: `HLT` instruction (software halt)
- `C2`: Write to `P_LVL2` I/O port (read from FADT)
- `C3`: Write to `P_LVL3` I/O port; requires flushing the L2 cache

P-states (frequency/voltage scaling) are set through the `PERF_CTL` MSR
(`IA32_PERF_CTL`, address `0x199`) with the target P-state encoded in bits 15:0.

---

## DMA Controller (`dma_asm.rs`)

### ISA DMA Channels

The PC/AT DMA architecture provides 8 channels split across two Intel 8237
DMA controllers:

| Channels | Width | Common use |
|---|---|---|
| 0–3 | 8-bit | Floppy, ISA sound cards |
| 4–7 | 16-bit | DMA cascade, some ISA peripherals |

Channel 4 is permanently dedicated to cascading DMA1 into DMA0.

`DmaMode` bits are combined as:
- Direction: `READ (0x04)` (memory→I/O) or `WRITE (0x08)` (I/O→memory)
- Mode: `SINGLE (0x40)`, `BLOCK (0x80)`, `DEMAND (0x00)`, `CASCADE (0xC0)`
- Flags: `AUTO_INIT (0x10)` (circular), `ADDR_DECREMENT (0x20)`

### Scatter-Gather

`dma_scatter_gather` programs a chain of `DmaDescriptor` entries:

```rust
pub struct DmaDescriptor {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub length:   u32,
    pub next:     *mut DmaDescriptor,  // null-terminated list
}
```

---

## Memory Optimisation (`memopt_asm.rs`)

### Non-Temporal Store Operations

Non-temporal writes (`MOVNTI`, `MOVNTQ`) write directly to main memory,
bypassing the L1/L2/L3 caches.  This is faster for large sequential copies
where the destination will not be immediately re-read:

```rust
pub unsafe fn copy(dst: *mut u8, src: *const u8, count: usize) {
    memcpy_nt(dst, src, count as u32);
}
```

`memcpy_nt_sse` processes 64-byte chunks using SSE2 non-temporal stores
(16 bytes × 4 per iteration).  `memcpy_nt_avx` uses 256-bit AVX registers
(32 bytes × 4).

### Cache Management

- `cache_flush_line(addr)` — `CLFLUSH`; writes back and invalidates one cache line
- `cache_flush_all()` — `WBINVD`; write-back and invalidate all cache (ring-0 only)
- `cache_prefetch(addr, T0)` — `PREFETCHTx`; hint for a future load

Locality levels map to x86 prefetch hints: `T0`=all levels, `T1`=L2+,
`T2`=L3+, `NTA`=non-temporal (avoid cache pollution for streaming data).

### Hardware Acceleration (SSE4.2 / AES-NI)

- `crc32_hw(crc, data, len)` — uses `CRC32` instruction (SSE4.2)
- `strlen_sse`, `strcmp_sse`, `memchr_sse` — use `PCMPESTRM`/`PCMPISTRI`
  string processing instructions (SSE4.2)
- `aes_encrypt_block`, `aes_decrypt_block` — use `AESENC`/`AESDEC` (AES-NI),
  bypassing the software AES implementation in `crypto/mod.rs`

---

## Universal GPU Substrate (`GPUsupport/`)

### Five-Tier Capability Model

Every GPU is assigned a tier at probe time.  Higher tiers require proven
capability and are never guessed:

| Tier | Enum | Meaning |
|---|---|---|
| 0 | `ProbeOnly` | Safe detection only — no drawing |
| 1 | `Scanout` | Linear framebuffer / compositor backend |
| 2 | `Transfer2D` | Normalised 2D transfer path (blits, fills) |
| 3 | `Compute` | Normalised compute path |
| 4 | `Optimized` | Vendor-specific acceleration (Intel/AMD/NVIDIA) |

The kernel **never attempts brandless MMIO command inference** on unknown
hardware.  Unrecognised devices receive the highest tier that can be
proven safe (usually Tier 1 if a linear framebuffer is available).

### Submodule Map

| Submodule | Role |
|---|---|
| `core.rs` | `GpuTier`, `GpuClass`, `GpuProbeReport`, `GpuBarInfo` |
| `caps.rs` | `GpuCapabilities`, `GpuEngineMask` capability bitfields |
| `probe.rs` | PCI scan → `probe_all(mb2_ptr) → [Option<GpuProbeReport>; N]` |
| `registry.rs` | Singleton active backend + probe report store |
| `backend.rs` | `GpuBackend` trait (activate, deactivate) |
| `drivers/simplefb.rs` | Simple linear framebuffer (MB2 tag or PCI BAR0) |
| `drivers/bochs.rs` | Bochs VBE Extensions (BGA) MMIO registers |
| `drivers/qxl.rs` | QEMU QXL paravirtual |
| `drivers/virtio_gpu.rs` | VirtIO GPU (virtqueues over PCI) |
| `drivers/amd/` | AMD RDNA/GCN family (stub) |
| `drivers/intel/` | Intel Gen4+ (stub) |
| `drivers/nvidia/` | NVIDIA Turing/Ampere (stub) |
| `display/modeset.rs` | Mode selection and mode-set logic |
| `display/scanout.rs` | `ScanoutDevice`, `PresentTarget`, active-target registry |
| `display/edid.rs` | EDID parsing (monitor preferred resolution) |
| `display/cursor.rs` | Hardware cursor management |
| `display/damage.rs` | Dirty-region tracking for partial recomposition |
| `engines/compute.rs` | Compute job submission |
| `engines/transfer.rs` | 2D transfer (copy/fill) submission |
| `engines/scheduler.rs` | GPU command queue scheduler |
| `engines/packets.rs` | `CommandPacket`, `ComputePacket`, `TransferPacket` |
| `memory/bo.rs` | `BufferObject` — GPU memory handle |
| `memory/aperture.rs` | GART / VRAM aperture management |
| `memory/mapper.rs` | CPU↔GPU address mapping |
| `memory/cache.rs` | GPU cache coherency helpers |
| `transport/dma.rs` | GPU DMA burst transfers |
| `transport/fence.rs` | `GpuFence` — GPU/CPU synchronisation primitive |
| `transport/irq.rs` | GPU interrupt handler |
| `transport/mmio.rs` | Type-safe MMIO register accessors |
| `firmware/loader.rs` | GPU firmware binary loading |
| `firmware/manifest.rs` | Firmware manifest verification |
| `firmware/verify.rs` | Cryptographic firmware signature check |
| `security/iommu.rs` | IOMMU DMA remapping for GPU isolation |
| `security/isolation.rs` | Per-GPU capability isolation |
| `security/audit.rs` | GPU command audit log |
| `telemetry/counters.rs` | GPU performance counters |
| `topology.rs` | Multi-GPU topology (primary/secondary) |
| `tests/` | Unit tests: fake GPU, fence, probe, scanout, transfer |

### Initialisation Flow

```
gpu_support::init(mb2_ptr)
    ├── registry::clear()
    ├── probe::probe_all(mb2_ptr)
    │       ├── probe VirtIO GPU (PCI 0x1AF4:0x1050)
    │       ├── probe QXL (PCI 0x1B36:0x0100)
    │       ├── probe Bochs BGA (PCI 0x1234:0x1111)
    │       └── probe SimpleFB (Multiboot2 framebuffer tag)
    ├── register all GpuProbeReports
    ├── best_probe_report() → sort by tier, then by backend priority
    │       VirtioGpu > QXL > Bochs > SimpleFB > None
    └── activate_report(best)
            → drivers::<backend>::activate(mb2_ptr)
            → registry::set_active(best)
            → GPU_FB updated for compositor use
```

### `GpuFence`

A `GpuFence` is a 64-bit monotonic sequence number used to synchronise CPU
and GPU work:

- GPU writes the fence value to a mapped page when prior commands complete
- CPU spins on the mapped value or schedules a callback

The transport layer (`transport/fence.rs`) exposes `wait(timeout_ns)` and
`signal(value)` semantics on top of this.

---

## Architecture Constraint

All submodules in `drivers/` are gated:

```rust
#[cfg(not(target_arch = "aarch64"))]
pub mod <name>;
```

This prevents compilation on AArch64 QEMU-virt targets, where the
hardware model is completely different (no I/O ports, no ISA DMA, no VGA
text buffer).  An AArch64 driver layer is tracked separately.

---

## Public API Summary

```rust
// PCI
pci::PciScanner::new().scan()
pci::PciScanner::find_network_device() -> Option<PciDevice>
pci::PciScanner::find_usb_controller() -> Option<PciDevice>
pci::PciScanner::find_display_device() -> Option<PciDevice>
pci::PciScanner::find_nvme_controller() -> Option<PciDevice>
pci::PciDevice::enable_bus_mastering()
pci::PciDevice::read_bar(n: u8) -> u32

// VGA text
vga_print!(...);   vga_println!(...);
vga::write_cell(row, col, byte, fg, bg)
vga::clear_screen()

// Framebuffer
framebuffer::init_from_multiboot2(mb2_ptr)
framebuffer::init_from_pci(device: PciDevice)
framebuffer::display() -> MutexGuard<Option<Framebuffer>>
Framebuffer::put_pixel(x, y, r, g, b)
Framebuffer::fill_rect(x0, y0, w, h, r, g, b)
Framebuffer::blit(dx, dy, w, h, data: &[u8])

// Keyboard
keyboard::init()
keyboard::has_input() -> bool
keyboard::pop_event() -> Option<KeyEvent>

// Mouse
mouse::init()
mouse::pop_event() -> Option<MouseEvent>
mouse::get_state() -> MouseState
mouse::submit_usb_report(report: UsbMouseReport)

// Unified input
input::pump()
input::pop() -> Option<InputEvent>
input::peek_kind() -> InputEventKind

// Audio
audio::init()
audio::write_samples(samples: &[i16])
audio::is_playing() -> bool
audio::set_volume(vol: u8)

// USB
usb::init(pci: PciDevice)
usb::UsbBus::enumerate_devices()
usb::MassStorageDevice::read_sector(lba: u32, buf: &mut [u8; 512])
usb::MassStorageDevice::write_sector(lba: u32, buf: &[u8; 512])

// Compositor (also via WASM host functions 28–37)
compositor::compositor() -> MutexGuard<Compositor>
Compositor::create_window(x, y, w, h) -> Option<u32>
Compositor::set_pixel(wid, x, y, argb)
Compositor::flush(wid)

// GPU substrate
gpu_support::init(mb2_ptr: u32)
gpu_support::active_backend() -> ScanoutBackendId
gpu_support::with_framebuffer(f: impl FnOnce(&GpuFramebuffer))
gpu_support::GpuFence::wait(timeout_ns: u64) -> bool

// ACPI / power
acpi_asm::acpi_shutdown(pm1a_base)
acpi_asm::acpi_reboot(reset_reg_addr)
acpi_asm::acpi_enter_sleep_state(pm1a_base, sleep_type, sleep_enable)
acpi_asm::acpi_enter_c1() / acpi_enter_c2(port) / acpi_enter_c3(port)

// DMA
dma_asm::Dma::new(channel).init(buffer, count, mode)
dma_asm::Dma::start() / stop() / is_complete()

// Memory optimisation
memopt_asm::Cache::flush_line(addr)
memopt_asm::NonTemporal::copy(dst, src, count)
memopt_asm::Crc32::compute(data: &[u8]) -> u32
```

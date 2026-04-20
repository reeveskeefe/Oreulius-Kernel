# Architecture Abstraction Layer (arch)

This directory is for the boot and runtime code that the kernel relies on. This folder exposes the ArchPlatform trait that the kernel calls on for platform setup and theruntime entry. It isolates the CPU, the interrupt controller, the timer, and the differences in the MMU in order to create platform parity between the different ports. 

It is left intentionally small because it sits closest to the hardware and carries the most sensitive start up logic. 


## What the architecture boundary is

The architecture boundary is the layer that separates the kernel’s portable logic from the code that has to change for each CPU or platform. It is where the kernel handles things like boot setup, interrupts, low-level CPU state, calling conventions, and target-specific hardware differences without letting those details leak into the rest of the system. For a customer, the important part is that this boundary is what lets the same kernel design run on different machines while keeping the sensitive low-level work isolated and controlled in one place.

## Target-Specific Backends

Target-specific backends are the CPU- or platform-specific implementations that the kernel swaps in when it needs to talk to a particular machine. They handle the parts that cannot be shared across all targets, like register setup, interrupt handling, timers, firmware hooks, and low-level device access. The rest of the kernel stays portable by calling through this backend layer instead of hard-coding one architecture everywhere.


## Understanding the CPU and Platform Hooks

CPU and platform hooks are the small entry points the rest of the kernel uses when it needs to do something that depends on the machine underneath it. They cover the low-level pieces that sit right at the hardware edge, like interrupts, timers, boot setup, and target-specific CPU behavior, so the portable kernel code does not have to know the details of each architecture.

| Hook Type | What It Does |
|---|---|
| Interrupt hooks | Connect hardware interrupts to kernel handlers |
| Timer hooks | Drive time-based scheduling and wakeups |
| Boot hooks | Handle early machine setup |
| CPU hooks | Access target-specific CPU state and instructions |

Essentially it is the portable kernel code calls into the arch layer, while the arch layer chooses the right backend for the current CPU and platform. 

This means things like setting up and reading the MMU, handling interrupts and traps, reading timer ticks, exposing CPU registers and features, wiring boot/runtime setup for x86_64 and AArch64, handling platofor specific IRQ and scheduler Timing behaviour 

The current commands that are best to use with the CPU and platform hooks are as follows:

| Command | What to use it for |
|---|---|
| mmu | Show the memory management unit state and paging backend |
| regs | Show CPU register and platform state |
| traps | Show trap and exception counts |
| irqs | Show interrupt activity |
| ticks | Show the current platform tick count |
| uartirq | Show UART interrupt diagnostics |
| strict-uart-irq | Turn strict UART IRQ handling on or off |
| sched timeslice <ticks> | Set the scheduler timeslice in ticks |

It is wise to keep this command set small, so for any future dev cycles, it would not be a smart or secure choice to create any more operative commands to give to people to use to reduce security risks, only keeping what is necessary for diagnostics, and setting up the right environment for the workload. 

upon reviewing the code, IF new commands were to be made, it would have to be in compliance with these rules:

1. Inspect state that is already exposeed internally
2. Help diagnose a real failure mode 
3. Change a runtime parameter safely
4. Stays read-only unless there is a strong operator need. 

Because the architecture hooks are so close the the hardware, mistakes here become expensive. More operations than necessary here means there are more ways to break the isolation oreulius secures. Also it provides the ability to misconfigure the kernel. 

## MMU and Address Translation specifics 
This part of the kernel works by taking a virtual address from the kernel or a workload and walking the page tabes until it finds the actual physical page behind it. 

The physical page (a fixed-chunk of real ram usually around 4KB, that the kernel points memory mapping at) in the MMU and address translation acts as the storage behind the phsyical address. The kernel maps a virtual page to a phyisical page so the CPU knows where the data really lives in the memory. 

So for the MMU and address translation, the phsycal page: 
1. holds the real bytes 
2. backs a process's virtual memory 
3. gets copied during copy-on-write when needed
4. can  be mapped, unmapped, or shared by the kernel
5. is the thing that the MMU ultmiately reaches after the translation 

The overall flow for the MMU and address translaion works like this, 
1. step one: The kernel or process uses a virtual address
2. Step two: the MMU looks that address up in the active page tables
3. the page table entires tell it which physical page to use
4. The MMU does a secondary check to see whetehr access is allowed, such as read, write and if the user even has access. 
5. if it is thus valid, the CPU uses the physical page. 
6. if not, the kernel gets a page fault and decides what to do. 

This gives the kernel isolated memory per process, safe sharing through copy-on-write, controlled kernel/user seperation, and the ability to map an unmap memory deliberately. 

It works different on x86 and I686 than the AArch64 port. 

Heres a table to summarize the differences between how it effects the two different targets:
| Target | How its affected |
|---|---|
| X86_64 | uses the cr3, the page directories, and TLB flushes |
| AArch64 | uses the TTBR registers and its own page table walk. 

### TTBR Registers 
The TTBR registers are the  page-table base registers used in AArch64. They point the MMU at the current translation tables so the CPU knows where to start when translating the virtual addresses into physical ones. 

In Oreulius, the TTBR handling stays inside the architecutre and MMU layer, not inside the workload facing code. 

What keeps it protected is the registers are only touched by the kernels AARch64 MMU code, and nothing else can touch it, or ever should be allowed to touch it. 

User workloads do not get a command or syscall that exposes raw TTBR writes, this is to ensure that page table changes go through the bounded MMU functions. Suc has map, unmap and not give them durect register access. 

the arch layer checks mapping bounds and permissions efore it can be allowed to change the translation state. Then the kernel keeps user and kernel addresses spaces seperate so the workload does not get to see or rewrite the translation root directly. 

This should be completely automatic, it should not be allowed to be operated against or changed for security reasons. People gaming the system can foil even proven architecture. 

### CR3 and TLB flushes

The CR3 is an x86 register that tells the CPU what page table is currently active. After a mapping change, such as being unapped, mapped, or a permissions change. The TLB flush clears the cahced addresses, and then the lernel flushes any relevant TLB entry so the CPU can use the new CPU entry efficiently.   



## How do interrupt requests work?  (IRQ)
Interrupt requests are how the hardware gets the kernels attnetion when somehting important happens. 

Such as a timer tick arriving and the scheduler needs to run. A keyboard key is pressed, or a mouse moves or clicks. A disk read or write finishes, a UART byte arrives, or a network device signals incoming data. A page fault happens and the MMU needs help, or a devie error reports an error or status change. 

Important for the cases of an interrupt request, means the kernel needs to react to these things now, the event causing this requires and immediate and prompt action from the IRQ. 

Heres why it matters: 
1. It lets the kernel respond to hardware without busy-waiting
2. It keeps the input and device event-driven
3. it is a part of the platform hook layer so each architecture handles it in its own way. 

In Oreulius, the interrupt path stays inside the arch and platform boundary, feeds into a tightly controlled service model, and does not give workloads direct hardware access. The code is designed to keep the hot path narrow and explicit across targets.

There are several diagnostic commands for the IRQ available, heres a table explaining such and what it performs in the IRQ algorithim:

| Diagnostic Command | What it performs related to the IRQ |
|---|---|
| irqs | Shows interrupt activity and counts |
| traps | Shows trap and exception counts |
| ticks | Shows timer tick progress |
| uartirq | Shows UART interrupt diagnostics |
| strict-uart-irq | Turns strict UART IRQ handling on or off |


## The principles behind the UART byte handling
UART stands for "Universal Asynchronous Reciever And Transmitter". It is a serial byte path that the kernel uses for console input and output. This is the most heavily used on the AArch64 side of things where it is the PL011 UART is used during boot and runtime diagnostics 

>PL011 UART is a specific hardware block used on many ARM systems, and the concrete implementation on AArch64 in this context. PL011 is the UART model oreulius speaks too. PL stands for prime cell, its part of the ARM's older peripheral family name, and the 011 is the variant of this cell. It is a simple, well known and easy to bring up in early boot phases, and gives the kernel a reliable serial console for logs, shell input, and interrupt driven input handling. It is also a direct match for the virtual ARM machine Oreuliius is targeting in QEMU. 

##### Notes on UART byte handling:
It would be wise to add more UART/device bytes, when it comes time to port to various hardwares. If you are looking for a commericial license, it might be wise to tell us what AArch64 hardware platform or ARM board you are using so we can give you a package with a custom UART device that runs on your hardware, as coverage is fairly narrow and mainly on QEMU and ARM boards that use 
Contact the email `reeveskeefe@gmail.com` to disuss your needs.  


Currently it is compatible with these ARM boards: 

| Known compatible Targets | What the docs show |
|---|---|
| QEMU ARM virt | PL011 serial port discoverable via DTB |
| QEMU ARM sbsa-ref | PL011 serial port |
| Arm Juno development board | Part of the Versatile Express family, which supports PL011 UART |
| FVP_Base_RevC-2xAEMvA | Supported in the VExpress64 config with PL011 UART |
| FVP_BaseR_AEMv8R | Supported in the VExpress64 config with PL011 UART |
| Neoverse reference design FVP | Two PL011 UART controllers are present on the non-discoverable device block |
|DeveloperBox | Has a confirmed serial console path via the rear micro-USB AP UART and via a 96Boards UART mezzanine on the LS connector / UART0; PL011 also appears to be confirmed for the platform by SynQuacer DeveloperBox device-tree and kernel references.

> These boards are strictly pl011 verified, there are many others, but to avoid overstating, this list of boards are available with the PL011 UART byte in the primary documentation or is totally verified to work with the PL011 UART byte. 



#### Adding more UART hardware specific bytes for wider coverage 

Here are future UART byte support that will be needed to added in future dev cycles over the Architecture abstraction layers:
| UART Byte | What hardware it is compatible with |
|---|---|
| 8250-compatible MMIO UART | ARM boards that expose a PC-style serial block through memory-mapped I/O |
| DesignWare APB UART | ARM SoCs and boards that use the Synopsys DW serial controller |
| Generic MMIO UART fallback | Less common or custom ARM boards with a simple memory-mapped serial port |

## Interrupt and Timer Wiring
This part of the arch layer connects the hardware events to the kernel. Where interrupts are routed to the CPU, so the platform controller can send the correct core the inteneded hardware events. The processor knows whcih interrupt lines to handle. 

The kernel knows a timer tick happened because the timer hardware interrupts it on  fixed interval and hte interrupt handler increments the tick counter. 

It works different ways depending on if it is x86 or AArch 64:
|x86 | AArch64 |
|---|---|
The pit is prgrammed to fire the IRQ0 at the chosen rate, the IRQ0 is routed through hte interrupt controller to the kernel, the the IRQ0 calls the scheduler timer to tick the path | There is a generic timer configured in the arch layer so that when it fires, it sees the timer interrupt ID, it incremenets the functions being the code TIMER_IRQ_COUNT (counts how many timer interrupts have arrived) and TIMER_TICKS (counts how many timer ticks the kernel has accepted and processed), then calls the kernel timer tick hook. 
>IRQ0 just means its the first hardware interrupt line and that it is the traditional timer interupt. It is more specifically the event that drives scheduling on the x86 platform. The same role is handled by the platform timer interrupt on AArch64. 

## Boot and Runtime Setup
The startup seuence wires the machine into a usable kernel runtime by handing control the arch entrypoint where the arch layer captures the boot info like the DTB (Device Tree Blob) or the multiboot pointers. The kernel intializes the CPU tables and memory translation. Then the timer is initialized, and the interrupts are promptly enabled. Shared kernel subsystems are rought up after that point, then the scheduler starts and hte shell is brought up and then the available runtime tasks for the caller to use to their own devices. 

Differences between launch sequences on AArch64 and x86 
| AArch64 | x86 |
|---|---|
| Logs early bring-up over UART. Initializes CPU tables. Reads boot info. Initializes the MMU. Parses the DTB. Sets up vectors, the GIC, and the timer. Enables interrupts. Starts the scheduler and launches the shell and network tasks. | Sets up the GDT and IDT. Initializes the interrupt controller. Enables paging. Initializes the PIT timer. Brings up subsystems like security, filesystem, IPC, and the scheduler. Then starts the runtime scheduler. |


### DTB deep dive on the arch boot layer
The Device Tree Blob is the data structure passed to the kernel on boot, and is AArch64 specific, it describes the hardware layout of the machine. 

It tells the kernel,  where the memory is, where the UART is, where the interrupt controller is, where the timer is, and what VirtIO devices are present. 

It lets the kernel dsicver the hardware without hardcoding everyboard, and it helps the kernel adapt to the actual machine it is booted on. 

The DTB format is pretty standard on the kernel itself, but how the kernel uses it is quite unique. It seeds platform discoery for the exact machine the kernel booted on, it helps configure the UART, GIC, timer, memory map and VirtIO devices early, then it feeds directly intot he runtime shell and diagnostic path. It is used to keep the AArch64 backend explicit instead of hardoding board assumptions everywhere. 

So unlike other OS's where its simply a boot detail, we treat it as a trusted input to the architecture layer that helps the kernel always be aware of the machine it is on. the DTB can then be parsed in values such as in diagnostic commands like boot, regs, mmu, irqa and uartirq. 

The kernel can then use that data to keep platform specific logic inside the arch boundary rather than leaking it through the rest of the system. 

## Platform Variants
Platform variants are how Oreulius changes it low-level set-up depending on the hardware target. It doesnt boot the same way everywhere, instead on AArch64 it uses the DTB, GIC, generic timer, and the current legacy PL011 UART byte. 

Whereas on x86 and x86_64, Oreulius uses the x86 boot path, the GDT and IDT, and a PIT-based timer path. The PIT (programmable interval timer) is programmed to generate periodic timer interrupts, which arrive as IRQ0. The interrupt is routed through the IDT, and the scheduler uses it as the tick source. In practice, the x86 timer path today is PIT initialization, IRQ0 handling, tick counting, and scheduler preemption.


### Future Timing backends
In the future, some good development ideas for timing backends would be an AIPIC and and HPET. 

#### APIC 
It stands for advanced programmable interrupt controller. On x86 it would be used to deliver timer interrupts more flexibly than the old PIT

#### HPET
HPET stands for High Precision Event Timer, it is also a x86 timer source, it is more precise than a PIT

#### What a Future APIC and HPET path in oreulius would best be
It should be treated as a timing backend, and not as user-facing controls. 

Heres a table to represent what the APIC and the HPET paths should be or not be:

|Timing Backend |What they should be
|---|---|
| APIC |An x86 should be the x86 interupt delivery path that can route timer interrupts more cleaner than the legacy PIT 
|HPET | A higher-precision timer source the kernel can use when it wants better timing than the PIT 

They should not be:
1. Shell tools that let workloads poke raw interrupt hardware
2. Direct register-editing interfaces for users
3. Broad “control everything” commands
4. Something exposed before the kernel actually needs and supports them

How they should fit within Oreulius's Architecture:
1. kept inside the arch layer
2. let the kernel select the backend at the boot or runtime based on platform support 
3. keep the schedular interface stable, and in a sense that the kernel only sees "timer ticks, and not which x86 timer chip was used. 
5. with a preference for one clear path per machine not overlapping timer controls. 

Security measures to be considered with the future APIC and HPET paths
1. Initialize them only in trusted kernel bring-up code
2. keep the ahrdware access behind tha arch abstraction 
3. do not expose the raw APIC/HPET regiseters to the shell or workloads
4. Validate every coonfiguration change against the current CPU/platform state. 
5. make sure that any fall back behaviour is safe, especially if a device is missing or broken. 
6. keep mutation commands out, unless there is a real operator need, and then gate those commands with capabilities should they exist. 

#### When each is optimal for the kernel to use 

| Timer back-end | Optimal time for kernel to use |
|---|---|
| PIT | Simple periodic ticks, early bring-up, and legacy-compatible x86 scheduling |
| APIC | Modern x86 interrupt routing and per-core timer delivery |
| HPET | Higher-precision timing, profiling, and finer-grained timekeeping |


To further clarify, here is what each will be best for, for smoother and less resource-intensive x86 timer operations:

**PIT:**
1. best for the current x86 bring-up path
2. good for simple periodic timer ticks
3. fine for basic scheduler preemption
4. useful when you want the smallest, 
5. easiest-to-debug timer path

**APIC:**
1. best for interrupt delivery on modern x86
2. useful when you want cleaner routing of 
3. timer interrupts to specific CPU cores
4. better than PIT when the kernel wants 
5. per-core timer behavior or more flexible 
6. interrupt handling
7. fits the interrupt-controller side of the architecture
**HPET:**
1. best when you want higher precision timing
2. useful for monotonic timers, profiling, and
3. tighter timing work
4. better than PIT when the kernel needs 
5. finer-grained timing than a legacy periodic tick source
6. fits the time-source side of the architecture

Its important that all three do not compete as user-facing choices, that theyare not exposed as raw operational knobs, and that their responsibikities in the scheduler are not mixed. 

## Assembly and Low-Level Entry Points

This is they layer that gets oreuliis from the raw bootloader handoff into rust code that can actually run. It is the first code that the machine executes after the boot, and the place where the kernel sets up the minimum CPU state that rust needs. 

In oreulius it is unique in the sense that it keeps seperate enty paths for x86, x86_64, and AArch64. The boot stubs do not try to hude the hardware differences, and that the assembly is used exactly for the things rust should not, or cannot do portably. Suc has early boot handoff, mode transition, vector tables, context switching, interrupt stubs and the llw level refister setup. Instead that is handled by the arch layer, that keeps the rest of the kernel portable. 

Here arethe main entry points in a table so it is easier to understand. 

| Entry Point | What it is for | 
|---|---|
|_start | like it states, this is the raw boot entry used in the assembly stubs  |
| rust_main | this is the common rust entry |
|arch_x86_record_boot_handoff | records the x86 bootloader handoff before the Rust code takes over, it is used by the x86 boot assembly and implemented in the x86 arch path |
| arch_aarch64_record_boot_handoff | records the AARch64 DTB handoff before rust takes over, it is called from the boot_aarch64_virt.s and implemetne in the AARch64 arch path. |
|oreulius_aarch64_vector_dispatch | the rust side AArch64exception dipatcher called by the vector table assembly, it is declared in the AARch64 vector code |
|x86_64_trap_dispatch | This is the rust-side AARch64 exception dispatcher that is called by the vector table assembly code. |
|x86_64_trap_dispatch | this is the rust side x86_64 trap dispatcher called from the x86_64 interrupt path |

The assembly transitions functionality into rust by preparing registers, stack and starting up the CPU mode, it saves the bootloader handoff data, it calles the rust_main entry point, and then Rust calls it into the arch layer to finish the bring-up. Assembly is then used again for things like vectors, traps interrupts, and context switching

What is yet to be completed for the assembly and low level entry points:
1. not every platform/backend is supported, but this is a long term goal, and will be done through agile development.
2. The assembly layer still reflects a staged bring-up model.
3. Some pieces are target-sepcific shims rather than one unified final abstraction 
4. The x86 side still has legacy 32-bit and 64-bit split behaviour
5. Future hardware backends and some cleaner abstractions need to be added for wider platform coverage. 
>while these things arent fully complete, it is still functional for the current supported targets, its just not final or universal. It is complete enough, it can do bring-up, runtime entry, interrupts, vectors and context switching on the current targets. 

## Port it to RISC-V?
One of the goals of Oreulius is to eventually port it beyond x86 and AArch64, RISC-V would be a good architectur fit. 

This is for two main reasons, it fits the kind of kernel that Oreulius is trying to be, and its a clean enough architecture, to map onto the existing design without fitting the model.

Heres why it fits the architecture so well. RISC-V is designed around a clean kind of seperation, it has simple, explicit privilage modulars, and is a hardware architecture that is easier to reason about than many older platforms. 

It matches our style, explicit authority, narrow boundaries and low-level code kept all in one place. It wouldnt be hard to port over and would likely wind up making a super smooth system. It is almost as if it was meant to be. 

It would also allow people to run Oreulius on research boards, Custom SoC's, simulators, or platforms where vendor lock is undesirable. The project is trying to be a controlled run time for workloads no matter where you want to run it. 

### Assembly boundary 
The assembly boundary is where the kernel stops using portable rust and starts using target-specific machine code. Our kernel uses this boundary to prevent jobs from running to close to the hardware for rust to handle directly and safely in a way that is portable. 

The jobs are:
1. the first instruction set after the boot
2. switching CPU modes 
3. saving and restoring the exact register state
4. entering and exiting interrupt handlers.
5. installing exception vector tables 
6. doing low-level context switches

Think of it like a thin layer between the firmware, bootloader, and cpu entry. As-well as the rust kernel run-time. It is to keep the dangerous machine specific work in one secure place. To let the rest of the kernel stay portable, and to keep the boot, interrupts, and context switching explicit rather than ambient. Importantly, it prevents low-level CPU details from leaking into the normal kernel code. 

Rust owns most of the kernel, whereas assmembly, owns the exact entyr and exit points where the CPU needs precise instructions. Assembly really is a smart choice for interacting with machines and connecting code into machines safely. 

In the system, the assembly layer is the kernel’s first contact with the machine. It handles the raw boot entry, preserves early handoff state, and transfers control into Rust once the CPU is ready.

## Capability and Isolation Boundaries
The capability and isolation boundaries are about who is allowed to what once the kernel is running. It covers permission and authority. 

This trust fence gives:
1. a process explicit authority for a specific action 
2. limits authority to a specific scope
3. lets the kernel attenuate rights instead of expanding them
4. ties access to things like files, IPC, and other kernel services into a real grant, not just a path or a handle. 

It keeps one process's memory and runtime state seperate from anothers. Prevents direct access to privilged kernel states, blocks a workload from reaching beyond its allowed context, and keeps faults, traps, and low-level CPU events contained inside the kernel path that owns them. 

For operating the capability and isolation boundaries, please use these commands:
| Current command | What it does |
|---|---|
| cap-list | List capabilities |
| cap-test-atten | Demonstrate capability attenuation |
| cap-test-cons | Test console capabilities |
| cap-arch | Show the capability architecture |
| fs-cap <pid> | Show a process filesystem capability |
| fs-quota <pid> | Show or set a process quota |
| security-stats | Show security statistics |
| security-audit | Show recent security events |

There are a few commands that would be good, but they owuld need to be read-only and narrowly scoped so that they remain safe. 

For example, we dont want people to be able to change states, or expose raw hardware or secret material, or punch through the architecture boundaries. 

Here are some potential commands that would be nice haves that fit our architecture principles: 
| Future command | What it will do |
|---|---|
| cap-show <id> | Show one capability in detail |
| cap-scope <id> | Show the path or object scope attached to a capability |
| cap-expiry <id> | Show when a capability expires |
| security-boundaries | Show the active isolation and authority boundaries |
| security-summary | Show a compact summary of current security state |
| mmu-state | Show the current paging and translation state at a high level |


As you can see they are mostly visibility commands, not control commands. 



## Diagnostics and Self-Test
This is the part of the arch layer that helps you verify if the machien is behaving correctly, it is where the kernel exposes various checks and measurements such as 

1. CPU state
2. interrupt behaviour
3. Timer behaviour
4. MMU behaviour
5. UART Behaviour 
6. boot and runtime health 

The arch layer is the most failure prone part of any kernel, so its importnat we have ways to check and see whats wrong without compromising security. Self tests are the way that you can do sow to verigy the low level plumbing wihtout relying on, or allowing for higher level subsystems. 

While we already covered these commands, These are again the commands that cover these things: 

| Diagnostic commmand | What it used to inspects or test|
|---|---|
|mmu | to inspect paging state|
|regs | to inspect CPU/platform state|
|traps | to inspect fault and exception counts|
|irqs | to inspect interrupt activity|
|ticks | to inspect timer progress|
|uartirq | to inspect UART interrupt status|
|vmtest | or similar tests to exercise memory| and runtime paths |

These above commands are enough for observing the arch layer, checking tier and interrupt behaviour, fully validating the bring-up, and debugging the low-level failures. 

Some future commands that are risk free for security would be these, but not a outright necessity.  

These commands below will be useful to develop in future dev-cycles: 
|Future command | What it would do |
|---|---|
| boot | Show boot handoff and runtime boot info |
| vmtest | Run a low-level virtual memory self-test |
| mmu-state | Show a compact paging and translation summary |
| interrupt-health | Show a combined IRQ and trap health summary |
| timer-health | Show timer interrupt and tick health |



## Additional needs i've noticed missing during further code Review: 

1. Add unit & integration tests for MMU primitives: translate, map_page_4k, map_range_l2_blocks, debug_walk_current
2. Add read‑back verification in write_mair_tcr_ttbrs_and_enable() to assert MAIR_EL1, TCR_EL1, and TTBR0/TTBR1 after MSR writes. These need to be gated to debug_assertions
3. Expose a serial shell command that pretty‑prints debug_walk_current() output; implement hook in aarch64_virt.rs shell handlers.
4. Split aarch64_virt.rs into smaller modules to reduce review surface and enable per‑module tests.
5. Harden and test virtio‑blk sync path by adding final completion harvest, deterministic wait and timeout behavior, as-well as regression tests in the blk_sync.rs file to make the sync wait spins configurable to tests
6. Make page‑table allocator deterministic for tests, such as adding a test pool or an allocator path in alloc_page_raw() and unit tests validating the allocation boundaries.
7. Add concurrency and stress tests for the recursive clone table and page allocation and page end atomics to ensure all the races are caught and mediated. 
8. Add TLB flush ordering verification,  host mocks for flush tlb's, so that page‑table logic can be unit tested without qemu
9. Create a libFuzzer cargo target, for the cargo-fuzz command, to exercise map_page_4k, translate, and clone_table_recusive, as-well as wire a  CL job to run quick fuzz rounds.
10. Create a second CL smoke test called extended-aarch64.sh. Make sure it includes all the regression tests in the smoke sweet for the virtio-blk boot. 
11. Improve invariant messaging, and create more clear error messaging. 
12. Create a script that boots in qemu. runs the ptwalk, and saves a page-table snapshot to compare regressions. 


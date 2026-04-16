# Architecture Abstraction Layer

This directory is for the boot and runtime code that the kernel relies on. This folder exposes the ArchpPlatform trait that the kerenl calls on for platform setup and theruntime entry. It isolates the CPU, the interrupt controller, the timer, and the differences in the MMU in order to create platform parity between the different ports. 

## Run 

To run in qemu, here is the AArch64 test command:

```bash
./kernel/run-aarch64-virt-image.sh
```



## Future work: 
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












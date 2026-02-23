use super::{ArchPlatform, BootInfo};

pub(super) struct UnsupportedPlatform;

pub(super) static PLATFORM: UnsupportedPlatform = UnsupportedPlatform;

impl ArchPlatform for UnsupportedPlatform {
    fn name(&self) -> &'static str {
        "unsupported"
    }

    fn boot_info(&self) -> BootInfo {
        BootInfo::default()
    }

    fn init_cpu_tables(&self) {}

    fn init_trap_table(&self) {}

    fn init_interrupt_controller(&self) {}

    fn init_timer(&self) {}

    fn enable_interrupts(&self) {}

    fn halt_loop(&self) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}

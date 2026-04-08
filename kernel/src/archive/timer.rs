/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

use x86_64::instructions::port::Port;

pub fn init_pit() {
    // Set PIT to 1000 Hz
    let divisor = 1193182 / 1000;
    let mut command_port = Port::new(0x43);
    let mut data_port = Port::new(0x40);
    unsafe {
        command_port.write(0x36u8);
        data_port.write((divisor & 0xFF) as u8);
        data_port.write((divisor >> 8) as u8);
    }
}
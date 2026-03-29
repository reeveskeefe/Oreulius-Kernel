/*!
 * Shared network command helpers used by both the full x86 shell and the
 * AArch64 serial shell adapter.
 */

use core::fmt::Write;

use crate::net;
use crate::net_reactor;
use crate::netstack::Ipv4Addr;

fn write_help_line<W: Write>(out: &mut W, prefix: &str, body: &str) {
    if prefix.is_empty() {
        let _ = writeln!(out, "{}", body);
    } else {
        let _ = writeln!(out, "{} {}", prefix, body);
    }
}

fn write_ipv4<W: Write>(out: &mut W, ip: Ipv4Addr) {
    let octets = ip.octets();
    let _ = write!(
        out,
        "{}.{}.{}.{}",
        octets[0], octets[1], octets[2], octets[3]
    );
}

fn write_mac<W: Write>(out: &mut W, mac: [u8; 6]) {
    let _ = write!(
        out,
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
}

pub fn print_help<W: Write>(out: &mut W, prefix: &str) {
    write_help_line(out, prefix, "  netstack-info");
    write_help_line(out, prefix, "  eth-status");
    write_help_line(out, prefix, "  dns-resolve <domain>");
    write_help_line(out, prefix, "  http-get <url>");
}

pub fn cmd_http_get<W: Write>(out: &mut W, url: Option<&str>) {
    let url = match url {
        Some("ex") => "http://example.com/",
        Some("exs") => "https://example.com/",
        Some(u) => u,
        None => "http://example.com/",
    };

    let _ = writeln!(out);
    let _ = writeln!(out, "HTTP GET: {}", url);
    let _ = writeln!(out);

    let response = match net::network().lock().http_get(url) {
        Ok(resp) => resp,
        Err(e) => {
            let _ = writeln!(out, "Request failed: {}", e.as_str());
            let _ = writeln!(
                out,
                "[HTTP] Note: http-get requires an active network connection."
            );
            let _ = writeln!(
                out,
                "[HTTP] In QEMU emulation this command requires a configured"
            );
            let _ = writeln!(
                out,
                "[HTTP]   user-mode or TAP network backend (e.g. -netdev user)."
            );
            return;
        }
    };

    let _ = writeln!(out, "Status: {}", response.status_code);
    let _ = writeln!(out);
    let _ = writeln!(out, "===== Response Body =====");
    let _ = writeln!(out);

    let print_len = response.body_len.min(1024);
    if let Ok(body) = core::str::from_utf8(&response.body[..print_len]) {
        let _ = write!(out, "{}", body);
    } else {
        for &byte in &response.body[..print_len] {
            let ch = if (0x20..=0x7e).contains(&byte) || byte == b'\n' || byte == b'\r' {
                byte as char
            } else {
                '.'
            };
            let _ = write!(out, "{}", ch);
        }
    }

    if response.body_len > 1024 {
        let _ = writeln!(
            out,
            "\n\n[... truncated {} bytes ...]",
            response.body_len - 1024
        );
    }

    let _ = writeln!(out, "\n\nTotal: {} bytes", response.body_len);
}

pub fn cmd_dns_resolve<W: Write>(out: &mut W, domain: Option<&str>) {
    let domain = match domain {
        Some("ex") => "example.com",
        Some(d) => d,
        None => "example.com",
    };

    let _ = writeln!(out);
    let _ = writeln!(out, "=== Real DNS Resolution ===");
    let _ = writeln!(out);
    let _ = writeln!(out, "Domain: {}", domain);

    let info = match net_reactor::get_info() {
        Ok(info) => info,
        Err(e) => {
            let _ = writeln!(out, "Error: {}", e);
            let _ = writeln!(out);
            return;
        }
    };

    if !info.ready {
        let _ = writeln!(out, "Error: Network not ready");
        let _ = writeln!(out, "Check: eth-status or netstack-info");
        let _ = writeln!(out);
        return;
    }

    let _ = write!(out, "Sending UDP DNS query to ");
    write_ipv4(out, info.dns_server);
    let _ = writeln!(out, "...");

    let ip = match net_reactor::dns_resolve(domain) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = writeln!(out, "Resolution failed: {}", e);
            let _ = writeln!(out);
            return;
        }
    };

    let _ = write!(out, "Success! IP: ");
    write_ipv4(out, ip);
    let _ = writeln!(out);
    let _ = writeln!(out);
}

pub fn cmd_eth_status<W: Write>(out: &mut W) {
    let _ = writeln!(out);
    let _ = writeln!(out, "===== Ethernet Status =====");
    let _ = writeln!(out);

    let info = match net_reactor::get_info() {
        Ok(info) => info,
        Err(e) => {
            let _ = writeln!(out, "Error: {}", e);
            let _ = writeln!(out);
            return;
        }
    };

    let mac = info.mac;
    let has_mac = mac.iter().any(|&byte| byte != 0);
    let has_device = has_mac || info.link_up || info.ip.0 != [0, 0, 0, 0];

    if !has_device {
        let _ = writeln!(out, "No Ethernet device detected");
        let _ = writeln!(out);
        return;
    }

    #[cfg(target_arch = "aarch64")]
    let device_name = "VirtIO Network Device";
    #[cfg(not(target_arch = "aarch64"))]
    let device_name = "Intel E1000 Gigabit Ethernet";

    let _ = writeln!(out, "Device: {}", device_name);
    let _ = write!(out, "MAC Address: ");
    if has_mac {
        write_mac(out, mac);
        let _ = writeln!(out);
    } else {
        let _ = writeln!(out, "Unavailable");
    }

    let _ = writeln!(
        out,
        "Link Status: {}",
        if info.link_up { "UP" } else { "DOWN" }
    );
    let _ = writeln!(
        out,
        "Reactor Status: {}",
        if info.ready { "READY" } else { "NOT READY" }
    );

    #[cfg(target_arch = "aarch64")]
    let _ = writeln!(out, "Speed: virtio-net");
    #[cfg(not(target_arch = "aarch64"))]
    let _ = writeln!(out, "Speed: 1000 Mbps (Gigabit)");

    #[cfg(not(target_arch = "aarch64"))]
    let _ = writeln!(out, "Duplex: Full");
    let _ = writeln!(out);
}

pub fn cmd_netstack_info<W: Write>(out: &mut W) {
    let _ = writeln!(out);
    let _ = writeln!(out, "===== Production Network Stack =====");
    let _ = writeln!(out);

    let info = match net_reactor::get_info() {
        Ok(info) => info,
        Err(e) => {
            let _ = writeln!(out, "Error: {}", e);
            return;
        }
    };

    let _ = writeln!(out, "Status: {}", if info.ready { "READY" } else { "NOT READY" });
    let _ = writeln!(out);
    let _ = writeln!(out, "Features:");
    let _ = writeln!(out, "  [x] ARP Protocol (address resolution)");
    let _ = writeln!(out, "  [x] UDP Protocol (for DNS)");
    let _ = writeln!(out, "  [x] DNS Client (QEMU usernet resolver / configured DNS)");
    #[cfg(target_arch = "aarch64")]
    let _ = writeln!(out, "  [x] Real packet I/O via virtio-net MMIO");
    #[cfg(not(target_arch = "aarch64"))]
    let _ = writeln!(out, "  [x] Real packet I/O via E1000 descriptors");
    let _ = writeln!(out, "  [x] Universal interface (works with any driver)");
    let _ = writeln!(out);

    let _ = write!(out, "My IP: ");
    write_ipv4(out, info.ip);
    let _ = writeln!(out);
    let _ = write!(out, "DNS server: ");
    write_ipv4(out, info.dns_server);
    let _ = writeln!(out);
    let _ = writeln!(out, "Link: {}", if info.link_up { "UP" } else { "DOWN" });
    let _ = writeln!(
        out,
        "\nTCP: {} connections, {} listeners",
        info.tcp_conns, info.tcp_listeners
    );
    let _ = writeln!(
        out,
        "HTTP server: {}",
        if info.http_running { "ON" } else { "OFF" }
    );
    if info.http_running {
        let _ = writeln!(out, "HTTP port: {}", info.http_port);
    }
    let _ = writeln!(out);
}

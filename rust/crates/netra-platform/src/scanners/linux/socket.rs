//! Linux /proc/net/tcp and /proc/net/udp socket telemetry parser.

use std::fs;
use std::net::Ipv4Addr;

use netra_core::error::Result;
use netra_core::observation::{
    ObservationPayload, SocketObservationPayload, SocketProtocol, SocketRecord,
};

/// Translates Linux TCP hex state to human-readable state string.
pub fn linux_tcp_state_to_str(st: u8) -> &'static str {
    match st {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSED",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Parses a Linux /proc/net/tcp line into a [`SocketRecord`].
pub fn parse_proc_net_tcp4_line(line: &str) -> Option<SocketRecord> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    // Skip header line
    if parts[0].starts_with("sl") {
        return None;
    }

    let local = parts[1];
    let remote = parts[2];
    let st_hex = parts[3];

    let (local_ip, local_port) = parse_hex_v4_endpoint(local)?;
    let (remote_ip, remote_port) = parse_hex_v4_endpoint(remote)?;
    let state_byte = u8::from_str_radix(st_hex, 16).unwrap_or(0);
    let state = linux_tcp_state_to_str(state_byte);

    Some(SocketRecord {
        protocol: SocketProtocol::Tcp,
        local_address: local_ip.to_string(),
        local_port,
        remote_address: (remote_port > 0).then(|| remote_ip.to_string()),
        remote_port: (remote_port > 0).then_some(remote_port),
        state: state.to_string(),
        owning_pid: 0, // Inode to PID mapping can be enriched via /proc/[pid]/fd
        process_name: None,
    })
}

/// Parses a Linux /proc/net/udp line into a [`SocketRecord`].
pub fn parse_proc_net_udp4_line(line: &str) -> Option<SocketRecord> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    if parts[0].starts_with("sl") {
        return None;
    }

    let local = parts[1];
    let (local_ip, local_port) = parse_hex_v4_endpoint(local)?;

    Some(SocketRecord {
        protocol: SocketProtocol::Udp,
        local_address: local_ip.to_string(),
        local_port,
        remote_address: None,
        remote_port: None,
        state: "BOUND".to_string(),
        owning_pid: 0,
        process_name: None,
    })
}

fn parse_hex_v4_endpoint(endpoint: &str) -> Option<(Ipv4Addr, u16)> {
    let mut split = endpoint.split(':');
    let ip_hex = split.next()?;
    let port_hex = split.next()?;

    if ip_hex.len() != 8 {
        return None;
    }

    let ip_num = u32::from_str_radix(ip_hex, 16).ok()?;
    // Linux stores IPv4 as little-endian bytes in /proc/net/tcp
    let ip = Ipv4Addr::from(ip_num.to_le_bytes());
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    Some((ip, port))
}

/// Collects sockets from Linux /proc/net filesystem.
pub fn collect_linux_sockets() -> Result<ObservationPayload> {
    let mut records = Vec::new();

    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines() {
            if let Some(rec) = parse_proc_net_tcp4_line(line) {
                records.push(rec);
            }
        }
    }

    if let Ok(content) = fs::read_to_string("/proc/net/udp") {
        for line in content.lines() {
            if let Some(rec) = parse_proc_net_udp4_line(line) {
                records.push(rec);
            }
        }
    }

    Ok(ObservationPayload::Sockets(SocketObservationPayload {
        sockets: records,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_tcp4_line() {
        let sample = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 38244 1 0000000000000000 100 0 0 10 0";
        let record = parse_proc_net_tcp4_line(sample).unwrap();
        assert_eq!(record.protocol, SocketProtocol::Tcp);
        assert_eq!(record.local_address, "127.0.0.1");
        assert_eq!(record.local_port, 8080);
        assert_eq!(record.state, "LISTEN");
    }

    #[test]
    fn test_parse_proc_net_udp4_line() {
        let sample = "   1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 18321 2 0000000000000000 0";
        let record = parse_proc_net_udp4_line(sample).unwrap();
        assert_eq!(record.protocol, SocketProtocol::Udp);
        assert_eq!(record.local_address, "0.0.0.0");
        assert_eq!(record.local_port, 53);
        assert_eq!(record.state, "BOUND");
    }
}

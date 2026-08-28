//! Linux kernel `/proc/net/route` and `/proc/net/ipv6_route` passive collector.

use netra_core::error::{NetraError, Result};
use netra_core::observation::{
    ObservationPayload, RouteObservationPayload, RouteRecord, RouteType,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parses Linux `/proc/net/route` IPv4 routing table format.
pub fn parse_proc_net_route(content: &str) -> Vec<RouteRecord> {
    let mut records = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }

        let iface = fields[0].to_string();
        let dest_hex = fields[1];
        let gw_hex = fields[2];
        let flags_hex = fields[3];
        let metric_str = fields[6];
        let mask_hex = fields[7];

        let dest_ip = match parse_ipv4_hex_le(dest_hex) {
            Some(ip) => ip,
            None => continue,
        };
        let gw_ip = match parse_ipv4_hex_le(gw_hex) {
            Some(ip) => ip,
            None => continue,
        };
        let mask_ip = match parse_ipv4_hex_le(mask_hex) {
            Some(ip) => ip,
            None => continue,
        };
        let flags = u32::from_str_radix(flags_hex, 16).unwrap_or(0);
        let metric = metric_str.parse::<u32>().unwrap_or(0);

        let prefix_length = u32::from(mask_ip).count_ones() as u8;
        let destination_cidr = format!("{}/{}", dest_ip, prefix_length);

        let has_gw_flag = (flags & 0x0002) != 0;
        let gateway_ip = if has_gw_flag && !gw_ip.is_unspecified() {
            Some(gw_ip.to_string())
        } else {
            None
        };

        let is_default_gateway =
            dest_ip.is_unspecified() && prefix_length == 0 && gateway_ip.is_some();

        let route_type = if iface == "lo" || dest_ip.is_loopback() {
            RouteType::Local
        } else if gateway_ip.is_some() {
            RouteType::Remote
        } else {
            RouteType::Direct
        };

        records.push(RouteRecord {
            destination_cidr,
            gateway_ip,
            interface_index: 0,
            interface_name: Some(iface),
            metric,
            is_ipv6: false,
            is_default_gateway,
            route_type,
        });
    }

    records
}

/// Parses Linux `/proc/net/ipv6_route` IPv6 routing table format.
pub fn parse_proc_net_ipv6_route(content: &str) -> Vec<RouteRecord> {
    let mut records = Vec::new();

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let dst_hex = fields[0];
        let dst_prefix_hex = fields[1];
        let next_hop_hex = fields[4];
        let metric_hex = fields[5];
        let iface = fields[9].to_string();

        let dst_ip = match parse_ipv6_hex_32(dst_hex) {
            Some(ip) => ip,
            None => continue,
        };
        let prefix_length = u8::from_str_radix(dst_prefix_hex, 16).unwrap_or(128);
        let destination_cidr = format!("{}/{}", dst_ip, prefix_length);

        let next_hop = match parse_ipv6_hex_32(next_hop_hex) {
            Some(ip) => ip,
            None => continue,
        };

        let gateway_ip = if !next_hop.is_unspecified() {
            Some(next_hop.to_string())
        } else {
            None
        };

        let metric = u32::from_str_radix(metric_hex, 16).unwrap_or(0);
        let is_default_gateway =
            dst_ip.is_unspecified() && prefix_length == 0 && gateway_ip.is_some();

        let route_type = if iface == "lo" || dst_ip.is_loopback() {
            RouteType::Local
        } else if gateway_ip.is_some() {
            RouteType::Remote
        } else {
            RouteType::Direct
        };

        records.push(RouteRecord {
            destination_cidr,
            gateway_ip,
            interface_index: 0,
            interface_name: Some(iface),
            metric,
            is_ipv6: true,
            is_default_gateway,
            route_type,
        });
    }

    records
}

fn parse_ipv6_hex_32(hex_str: &str) -> Option<Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }

    let mut segments = [0u16; 8];
    for i in 0..8 {
        let chunk = &hex_str[i * 4..(i + 1) * 4];
        segments[i] = u16::from_str_radix(chunk, 16).ok()?;
    }

    Some(Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    ))
}

fn parse_ipv4_hex_le(hex_str: &str) -> Option<Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let b0 = u8::from_str_radix(&hex_str[0..2], 16).ok()?;
    let b1 = u8::from_str_radix(&hex_str[2..4], 16).ok()?;
    let b2 = u8::from_str_radix(&hex_str[4..6], 16).ok()?;
    let b3 = u8::from_str_radix(&hex_str[6..8], 16).ok()?;
    Some(Ipv4Addr::new(b3, b2, b1, b0))
}

/// Collects Linux routing tables from `/proc/net/route` and `/proc/net/ipv6_route`.
#[cfg(target_os = "linux")]
pub fn collect_linux_routes() -> Result<ObservationPayload> {
    let mut routes = Vec::new();

    // 1. Read IPv4 routing table
    match std::fs::read_to_string("/proc/net/route") {
        Ok(content) => {
            routes.extend(parse_proc_net_route(&content));
        }
        Err(e) => {
            return Err(NetraError::platform(format!(
                "Failed to read /proc/net/route: {}",
                e
            )));
        }
    }

    // 2. Read IPv6 routing table if available
    if let Ok(content) = std::fs::read_to_string("/proc/net/ipv6_route") {
        routes.extend(parse_proc_net_ipv6_route(&content));
    }

    // Deterministic route ordering: (is_ipv6, destination_cidr, metric, interface_index, gateway_ip)
    routes.sort_by(|a, b| {
        (
            a.is_ipv6,
            &a.destination_cidr,
            a.metric,
            a.interface_index,
            &a.gateway_ip,
        )
            .cmp(&(
                b.is_ipv6,
                &b.destination_cidr,
                b.metric,
                b.interface_index,
                &b.gateway_ip,
            ))
    });

    // Derive default gateways ordered strictly by lowest metric first
    let mut default_routes: Vec<&RouteRecord> = routes
        .iter()
        .filter(|r| r.is_default_gateway && r.gateway_ip.is_some())
        .collect();
    default_routes.sort_by_key(|r| r.metric);

    let mut default_gateways = Vec::new();
    for r in default_routes {
        if let Some(ref gw) = r.gateway_ip {
            if !default_gateways.contains(gw) {
                default_gateways.push(gw.clone());
            }
        }
    }

    Ok(ObservationPayload::Routes(RouteObservationPayload {
        routes,
        default_gateways,
    }))
}

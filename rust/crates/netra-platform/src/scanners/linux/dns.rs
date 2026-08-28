//! Linux passive DNS configuration parser and collector.

use netra_core::error::Result;
use netra_core::network::IpClassification;
use netra_core::observation::{DnsObservationPayload, DnsServerRecord, ObservationPayload};
use std::net::IpAddr;
use std::str::FromStr;

/// Pure parser for `/etc/resolv.conf` and `/run/systemd/resolve/resolv.conf` contents.
pub fn parse_resolv_conf(content: &str) -> (Vec<DnsServerRecord>, Vec<String>) {
    let mut dns_servers = Vec::new();
    let mut search_domains = Vec::new();
    let mut fallback_domain: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Strip inline comments
        let clean_line = if let Some(idx) = line.find(['#', ';']) {
            line[..idx].trim()
        } else {
            line
        };

        let tokens: Vec<&str> = clean_line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        match tokens[0] {
            "nameserver" => {
                if tokens.len() > 1 {
                    let raw_addr = tokens[1];
                    let (addr_str, iface_name) =
                        if let Some((ip_part, iface_part)) = raw_addr.split_once('%') {
                            (ip_part, Some(iface_part.to_string()))
                        } else {
                            (raw_addr, None)
                        };

                    if let Ok(ip) = IpAddr::from_str(addr_str) {
                        if !ip.is_unspecified() {
                            let is_ipv6 = ip.is_ipv6();
                            let classification = IpClassification::classify(&ip);
                            let record = DnsServerRecord {
                                server_address: ip.to_string(),
                                interface_name: iface_name,
                                is_ipv6,
                                classification,
                            };

                            if !dns_servers.iter().any(|r: &DnsServerRecord| {
                                r.server_address == record.server_address
                                    && r.interface_name == record.interface_name
                            }) {
                                dns_servers.push(record);
                            }
                        }
                    }
                }
            }
            "search" => {
                for &dom in &tokens[1..] {
                    let domain = dom.trim().to_string();
                    if !domain.is_empty() && !search_domains.contains(&domain) {
                        search_domains.push(domain);
                    }
                }
            }
            "domain" if tokens.len() > 1 => {
                let dom = tokens[1].trim().to_string();
                if !dom.is_empty() && fallback_domain.is_none() {
                    fallback_domain = Some(dom);
                }
            }
            _ => {}
        }
    }

    if search_domains.is_empty() {
        if let Some(dom) = fallback_domain {
            search_domains.push(dom);
        }
    }

    (dns_servers, search_domains)
}

/// Collects Linux DNS resolver configuration from `/etc/resolv.conf` and `/run/systemd/resolve/resolv.conf`.
#[cfg(target_os = "linux")]
pub fn collect_linux_dns() -> Result<ObservationPayload> {
    let mut dns_servers = Vec::new();
    let mut search_domains = Vec::new();

    // 1. Read primary resolver config
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        let (servers, domains) = parse_resolv_conf(&content);
        dns_servers.extend(servers);
        search_domains.extend(domains);
    }

    // 2. If systemd-resolved stub is active (127.0.0.53), also check for upstream resolv.conf
    let has_stub_resolver = dns_servers.iter().any(|r| r.server_address == "127.0.0.53");
    if has_stub_resolver || dns_servers.is_empty() {
        if let Ok(upstream_content) = std::fs::read_to_string("/run/systemd/resolve/resolv.conf") {
            let (upstream_servers, upstream_domains) = parse_resolv_conf(&upstream_content);
            for s in upstream_servers {
                if !dns_servers
                    .iter()
                    .any(|r| r.server_address == s.server_address)
                {
                    dns_servers.push(s);
                }
            }
            for d in upstream_domains {
                if !search_domains.contains(&d) {
                    search_domains.push(d);
                }
            }
        }
    }

    Ok(ObservationPayload::Dns(DnsObservationPayload {
        dns_servers,
        search_domains,
        is_dynamic_dns_enabled: None,
    }))
}

#[cfg(not(target_os = "linux"))]
pub fn collect_linux_dns() -> Result<ObservationPayload> {
    use netra_core::error::NetraError;
    Err(NetraError::platform(
        "Linux DNS scanner is not supported on non-Linux platforms",
    ))
}

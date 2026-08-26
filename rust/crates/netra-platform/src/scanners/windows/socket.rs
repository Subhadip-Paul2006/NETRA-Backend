//! Windows native Win32 IP Helper socket telemetry collector.

#[cfg(windows)]
use netra_core::error::{NetraError, Result};
#[cfg(windows)]
use netra_core::observation::{
    ObservationPayload, SocketObservationPayload, SocketProtocol, SocketRecord,
};
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[cfg(windows)]
fn tcp_state_to_str(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

/// Collects all TCP and UDP active/listening endpoints from the Windows kernel via IP Helper APIs.
#[cfg(windows)]
pub fn collect_windows_sockets() -> Result<ObservationPayload> {
    let mut records = Vec::new();

    // 1. TCP IPv4 Table
    collect_tcp4(&mut records)?;

    // 2. TCP IPv6 Table
    collect_tcp6(&mut records)?;

    // 3. UDP IPv4 Table
    collect_udp4(&mut records)?;

    // 4. UDP IPv6 Table
    collect_udp6(&mut records)?;

    Ok(ObservationPayload::Sockets(SocketObservationPayload {
        sockets: records,
    }))
}

#[cfg(windows)]
fn collect_tcp4(records: &mut Vec<SocketRecord>) -> Result<()> {
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }

    if size == 0 {
        return Ok(());
    }

    let mut buffer: Vec<u8> = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret != 0 {
        return Err(NetraError::platform(format!(
            "GetExtendedTcpTable (IPv4) failed with win32 error code {}",
            ret
        )));
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    let entries_ptr = table.table.as_ptr();

    for i in 0..num_entries {
        let row = unsafe { &*entries_ptr.add(i) };
        let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let remote_addr = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
        let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
        let state = tcp_state_to_str(row.dwState);

        records.push(SocketRecord {
            protocol: SocketProtocol::Tcp,
            local_address: local_addr.to_string(),
            local_port,
            remote_address: if remote_port > 0 {
                Some(remote_addr.to_string())
            } else {
                None
            },
            remote_port: if remote_port > 0 {
                Some(remote_port)
            } else {
                None
            },
            state: state.to_string(),
            owning_pid: row.dwOwningPid,
            process_name: None,
        });
    }

    Ok(())
}

#[cfg(windows)]
fn collect_tcp6(records: &mut Vec<SocketRecord>) -> Result<()> {
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }

    if size == 0 {
        return Ok(());
    }

    let mut buffer: Vec<u8> = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret != 0 {
        return Err(NetraError::platform(format!(
            "GetExtendedTcpTable (IPv6) failed with win32 error code {}",
            ret
        )));
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    let entries_ptr = table.table.as_ptr();

    for i in 0..num_entries {
        let row = unsafe { &*entries_ptr.add(i) };
        let local_addr = Ipv6Addr::from(row.ucLocalAddr);
        let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let remote_addr = Ipv6Addr::from(row.ucRemoteAddr);
        let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
        let state = tcp_state_to_str(row.dwState);

        records.push(SocketRecord {
            protocol: SocketProtocol::Tcp,
            local_address: local_addr.to_string(),
            local_port,
            remote_address: if remote_port > 0 {
                Some(remote_addr.to_string())
            } else {
                None
            },
            remote_port: if remote_port > 0 {
                Some(remote_port)
            } else {
                None
            },
            state: state.to_string(),
            owning_pid: row.dwOwningPid,
            process_name: None,
        });
    }

    Ok(())
}

#[cfg(windows)]
fn collect_udp4(records: &mut Vec<SocketRecord>) -> Result<()> {
    let mut size: u32 = 0;
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }

    if size == 0 {
        return Ok(());
    }

    let mut buffer: Vec<u8> = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if ret != 0 {
        return Err(NetraError::platform(format!(
            "GetExtendedUdpTable (IPv4) failed with win32 error code {}",
            ret
        )));
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    let entries_ptr = table.table.as_ptr();

    for i in 0..num_entries {
        let row = unsafe { &*entries_ptr.add(i) };
        let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);

        records.push(SocketRecord {
            protocol: SocketProtocol::Udp,
            local_address: local_addr.to_string(),
            local_port,
            remote_address: None,
            remote_port: None,
            state: "BOUND".to_string(),
            owning_pid: row.dwOwningPid,
            process_name: None,
        });
    }

    Ok(())
}

#[cfg(windows)]
fn collect_udp6(records: &mut Vec<SocketRecord>) -> Result<()> {
    let mut size: u32 = 0;
    unsafe {
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
    }

    if size == 0 {
        return Ok(());
    }

    let mut buffer: Vec<u8> = vec![0u8; size as usize];
    let ret = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };

    if ret != 0 {
        return Err(NetraError::platform(format!(
            "GetExtendedUdpTable (IPv6) failed with win32 error code {}",
            ret
        )));
    }

    let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let num_entries = table.dwNumEntries as usize;
    let entries_ptr = table.table.as_ptr();

    for i in 0..num_entries {
        let row = unsafe { &*entries_ptr.add(i) };
        let local_addr = Ipv6Addr::from(row.ucLocalAddr);
        let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);

        records.push(SocketRecord {
            protocol: SocketProtocol::Udp,
            local_address: local_addr.to_string(),
            local_port,
            remote_address: None,
            remote_port: None,
            state: "BOUND".to_string(),
            owning_pid: row.dwOwningPid,
            process_name: None,
        });
    }

    Ok(())
}

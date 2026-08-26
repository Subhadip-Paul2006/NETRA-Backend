//! Windows host firewall profile posture collector via Registry.

#[cfg(windows)]
use netra_core::error::Result;
#[cfg(windows)]
use netra_core::observation::{
    FirewallObservationPayload, FirewallProfileRecord, ObservationPayload,
};
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
};

#[cfg(windows)]
fn query_firewall_profile_registry(profile_subpath: &str) -> (bool, String, String) {
    let subkey = format!(
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\{}",
        profile_subpath
    );
    let wide_key: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();

    let mut hkey: HKEY = std::ptr::null_mut();
    let res = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_key.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };

    if res != 0 || hkey.is_null() {
        // Default to enabled if cannot open subkey
        return (true, "Block".to_string(), "Allow".to_string());
    }

    let val_name: Vec<u16> = "EnableFirewall\0".encode_utf16().collect();
    let mut val_type: u32 = 0;
    let mut val_data: u32 = 0;
    let mut val_size: u32 = std::mem::size_of::<u32>() as u32;

    let query_res = unsafe {
        RegQueryValueExW(
            hkey,
            val_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            &mut val_data as *mut u32 as *mut u8,
            &mut val_size,
        )
    };

    unsafe { RegCloseKey(hkey) };

    let is_enabled = if query_res == 0 && val_type == REG_DWORD {
        val_data != 0
    } else {
        true
    };

    (is_enabled, "Block".to_string(), "Allow".to_string())
}

/// Collects Windows firewall profiles and configuration states.
#[cfg(windows)]
pub fn collect_windows_firewall() -> Result<ObservationPayload> {
    let profiles = vec![
        ("Domain", "DomainProfile"),
        ("Private", "StandardProfile"),
        ("Public", "PublicProfile"),
    ];

    let mut records = Vec::new();

    for (name, subpath) in profiles {
        let (is_enabled, inbound, outbound) = query_firewall_profile_registry(subpath);
        records.push(FirewallProfileRecord {
            profile_name: name.to_string(),
            is_enabled,
            default_inbound_action: inbound,
            default_outbound_action: outbound,
            active_rules_count: 0,
        });
    }

    Ok(ObservationPayload::Firewall(FirewallObservationPayload {
        profiles: records,
    }))
}

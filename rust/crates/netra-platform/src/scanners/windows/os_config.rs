//! Windows OS security configuration posture collector via Registry.

#[cfg(windows)]
use netra_core::error::Result;
#[cfg(windows)]
use netra_core::observation::{ObservationPayload, OsConfigObservationPayload, OsConfigRecord};
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
};

#[cfg(windows)]
fn query_registry_dword(subkey: &str, val_name_str: &str) -> Option<u32> {
    let wide_key: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_val: Vec<u16> = val_name_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

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
        return None;
    }

    let mut val_type: u32 = 0;
    let mut val_data: u32 = 0;
    let mut val_size: u32 = std::mem::size_of::<u32>() as u32;

    let query_res = unsafe {
        RegQueryValueExW(
            hkey,
            wide_val.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            &mut val_data as *mut u32 as *mut u8,
            &mut val_size,
        )
    };

    unsafe { RegCloseKey(hkey) };

    if query_res == 0 && val_type == REG_DWORD {
        Some(val_data)
    } else {
        None
    }
}

/// Collects Windows operating system security configurations.
#[cfg(windows)]
pub fn collect_windows_os_config() -> Result<ObservationPayload> {
    let mut records = Vec::new();

    // 1. UEFI Secure Boot
    let sb_val = query_registry_dword(
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        "UEFISecureBootEnabled",
    );
    let (sb_status, sb_val_str) = match sb_val {
        Some(1) => ("PASS", "1".to_string()),
        Some(0) => ("FAIL", "0".to_string()),
        _ => ("UNKNOWN", "N/A".to_string()),
    };
    records.push(OsConfigRecord {
        check_name: "SecureBoot".to_string(),
        status: sb_status.to_string(),
        value: sb_val_str,
        details: Some("UEFI Secure Boot platform verification".to_string()),
    });

    // 2. User Account Control (UAC) EnableLUA
    let uac_val = query_registry_dword(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "EnableLUA",
    );
    let (uac_status, uac_val_str) = match uac_val {
        Some(1) => ("PASS", "1".to_string()),
        Some(0) => ("FAIL", "0".to_string()),
        _ => ("UNKNOWN", "N/A".to_string()),
    };
    records.push(OsConfigRecord {
        check_name: "UAC_EnableLUA".to_string(),
        status: uac_status.to_string(),
        value: uac_val_str,
        details: Some("User Account Control consent virtualization".to_string()),
    });

    Ok(ObservationPayload::OsConfig(OsConfigObservationPayload {
        configurations: records,
    }))
}

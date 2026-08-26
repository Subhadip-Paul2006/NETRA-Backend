//! Windows local user account posture collector via NetUserEnum.

#[cfg(windows)]
use netra_core::error::Result;
#[cfg(windows)]
use netra_core::observation::{ObservationPayload, UserObservationPayload, UserRecord};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetUserEnum, FILTER_NORMAL_ACCOUNT, USER_INFO_1,
    USER_PRIV_ADMIN,
};

const UF_ACCOUNTDISABLE: u32 = 0x0002;

/// Enumerates local user accounts and administrative privilege indicators.
#[cfg(windows)]
pub fn collect_windows_users() -> Result<ObservationPayload> {
    let mut records = Vec::new();

    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume_handle: u32 = 0;

    let res = unsafe {
        NetUserEnum(
            std::ptr::null(),
            1, // Level 1: USER_INFO_1
            FILTER_NORMAL_ACCOUNT,
            &mut buf_ptr,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        )
    };

    if res == NERR_Success && !buf_ptr.is_null() {
        let user_info_ptr = buf_ptr as *const USER_INFO_1;
        for i in 0..entries_read as usize {
            let info = unsafe { &*user_info_ptr.add(i) };
            let username = if !info.usri1_name.is_null() {
                let mut len = 0;
                while unsafe { *info.usri1_name.add(len) } != 0 {
                    len += 1;
                }
                let slice = unsafe { std::slice::from_raw_parts(info.usri1_name, len) };
                String::from_utf16_lossy(slice)
            } else {
                "Unknown".to_string()
            };

            let is_enabled = (info.usri1_flags & UF_ACCOUNTDISABLE) == 0;
            let is_admin = info.usri1_priv == USER_PRIV_ADMIN;

            records.push(UserRecord {
                username: username.clone(),
                uid_or_sid: username,
                is_enabled,
                is_admin,
                account_type: "Local".to_string(),
                last_logon_timestamp: None,
            });
        }

        unsafe { NetApiBufferFree(buf_ptr as *mut _) };
    }

    Ok(ObservationPayload::Users(UserObservationPayload {
        users: records,
    }))
}

//! Windows Service Control Manager posture collector.

#[cfg(windows)]
use netra_core::error::{NetraError, Result};
#[cfg(windows)]
use netra_core::observation::{
    ObservationPayload, ServiceObservationPayload, ServiceRecord, ServiceStartType, ServiceState,
};
#[cfg(windows)]
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_PAUSED, SERVICE_RUNNING,
    SERVICE_STATE_ALL, SERVICE_STOPPED, SERVICE_WIN32,
};

#[cfg(windows)]
fn service_state_from_u32(state: u32) -> ServiceState {
    match state {
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_PAUSED => ServiceState::Paused,
        _ => ServiceState::Unknown,
    }
}

/// Collects installed system services from the Windows Service Control Manager.
#[cfg(windows)]
pub fn collect_windows_services() -> Result<ObservationPayload> {
    let mut records = Vec::new();

    let scm = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        )
    };

    if scm.is_null() {
        return Err(NetraError::platform(
            "Failed to open Service Control Manager for enumeration",
        ));
    }

    let mut bytes_needed: u32 = 0;
    let mut services_returned: u32 = 0;
    let mut resume_handle: u32 = 0;

    unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            std::ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        );
    }

    if bytes_needed > 0 {
        let mut buffer: Vec<u8> = vec![0u8; bytes_needed as usize];
        let res = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.as_mut_ptr(),
                bytes_needed,
                &mut bytes_needed,
                &mut services_returned,
                &mut resume_handle,
                std::ptr::null(),
            )
        };

        if res != 0 {
            let entries_ptr = buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
            for i in 0..services_returned as usize {
                let entry = unsafe { &*entries_ptr.add(i) };

                let svc_name = if !entry.lpServiceName.is_null() {
                    let mut len = 0;
                    while unsafe { *entry.lpServiceName.add(len) } != 0 {
                        len += 1;
                    }
                    String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(entry.lpServiceName, len)
                    })
                } else {
                    "Unknown".to_string()
                };

                let disp_name = if !entry.lpDisplayName.is_null() {
                    let mut len = 0;
                    while unsafe { *entry.lpDisplayName.add(len) } != 0 {
                        len += 1;
                    }
                    String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(entry.lpDisplayName, len)
                    })
                } else {
                    svc_name.clone()
                };

                let state = service_state_from_u32(entry.ServiceStatusProcess.dwCurrentState);

                records.push(ServiceRecord {
                    service_name: svc_name,
                    display_name: disp_name,
                    state,
                    start_type: ServiceStartType::Auto,
                    binary_path: None,
                    account_context: None,
                });
            }
        }
    }

    unsafe { CloseServiceHandle(scm) };

    Ok(ObservationPayload::Services(ServiceObservationPayload {
        services: records,
    }))
}

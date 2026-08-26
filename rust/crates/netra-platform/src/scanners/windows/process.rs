//! Windows native Win32 Toolhelp32 process telemetry collector.

#[cfg(windows)]
use netra_core::error::{NetraError, Result};
#[cfg(windows)]
use netra_core::observation::{ObservationPayload, ProcessObservationPayload, ProcessRecord};
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::fs::File;
#[cfg(windows)]
use std::io::Read;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Maximum executable file size to hash (50MB).
pub const MAX_HASHABLE_BINARY_BYTES: u64 = 50 * 1024 * 1024;

/// Computes SHA-256 hash of an executable binary with bounded file size.
#[cfg(windows)]
pub fn hash_executable_binary<P: AsRef<Path>>(path: P) -> Option<String> {
    let p = path.as_ref();
    let metadata = std::fs::metadata(p).ok()?;
    if metadata.len() > MAX_HASHABLE_BINARY_BYTES {
        return None;
    }

    let mut file = File::open(p).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => return None,
        }
    }

    Some(hex::encode(hasher.finalize()))
}

/// Collects processes from the Windows kernel via Toolhelp32 and QueryFullProcessImageName.
#[cfg(windows)]
pub fn collect_windows_processes(hash_binaries: bool) -> Result<ObservationPayload> {
    let mut records = Vec::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
        return Err(NetraError::platform(
            "Failed to create Win32 Toolhelp32 snapshot for process collection",
        ));
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut success = unsafe { Process32FirstW(snapshot, &mut entry) };

    while success != 0 {
        let pid = entry.th32ProcessID;
        let ppid = if entry.th32ParentProcessID > 0 {
            Some(entry.th32ParentProcessID)
        } else {
            None
        };

        // Extract executable name from wchar array
        let name_len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let exe_name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

        // Attempt to query full image path with read-only query permissions
        let mut exe_path: Option<String> = None;
        let h_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if !h_proc.is_null() && h_proc != INVALID_HANDLE_VALUE {
            let mut path_buf = [0u16; 1024];
            let mut size: u32 = path_buf.len() as u32;
            let query_res = unsafe {
                QueryFullProcessImageNameW(
                    h_proc,
                    PROCESS_NAME_WIN32,
                    path_buf.as_mut_ptr(),
                    &mut size,
                )
            };
            if query_res != 0 && size > 0 {
                exe_path = Some(String::from_utf16_lossy(&path_buf[..size as usize]));
            }
            unsafe { CloseHandle(h_proc) };
        }

        let sha256_binary_hash = if hash_binaries {
            exe_path.as_ref().and_then(hash_executable_binary)
        } else {
            None
        };

        records.push(ProcessRecord {
            pid,
            ppid,
            name: exe_name,
            executable_path: exe_path,
            sha256_binary_hash,
            start_time: None,
            username: None,
            memory_rss_bytes: 0,
            has_command_line_args: false, // Arguments kept strictly ephemeral
        });

        success = unsafe { Process32NextW(snapshot, &mut entry) };
    }

    unsafe { CloseHandle(snapshot) };

    Ok(ObservationPayload::Processes(ProcessObservationPayload {
        processes: records,
    }))
}

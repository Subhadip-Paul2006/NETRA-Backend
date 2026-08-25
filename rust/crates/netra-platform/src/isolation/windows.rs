//! Windows Win32 Job Object process isolation and resource limits.

use netra_core::error::NetraError;
use tracing::{debug, info};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

use crate::isolation::traits::ProcessIsolation;

/// Windows Job Object container enforcing memory bounds and parent-death teardown.
pub struct WindowsJobIsolation {
    job_handle: HANDLE,
    memory_limit_bytes: u64,
}

// SAFETY: Windows HANDLE for Job Objects can be safely accessed across threads.
unsafe impl Send for WindowsJobIsolation {}
unsafe impl Sync for WindowsJobIsolation {}

impl WindowsJobIsolation {
    /// Creates and configures a new anonymous Win32 Job Object.
    pub fn new(memory_limit_bytes: u64) -> Result<Self, NetraError> {
        let job_handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job_handle.is_null() || job_handle == INVALID_HANDLE_VALUE {
            return Err(NetraError::platform(
                "Failed to create Win32 Job Object for worker isolation",
            ));
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        info.ProcessMemoryLimit = memory_limit_bytes as usize;

        let ret = unsafe {
            SetInformationJobObject(
                job_handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };

        if ret == 0 {
            unsafe { CloseHandle(job_handle) };
            return Err(NetraError::platform(
                "Failed to set resource limits on Win32 Job Object",
            ));
        }

        info!(
            memory_limit_mb = memory_limit_bytes / (1024 * 1024),
            "Initialized Win32 Job Object isolation container"
        );

        Ok(Self {
            job_handle,
            memory_limit_bytes,
        })
    }
}

impl ProcessIsolation for WindowsJobIsolation {
    fn name(&self) -> &'static str {
        "Win32 Job Object"
    }

    fn configure_command(&self, _cmd: &mut tokio::process::Command) -> Result<(), NetraError> {
        // Windows job objects are assigned post-spawn using the child PID.
        Ok(())
    }

    fn apply_to_pid(&self, pid: u32) -> Result<(), NetraError> {
        let proc_handle = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };

        if proc_handle.is_null() || proc_handle == INVALID_HANDLE_VALUE {
            return Err(NetraError::platform(format!(
                "Failed to open process handle for PID {} to assign Job Object",
                pid
            )));
        }

        let ret = unsafe { AssignProcessToJobObject(self.job_handle, proc_handle) };
        unsafe { CloseHandle(proc_handle) };

        if ret == 0 {
            return Err(NetraError::platform(format!(
                "Failed to assign PID {} to Win32 Job Object",
                pid
            )));
        }

        debug!(
            pid = pid,
            "Successfully assigned worker PID to Win32 Job Object"
        );
        Ok(())
    }

    fn memory_limit_bytes(&self) -> u64 {
        self.memory_limit_bytes
    }
}

impl Drop for WindowsJobIsolation {
    fn drop(&mut self) {
        if !self.job_handle.is_null() && self.job_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.job_handle);
            }
        }
    }
}

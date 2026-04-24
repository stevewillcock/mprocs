pub mod process;
pub mod process_spec;
#[cfg(unix)]
pub mod unix_process;
#[cfg(unix)]
pub mod unix_processes_waiter;
#[cfg(windows)]
pub mod win_process;
#[cfg(target_os = "linux")]
pub mod linux_process;

#[cfg(target_os = "linux")]
pub type NativeProcess = linux_process::LinuxProcess;
#[cfg(all(unix, not(target_os = "linux")))]
pub type NativeProcess = unix_process::UnixProcess;
#[cfg(windows)]
pub type NativeProcess = win_process::WinProcess;

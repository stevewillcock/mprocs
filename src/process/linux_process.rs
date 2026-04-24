use std::sync::atomic::{AtomicUsize, Ordering};

use rustix::{process::WaitStatus, termios::Pid};

use crate::{kernel::task::TaskId, term::Winsize};

use super::{
  process::Process, process_spec::ProcessSpec, unix_process::UnixProcess,
};

static SCOPE_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Linux-specific backend: spawns the process inside a transient systemd
/// user scope via `systemd-run --user --scope`. Graceful signals target the
/// pgrp (matching terminal Ctrl+C behavior); the nuclear `kill` path uses
/// `systemctl --user kill --kill-whom=all` so it reaches every descendant
/// in the scope, including daemonized/reparented processes like `conmon`.
pub struct LinuxProcess {
  inner: UnixProcess,
  unit_name: String,
  pub pid: Pid,
}

impl LinuxProcess {
  pub fn spawn(
    id: TaskId,
    spec: &ProcessSpec,
    size: Winsize,
    on_wait_returned: Box<dyn Fn(WaitStatus) + Send + Sync>,
  ) -> std::io::Result<Self> {
    let counter = SCOPE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let unit_name = format!(
      "mprocs-{}-t{}-n{}.scope",
      std::process::id(),
      id.0,
      counter,
    );

    let mut args: Vec<String> = vec![
      "--user".into(),
      "--scope".into(),
      "--quiet".into(),
      "--collect".into(),
      format!("--unit={}", unit_name),
      "--".into(),
      spec.prog.clone(),
    ];
    args.extend(spec.args.iter().cloned());

    let wrapped = ProcessSpec {
      prog: "systemd-run".into(),
      args,
      cwd: spec.cwd.clone(),
      env: spec.env.clone(),
    };

    let inner = UnixProcess::spawn(id, &wrapped, size, on_wait_returned)?;
    let pid = inner.pid;

    Ok(LinuxProcess {
      inner,
      unit_name,
      pid,
    })
  }
}

impl Process for LinuxProcess {
  fn on_exited(&mut self) {
    self.inner.on_exited();
  }

  async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    self.inner.read(buf).await
  }

  async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    self.inner.write(buf).await
  }

  async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
    self.inner.write_all(buf).await
  }

  fn send_signal(&mut self, sig: i32) -> std::io::Result<()> {
    // Graceful path: target the foreground pgrp. Matches terminal Ctrl+C:
    // same-pgrp processes get the signal, background pgrps keep running and
    // can finish draining output. For the nuclear path, see `kill` below.
    let pid: i32 = self.pid.as_raw_nonzero().into();
    if unsafe { libc::killpg(pid, sig) } < 0 {
      return Err(std::io::Error::last_os_error());
    }
    Ok(())
  }

  async fn kill(&mut self) -> std::io::Result<()> {
    // Nuclear path: SIGKILL the whole cgroup. Reaches anything that survived
    // signals, including processes reparented to systemd (e.g. conmon).
    let _ = tokio::process::Command::new("systemctl")
      .args([
        "--user",
        "kill",
        "--kill-whom=all",
        "--signal=SIGKILL",
        &self.unit_name,
      ])
      .stdout(std::process::Stdio::null())
      .stderr(std::process::Stdio::null())
      .status()
      .await;
    Ok(())
  }

  fn resize(&mut self, size: Winsize) -> std::io::Result<()> {
    self.inner.resize(size)
  }
}

use std::fmt::Debug;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::error::ResultLogger;
use crate::kernel::kernel_message::SharedVt;
use crate::kernel::task::TaskId;
use crate::mprocs::proc_log_config::{LogConfig, LogMode};
use crate::process::process::Process as _;
use crate::process::process_spec::ProcessSpec;
use crate::process::NativeProcess;
use crate::term::Winsize;

use super::msg::ProcEvent;
use super::ports::scan_listening_ports;
use super::Size;

const PORT_SCAN_INTERVAL: Duration = Duration::from_secs(2);

pub struct Inst {
  pub vt: SharedVt,
  pub log_writer: Option<tokio::fs::File>,

  pub pid: u32,
  pub process: NativeProcess,
  pub exit_code: Option<u32>,
  pub stdout_eof: bool,

  ports_scanner: Option<JoinHandle<()>>,
}

impl Drop for Inst {
  fn drop(&mut self) {
    if let Some(handle) = self.ports_scanner.take() {
      handle.abort();
    }
  }
}

impl Debug for Inst {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Inst")
      .field("pid", &self.pid)
      .field("exited", &self.exit_code)
      .field("stdout_eof", &self.stdout_eof)
      .finish()
  }
}

impl Inst {
  pub async fn spawn(
    id: TaskId,
    name: &str,
    spec: &ProcessSpec,
    tx: UnboundedSender<ProcEvent>,
    size: &Size,
    scrollback_len: usize,
    log: Option<&LogConfig>,
  ) -> anyhow::Result<Self> {
    let vt = crate::term::Parser::new(size.height, size.width, scrollback_len);
    let vt = SharedVt::new(vt);

    tx.send(ProcEvent::SetVt(Some(vt.clone()))).log_ignore();

    #[cfg(unix)]
    let process = {
      crate::process::NativeProcess::spawn(
        id,
        spec,
        Winsize {
          x: size.width,
          y: size.height,
          x_px: 0,
          y_px: 0,
        },
        {
          let tx = tx.clone();
          Box::new(move |wait_status| {
            let exit_code = wait_status.exit_status().unwrap_or(212);
            let _result = tx.send(ProcEvent::Exited(exit_code as u32));
          })
        },
      )?
    };
    #[cfg(unix)]
    let pid: i32 = process.pid.as_raw_nonzero().into();

    #[cfg(windows)]
    let process = {
      use anyhow::Context as _;

      crate::process::win_process::WinProcess::spawn(
        id,
        spec,
        Winsize {
          x: size.width,
          y: size.height,
          x_px: 0,
          y_px: 0,
        },
        {
          let tx = tx.clone();
          Box::new(move |exit_code| {
            let exit_code = exit_code.unwrap_or(213);
            let _result = tx.send(ProcEvent::Exited(exit_code as u32));
          })
        },
      )
      .context("WinProcess::spawn")?
    };
    #[cfg(windows)]
    let pid: i32 = process.pid;

    let log_file = log.and_then(|log| log.file_path(name, id.0, pid as u32));
    let log_writer = match log_file {
      Some(path) => {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
          std::fs::create_dir_all(parent).log_ignore();
        }
        let append = log.is_some_and(|log| log.mode() == LogMode::Append);
        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).write(true).append(append);
        if !append {
          options.truncate(true);
        }
        options
          .open(&path)
          .await
          .map_err(|e| log::warn!("Failed to open log file {:?}: {}", path, e))
          .ok()
      }
      None => None,
    };

    tx.send(ProcEvent::Started).log_ignore();

    let pid_u32 = pid as u32;
    let ports_scanner = {
      let tx = tx.clone();
      Some(tokio::spawn(async move {
        let mut timer = tokio::time::interval(PORT_SCAN_INTERVAL);
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last: Vec<u16> = Vec::new();
        loop {
          timer.tick().await;
          let ports = tokio::task::spawn_blocking(move || {
            scan_listening_ports(pid_u32)
          })
          .await
          .unwrap_or_default();
          if ports != last {
            if tx.send(ProcEvent::PortsUpdated(ports.clone())).is_err() {
              break;
            }
            last = ports;
          }
        }
      }))
    };

    let inst = Inst {
      vt,
      log_writer,

      process,
      pid: pid_u32,
      exit_code: None,
      stdout_eof: false,

      ports_scanner,
    };
    Ok(inst)
  }

  pub fn resize(&mut self, size: &Size) {
    let rows = size.height;
    let cols = size.width;

    self
      .process
      .resize(Winsize {
        x: size.width,
        y: size.height,
        x_px: 0,
        y_px: 0,
      })
      .log_ignore();

    if let Ok(mut vt) = self.vt.write() {
      vt.set_size(rows, cols);
    }
  }
}

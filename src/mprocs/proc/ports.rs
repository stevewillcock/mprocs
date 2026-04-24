//! Listening TCP port discovery for a proc and everything under it.
//!
//! On Linux we rely on the process being inside a systemd user scope (set up
//! by the `LinuxProcess` backend) so the cgroup is the authoritative set of
//! "everything this proc owns", including processes that have daemonized and
//! been reparented to the user manager (conmon, etc). For each pid in the
//! cgroup we enumerate `/proc/<pid>/fd` and collect socket inodes (mapped
//! back to the owning pid), then match those against LISTEN rows of
//! `/proc/net/tcp{,6}` to produce `PortInfo` entries (port, pid, comm).

use crate::kernel::task::PortInfo;

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};

#[cfg(target_os = "linux")]
const FD_READLINK_BUDGET: usize = 10_000;

#[cfg(target_os = "linux")]
pub fn scan_listening_ports(root_pid: u32) -> Vec<PortInfo> {
  let pids = pids_in_cgroup(root_pid);
  let inode_to_pid = inode_to_pid_map(&pids);
  if inode_to_pid.is_empty() {
    return Vec::new();
  }
  let listeners = listeners_for_inodes(&inode_to_pid);
  let mut comm_cache: HashMap<u32, String> = HashMap::new();
  let mut result: Vec<PortInfo> = listeners
    .into_iter()
    .map(|(inode, port)| {
      let pid = inode_to_pid[&inode];
      let comm = comm_cache
        .entry(pid)
        .or_insert_with(|| read_comm(pid))
        .clone();
      PortInfo { port, pid, comm }
    })
    .collect();

  // Rootless podman binds via a helper named "rootlessport" that holds the
  // host-side socket; the useful identity is the container it proxies for.
  // Call `podman ps` at most once per scan, then rewrite matching ports.
  if result.iter().any(|p| p.comm == "rootlessport") {
    let pmap = podman_port_map();
    if !pmap.is_empty() {
      for info in result.iter_mut() {
        if info.comm == "rootlessport" {
          if let Some(name) = pmap.get(&info.port) {
            info.comm = name.clone();
          }
        }
      }
    }
  }

  result.sort_unstable_by(|a, b| (a.port, a.pid).cmp(&(b.port, b.pid)));
  result.dedup();
  result
}

#[cfg(not(target_os = "linux"))]
pub fn scan_listening_ports(_root_pid: u32) -> Vec<PortInfo> {
  Vec::new()
}

#[cfg(target_os = "linux")]
fn pids_in_cgroup(root_pid: u32) -> HashSet<u32> {
  let mut pids = HashSet::new();
  pids.insert(root_pid);

  if let Some(cgroup_path) = read_cgroup_path(root_pid) {
    let procs_file =
      format!("/sys/fs/cgroup{}/cgroup.procs", cgroup_path);
    if let Ok(contents) = std::fs::read_to_string(&procs_file) {
      for line in contents.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
          pids.insert(pid);
        }
      }
    }
  }

  pids
}

#[cfg(target_os = "linux")]
fn read_cgroup_path(pid: u32) -> Option<String> {
  let contents =
    std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
  for line in contents.lines() {
    if let Some(rest) = line.strip_prefix("0::") {
      return Some(rest.to_string());
    }
  }
  None
}

#[cfg(target_os = "linux")]
fn inode_to_pid_map(pids: &HashSet<u32>) -> HashMap<u64, u32> {
  let mut inodes: HashMap<u64, u32> = HashMap::new();
  let mut budget = FD_READLINK_BUDGET;
  'outer: for &pid in pids {
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = match std::fs::read_dir(&fd_dir) {
      Ok(e) => e,
      Err(_) => continue,
    };
    for entry in entries.flatten() {
      if budget == 0 {
        log::debug!("ports scan hit readlink budget");
        break 'outer;
      }
      budget -= 1;
      let target = match std::fs::read_link(entry.path()) {
        Ok(t) => t,
        Err(_) => continue,
      };
      let s = match target.to_str() {
        Some(s) => s,
        None => continue,
      };
      if let Some(rest) = s.strip_prefix("socket:[") {
        if let Some(inode_str) = rest.strip_suffix(']') {
          if let Ok(inode) = inode_str.parse::<u64>() {
            // First pid wins; shared inodes (e.g. inherited via fork) are
            // rare here and attribution by first-seen is good enough.
            inodes.entry(inode).or_insert(pid);
          }
        }
      }
    }
  }
  inodes
}

#[cfg(target_os = "linux")]
fn listeners_for_inodes(
  inodes: &HashMap<u64, u32>,
) -> Vec<(u64, u16)> {
  const LISTEN: &str = "0A";
  let mut out = Vec::new();
  for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
    let contents = match std::fs::read_to_string(path) {
      Ok(c) => c,
      Err(_) => continue,
    };
    for (i, line) in contents.lines().enumerate() {
      if i == 0 {
        continue;
      }
      let mut cols = line.split_whitespace();
      let _sl = cols.next();
      let Some(local) = cols.next() else { continue };
      let _rem = cols.next();
      let Some(st) = cols.next() else { continue };
      if st != LISTEN {
        continue;
      }
      // Skip tx_queue:rx_queue, timer:when, retransmit, uid, timeout.
      let Some(inode_str) = cols.nth(5) else { continue };
      let Ok(inode) = inode_str.parse::<u64>() else {
        continue;
      };
      if !inodes.contains_key(&inode) {
        continue;
      }
      if let Some((_, port_hex)) = local.rsplit_once(':') {
        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
          out.push((inode, port));
        }
      }
    }
  }
  out
}

#[cfg(target_os = "linux")]
fn read_comm(pid: u32) -> String {
  match std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
    Ok(s) => s.trim_end_matches('\n').to_string(),
    Err(_) => String::new(),
  }
}

/// Shell out to `podman ps` once and build a host-port → container-name map.
/// Empty result on any failure (podman missing, daemon issue, parse error),
/// which leaves rootlessport entries untouched and falls back to the bare
/// `rootlessport` label.
#[cfg(target_os = "linux")]
fn podman_port_map() -> HashMap<u16, String> {
  let mut map = HashMap::new();
  let output = match std::process::Command::new("podman")
    .args(["ps", "--format", "{{.Names}}\t{{.Ports}}"])
    .output()
  {
    Ok(o) if o.status.success() => o,
    _ => return map,
  };
  let text = match std::str::from_utf8(&output.stdout) {
    Ok(t) => t,
    Err(_) => return map,
  };
  for line in text.lines() {
    let mut parts = line.splitn(2, '\t');
    let name = match parts.next() {
      Some(n) if !n.is_empty() => n,
      _ => continue,
    };
    let ports_str = parts.next().unwrap_or("");
    // Ports format: "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp" (comma-sep).
    // Host port can also be a range: "0.0.0.0:4317-4318->18889-18890/tcp".
    // We extract the digits immediately left of "->" (single or range).
    for entry in ports_str.split(',').map(|s| s.trim()) {
      let Some((hostpart, _)) = entry.split_once("->") else {
        continue;
      };
      let host_port_str =
        hostpart.rsplit_once(':').map_or(hostpart, |(_, p)| p);
      if let Some((start, end)) = host_port_str.split_once('-') {
        if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
          for port in s..=e {
            map.insert(port, name.to_string());
          }
        }
      } else if let Ok(port) = host_port_str.parse::<u16>() {
        map.insert(port, name.to_string());
      }
    }
  }
  map
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use super::*;

  #[test]
  fn scan_finds_own_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let found = scan_listening_ports(std::process::id());
    let entry = found.iter().find(|p| p.port == port);
    assert!(entry.is_some(), "expected port {} in {:?}", port, found);
    let entry = entry.unwrap();
    assert_eq!(entry.pid, std::process::id());
    assert!(!entry.comm.is_empty(), "expected non-empty comm");
  }
}

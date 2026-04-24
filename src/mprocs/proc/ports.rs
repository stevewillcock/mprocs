//! Listening TCP port discovery for a proc and everything under it.
//!
//! On Linux we rely on the process being inside a systemd user scope (set up
//! by the `LinuxProcess` backend) so the cgroup is the authoritative set of
//! "everything this proc owns", including processes that have daemonized and
//! been reparented to the user manager (conmon, etc). For each pid in the
//! cgroup we enumerate `/proc/<pid>/fd` and collect socket inodes, then
//! match those against LISTEN rows of `/proc/net/tcp{,6}`.

#[cfg(target_os = "linux")]
use std::collections::HashSet;

#[cfg(target_os = "linux")]
const FD_READLINK_BUDGET: usize = 10_000;

#[cfg(target_os = "linux")]
pub fn scan_listening_ports(root_pid: u32) -> Vec<u16> {
  let pids = pids_in_cgroup(root_pid);
  let inodes = socket_inodes_for_pids(&pids);
  if inodes.is_empty() {
    return Vec::new();
  }
  listening_ports_for_inodes(&inodes)
}

#[cfg(not(target_os = "linux"))]
pub fn scan_listening_ports(_root_pid: u32) -> Vec<u16> {
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
fn socket_inodes_for_pids(pids: &HashSet<u32>) -> HashSet<u64> {
  let mut inodes = HashSet::new();
  let mut budget = FD_READLINK_BUDGET;
  'outer: for pid in pids {
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
            inodes.insert(inode);
          }
        }
      }
    }
  }
  inodes
}

#[cfg(target_os = "linux")]
fn listening_ports_for_inodes(inodes: &HashSet<u64>) -> Vec<u16> {
  const LISTEN: &str = "0A";
  let mut ports = Vec::new();
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
      if !inodes.contains(&inode) {
        continue;
      }
      if let Some((_, port_hex)) = local.rsplit_once(':') {
        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
          ports.push(port);
        }
      }
    }
  }
  ports.sort_unstable();
  ports.dedup();
  ports
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use super::*;

  #[test]
  fn scan_finds_own_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let found = scan_listening_ports(std::process::id());
    assert!(
      found.contains(&port),
      "expected {} in {:?}",
      port,
      found
    );
  }
}

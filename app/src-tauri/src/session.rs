//! SSH access to the head unit through the system `ssh` client.
//!
//! The unit runs OpenSSH 5.2 and only offers SHA-1 based algorithms (ssh-rsa, DH group14/group1 or
//! group exchange). libssh2 builds without SHA-1 cannot talk to it, so we use the same legacy
//! options as `source/tools/capture_headunit.py` with the OS `ssh` binary.

use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SSH: &str = "/usr/bin/ssh";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
const MAX_OUTPUT: u64 = 4 << 20;
const LEGACY: [&str; 4] = [
    "HostKeyAlgorithms=+ssh-rsa",
    "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
    "Ciphers=+aes128-cbc,aes256-cbc,3des-cbc",
    "MACs=+hmac-sha1,hmac-sha1-96",
];

pub struct Connection {
    ip: Ipv4Addr,
    known_hosts: PathBuf,
    password: Option<String>,
    askpass: Option<PathBuf>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(path) = &self.askpass {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn enet_ip(value: &str) -> Result<Ipv4Addr, String> {
    let ip: Ipv4Addr = value.trim().parse().map_err(|_| "enter the head unit's IPv4 address".to_string())?;
    let o = ip.octets();
    if !ip.is_link_local() || o[2] == 0 || o[2] == 255 {
        return Err("use the head unit's wired 169.254.x.x ENET IP".into());
    }
    Ok(ip)
}

fn known_hosts_path(ip: Ipv4Addr) -> PathBuf {
    std::env::temp_dir().join(format!("id6-known-hosts-{ip}"))
}

fn base_args(known_hosts: &Path, host_key_checking: &str) -> Vec<String> {
    let mut args = vec![
        "-o".to_string(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        format!("StrictHostKeyChecking={host_key_checking}"),
    ];
    for option in LEGACY {
        args.push("-o".into());
        args.push(option.into());
    }
    args
}

fn reach_error(ip: Ipv4Addr, stderr: &str) -> String {
    format!("cannot reach {ip}:22 ({}). SSH may be closed: enable it with an unlock tool first", stderr.trim())
}

/// Parses the SHA256 fingerprint out of `ssh-keygen -lf` output.
fn parse_fingerprint(output: &str) -> Option<String> {
    output
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .filter(|f| f.starts_with("SHA256:"))
        .map(str::to_string)
}

fn fingerprint(known_hosts: &Path) -> Result<String, String> {
    let out = Command::new(SSH_KEYGEN)
        .arg("-lf")
        .arg(known_hosts)
        .output()
        .map_err(|e| format!("cannot run ssh-keygen: {e}"))?;
    parse_fingerprint(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| "no host key was received".to_string())
}

/// Connects without authenticating, stores the host key and returns its fingerprint for the user to confirm.
pub fn probe_host_key(ip: Ipv4Addr) -> Result<String, String> {
    let known_hosts = known_hosts_path(ip);
    let _ = fs::remove_file(&known_hosts);
    let out = Command::new(SSH)
        .args(base_args(&known_hosts, "accept-new"))
        .args(["-o", "BatchMode=yes", "-o", "PreferredAuthentications=none"])
        .arg(format!("root@{ip}"))
        .arg("true")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run ssh: {e}"))?;
    if !known_hosts.exists() {
        return Err(reach_error(ip, &String::from_utf8_lossy(&out.stderr)));
    }
    fingerprint(&known_hosts)
}

#[cfg(unix)]
fn write_askpass(ip: Ipv4Addr) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!("id6-askpass-{}-{ip}.sh", std::process::id()));
    let _ = fs::remove_file(&path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&path)
        .map_err(|e| e.to_string())?;
    file.write_all(b"#!/bin/sh\nprintf '%s\\n' \"$ID6_SSH_PASSWORD\"\n").map_err(|e| e.to_string())?;
    Ok(path)
}

#[cfg(not(unix))]
fn write_askpass(_ip: Ipv4Addr) -> Result<PathBuf, String> {
    Err("password login is only supported on macOS and Linux".into())
}

/// Requires the host key to match `expected`, then checks that root can log in.
pub fn connect(ip: Ipv4Addr, expected: &str, password: Option<&str>) -> Result<Connection, String> {
    let known_hosts = known_hosts_path(ip);
    if !known_hosts.exists() || fingerprint(&known_hosts)? != expected {
        return Err("the host key changed since you confirmed it. Check the connection and retry".into());
    }
    let password = password.filter(|p| !p.is_empty()).map(str::to_string);
    let askpass = if password.is_some() { Some(write_askpass(ip)?) } else { None };
    let conn = Connection { ip, known_hosts, password, askpass };
    run(&conn, "true", false).map_err(|e| format!("SSH login failed: {e}. Enter the password"))?;
    Ok(conn)
}

fn exec(conn: &Connection, command: &str) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(SSH);
    cmd.args(base_args(&conn.known_hosts, "yes"));
    match &conn.askpass {
        Some(askpass) => {
            cmd.args(["-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1"])
                .args(["-o", "PreferredAuthentications=password,keyboard-interactive"])
                .env("SSH_ASKPASS", askpass)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("ID6_SSH_PASSWORD", conn.password.as_deref().unwrap_or_default());
        }
        None => {
            cmd.args(["-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey"]);
        }
    }
    let mut child = cmd
        .arg(format!("root@{}", conn.ip))
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run ssh: {e}"))?;
    let mut out = Vec::new();
    child
        .stdout
        .take()
        .ok_or("no output stream")?
        .take(MAX_OUTPUT + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() as u64 > MAX_OUTPUT {
        let _ = child.kill();
        let _ = child.wait();
        return Err("returned more data than expected".into());
    }
    let mut stderr = String::new();
    if let Some(s) = child.stderr.take() {
        let _ = s.take(64 << 10).read_to_string(&mut stderr);
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    match status.code() {
        Some(0) => Ok(out),
        Some(code) => Err(format!("exit status {code}: {}", stderr.trim())),
        None => Err("ssh was terminated".into()),
    }
}

pub fn run(conn: &Connection, command: &str, optional: bool) -> Result<Vec<u8>, String> {
    match exec(conn, command) {
        Err(_) if optional => Ok(vec![]),
        other => other.map_err(|e| format!("{command} failed over SSH: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_enet_ip() {
        assert!(enet_ip("169.254.10.3").is_ok());
    }

    #[test]
    fn rejects_non_link_local() {
        assert!(enet_ip("192.168.1.2").is_err());
    }

    #[test]
    fn parses_keygen_fingerprint() {
        let line = "2048 SHA256:ccBSjAKu0zGcw8z2GuJpODkfbHkHFg+6hJRdU9HjB2Q 169.254.199.99 (RSA)\n";
        assert_eq!(
            parse_fingerprint(line).as_deref(),
            Some("SHA256:ccBSjAKu0zGcw8z2GuJpODkfbHkHFg+6hJRdU9HjB2Q")
        );
        assert_eq!(parse_fingerprint(""), None);
    }

    #[test]
    fn legacy_options_cover_the_unit() {
        assert!(LEGACY.iter().any(|o| o.contains("ssh-rsa")));
        assert!(LEGACY.iter().any(|o| o.contains("diffie-hellman-group14-sha1")));
    }
}

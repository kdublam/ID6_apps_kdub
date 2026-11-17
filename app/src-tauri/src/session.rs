//! SSH session to the head unit using libssh2 with the legacy algorithms the unit requires.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ssh2::{HashType, MethodType, Session};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT_MS: u32 = 60_000;
const MAX_OUTPUT: u64 = 4 << 20;
const KEX: &str = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
const HOST_KEY: &str = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
const CIPHERS: &str = "aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc,3des-cbc";
const MACS: &str = "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96";

pub fn enet_ip(value: &str) -> Result<Ipv4Addr, String> {
    let ip: Ipv4Addr = value.trim().parse().map_err(|_| "enter the head unit's IPv4 address".to_string())?;
    let o = ip.octets();
    if !ip.is_link_local() || o[2] == 0 || o[2] == 255 {
        return Err("use the head unit's wired 169.254.x.x ENET IP".into());
    }
    Ok(ip)
}

pub fn apply_legacy_methods(session: &Session) -> Result<(), ssh2::Error> {
    session.method_pref(MethodType::Kex, KEX)?;
    session.method_pref(MethodType::HostKey, HOST_KEY)?;
    session.method_pref(MethodType::CryptCs, CIPHERS)?;
    session.method_pref(MethodType::CryptSc, CIPHERS)?;
    session.method_pref(MethodType::MacCs, MACS)?;
    session.method_pref(MethodType::MacSc, MACS)
}

fn handshake(ip: Ipv4Addr) -> Result<Session, String> {
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), 22), TIMEOUT)
        .map_err(|e| format!("cannot reach {ip}:22 ({e}). SSH may be closed: enable it with an unlock tool first"))?;
    let mut session = Session::new().map_err(|e| e.to_string())?;
    apply_legacy_methods(&session).map_err(|e| format!("SSH algorithm setup failed: {e}"))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(COMMAND_TIMEOUT_MS);
    session.handshake().map_err(|e| format!("SSH handshake failed: {e}"))?;
    Ok(session)
}

fn fingerprint(session: &Session) -> Result<String, String> {
    let hash = session.host_key_hash(HashType::Sha256).ok_or("no host key hash available")?;
    Ok(format!("SHA256:{}", STANDARD_NO_PAD.encode(hash)))
}

/// Connects without authenticating and returns the host key fingerprint for the user to confirm.
pub fn probe_host_key(ip: Ipv4Addr) -> Result<String, String> {
    fingerprint(&handshake(ip)?)
}

/// Connects, requires the host key to match `expected`, then authenticates as root.
pub fn connect(ip: Ipv4Addr, expected: &str, password: Option<&str>) -> Result<Session, String> {
    let session = handshake(ip)?;
    if fingerprint(&session)? != expected {
        return Err("the host key changed since you confirmed it. Check the connection and retry".into());
    }
    match password.filter(|p| !p.is_empty()) {
        Some(p) => session.userauth_password("root", p).map_err(|e| format!("SSH login failed: {e}"))?,
        None => session.userauth_agent("root").map_err(|e| format!("SSH login failed: {e}. Enter the password"))?,
    }
    session.authenticated().then_some(session).ok_or_else(|| "SSH login failed".into())
}

pub fn run(session: &Session, command: &str, optional: bool) -> Result<Vec<u8>, String> {
    let result = (|| -> Result<Vec<u8>, String> {
        let mut channel = session.channel_session().map_err(|e| e.to_string())?;
        channel.exec(command).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        channel.by_ref().take(MAX_OUTPUT + 1).read_to_end(&mut out).map_err(|e| e.to_string())?;
        if out.len() as u64 > MAX_OUTPUT {
            return Err("returned more data than expected".into());
        }
        channel.wait_close().map_err(|e| e.to_string())?;
        match channel.exit_status().map_err(|e| e.to_string())? {
            0 => Ok(out),
            code => Err(format!("exit status {code}")),
        }
    })();
    match result {
        Err(_) if optional => Ok(vec![]),
        other => other.map_err(|e| format!("{command} failed over SSH: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_algorithms_are_available_in_this_build() {
        assert!(apply_legacy_methods(&Session::new().unwrap()).is_ok());
    }

    #[test]
    fn accepts_enet_ip() {
        assert!(enet_ip("169.254.10.3").is_ok());
    }

    #[test]
    fn rejects_non_link_local() {
        assert!(enet_ip("192.168.1.2").is_err());
    }
}

//! Read-only evidence capture, ported from `source/tools/capture_headunit.py`.

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const FRAMEWORKS: [&str; 2] = ["libAppFramework.A.so", "libCoreFramework.A.so"];
const FRAMEWORK_DIR: &str = "/opt/hmi/ID5/lib";
const FIRMWARE_FILE: &str = "/opt/sys/etc/nbt_version.txt";
const SCREEN: &str = "/opt/sys/bin/LayerManagerControl get screen 0";
const JACINTO_FIRMWARE_FILE: &str = "/etc/nbt_version.txt";
const JACINTO_FRAMEWORK_DIRS: [&str; 2] = [
    "/net/hu-omap/fs/sda0/repository/istep/opt/hmi/ID5/lib",
    "/net/hu-omap/fs/sda0/opt/hmi/ID5/lib",
];
const JACINTO_IFCONFIG: &str = "on -f hu-omap /sbin/ifconfig";
const JACINTO_SCREEN: &str = "on -f hu-omap sh -c \"export LD_LIBRARY_PATH=/opt/sys/lib:/usr/lib:/lib; /opt/sys/bin/LayerManagerControl get screen 0\"";
const ELF_ARM_MACHINE: u16 = 40;
const ELF_SHARED_OBJECT: u16 = 3;

/// Runs one command on the head unit. `optional` turns failures into empty output.
pub type Reader<'a> = dyn FnMut(&str, bool) -> Result<Vec<u8>, String> + 'a;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Display {
    pub width: u32,
    pub height: u32,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct FrameworkInfo {
    pub sha256: String,
    pub size_bytes: usize,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Report {
    pub firmware: String,
    pub firmware_source: String,
    pub os: String,
    pub os_release: String,
    pub architecture: String,
    pub ssh_node: String,
    pub hmi_node_ip: Option<String>,
    pub framework_dir: String,
    pub display: Option<Display>,
    pub frameworks: BTreeMap<String, FrameworkInfo>,
}

fn firmware_re() -> Regex {
    Regex::new(r"(?i)\bNBTevo_([A-Z][0-9]{5}[A-Z])\b").unwrap()
}

pub fn firmware_name(text: &str) -> String {
    firmware_re()
        .captures(text)
        .map(|c| format!("NBTevo_{}", c[1].to_uppercase()))
        .unwrap_or_default()
}

pub fn is_arm_elf(data: &[u8]) -> bool {
    data.len() >= 20
        && data[..6] == [0x7f, b'E', b'L', b'F', 1, 1]
        && u16::from_le_bytes([data[16], data[17]]) == ELF_SHARED_OBJECT
        && u16::from_le_bytes([data[18], data[19]]) == ELF_ARM_MACHINE
}

fn parse_display(output: &[u8]) -> Option<Display> {
    let re = Regex::new(r"(?i)resolution:\s*x\s*=\s*([0-9]{2,4}),\s*y\s*=\s*([0-9]{2,4})\b").unwrap();
    let text = String::from_utf8_lossy(output);
    let c = re.captures(&text)?;
    Some(Display { width: c[1].parse().ok()?, height: c[2].parse().ok()? })
}

fn parse_hmi_ip(output: &[u8]) -> Option<String> {
    let re = Regex::new(r"\binet (169\.254\.\d{1,3}\.\d{1,3})\b").unwrap();
    re.captures(&String::from_utf8_lossy(output)).map(|c| c[1].to_string())
}

pub fn capture(read: &mut Reader, entered: Option<&str>) -> Result<Report, String> {
    let uname = String::from_utf8_lossy(&read("uname -a", false)?).into_owned();
    let platform: Vec<&str> = uname.split_whitespace().collect();
    if platform.len() < 4 || platform[0] != "QNX" || platform[platform.len() - 1] != "armle" {
        return Err("expected an ARM QNX head unit".into());
    }
    let node = platform[1];
    let (ssh_node, split) = if node.contains("jacinto") {
        ("hu-jacinto", true)
    } else if node.contains("omap") {
        ("hu-omap", false)
    } else {
        ("unknown", false)
    };

    let firmware_file = if split { JACINTO_FIRMWARE_FILE } else { FIRMWARE_FILE };
    let detected = firmware_name(&String::from_utf8_lossy(&read(&format!("cat {firmware_file}"), true)?));
    let entered = entered.map(str::trim).filter(|s| !s.is_empty());
    if let Some(e) = entered {
        if !firmware_re().find(e).is_some_and(|m| m.as_str() == e) {
            return Err("enter the exact NBTevo firmware code shown on iDrive".into());
        }
    }
    let entered = entered.map(firmware_name).unwrap_or_default();
    if !detected.is_empty() && !entered.is_empty() && detected != entered {
        return Err("the iDrive firmware code differs from the one reported over SSH".into());
    }
    if detected.is_empty() && entered.is_empty() {
        return Err("firmware code unavailable over SSH. Enter the exact code shown on iDrive".into());
    }

    let display = parse_display(&read(if split { JACINTO_SCREEN } else { SCREEN }, true)?);

    let framework_dir = if split {
        let mut found = None;
        for dir in JACINTO_FRAMEWORK_DIRS {
            if is_arm_elf(&read(&format!("cat {dir}/{}", FRAMEWORKS[0]), true)?) {
                found = Some(dir);
                break;
            }
        }
        found.ok_or("framework libraries not found over Qnet. Check the hu-omap path on this split-node unit")?
    } else {
        FRAMEWORK_DIR
    };

    let hmi_node_ip = if split { parse_hmi_ip(&read(JACINTO_IFCONFIG, true)?) } else { None };

    let mut frameworks = BTreeMap::new();
    for name in FRAMEWORKS {
        let data = read(&format!("cat {framework_dir}/{name}"), false)?;
        if !is_arm_elf(&data) {
            return Err(format!("{name} is not a little-endian ARM ELF32 shared object"));
        }
        frameworks.insert(
            name.to_string(),
            FrameworkInfo { sha256: format!("{:x}", Sha256::digest(&data)), size_bytes: data.len() },
        );
    }
    let from_ssh = !detected.is_empty();
    Ok(Report {
        firmware: if from_ssh { detected } else { entered },
        firmware_source: if from_ssh { "ssh" } else { "manual" }.into(),
        os: "QNX".into(),
        os_release: platform[2].into(),
        architecture: "armle".into(),
        ssh_node: ssh_node.into(),
        hmi_node_ip,
        framework_dir: framework_dir.into(),
        display,
        frameworks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn elf() -> Vec<u8> {
        let mut d = vec![0x7f, b'E', b'L', b'F', 1, 1];
        d.resize(20, 0);
        d[16] = 3;
        d[18] = 40;
        d.extend_from_slice(b"payload");
        d
    }

    fn fake(files: Vec<(&'static str, Vec<u8>)>) -> impl FnMut(&str, bool) -> Result<Vec<u8>, String> {
        let map: HashMap<_, _> = files.into_iter().collect();
        move |cmd, optional| match map.get(cmd) {
            Some(v) => Ok(v.clone()),
            None if optional => Ok(vec![]),
            None => Err(format!("{cmd} failed")),
        }
    }

    fn direct() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("uname -a", b"QNX hu-omap 6.5.0 2014 armle".to_vec()),
            ("cat /opt/sys/etc/nbt_version.txt", b"version NBTevo_n18032i".to_vec()),
            (SCREEN, b"screen 0: resolution: x = 1280, y = 480".to_vec()),
            ("cat /opt/hmi/ID5/lib/libAppFramework.A.so", elf()),
            ("cat /opt/hmi/ID5/lib/libCoreFramework.A.so", elf()),
        ]
    }

    #[test]
    fn direct_unit() {
        let r = capture(&mut fake(direct()), None).unwrap();
        assert_eq!(r.firmware, "NBTevo_N18032I");
        assert_eq!(r.display, Some(Display { width: 1280, height: 480 }));
        assert_eq!(r.ssh_node, "hu-omap");
        assert_eq!(r.frameworks.len(), 2);
    }

    #[test]
    fn split_node_unit() {
        let dir = JACINTO_FRAMEWORK_DIRS[1];
        let files: Vec<(&'static str, Vec<u8>)> = vec![
            ("uname -a", b"QNX hu-jacinto 6.5.0 2014 armle".to_vec()),
            ("cat /etc/nbt_version.txt", b"NBTevo_P18362I".to_vec()),
            (JACINTO_SCREEN, b"resolution: x = 1920, y = 720".to_vec()),
            (JACINTO_IFCONFIG, b"inet 169.254.21.5 netmask".to_vec()),
        ];
        let app = format!("cat {dir}/libAppFramework.A.so");
        let core = format!("cat {dir}/libCoreFramework.A.so");
        let mut inner = fake(files);
        let e = elf();
        let mut read = move |cmd: &str, opt: bool| {
            if cmd == app || cmd == core {
                Ok(e.clone())
            } else {
                inner(cmd, opt)
            }
        };
        let r = capture(&mut read, None).unwrap();
        assert_eq!((r.ssh_node.as_str(), r.framework_dir.as_str()), ("hu-jacinto", dir));
        assert_eq!(r.hmi_node_ip.as_deref(), Some("169.254.21.5"));
    }

    #[test]
    fn rejects_non_qnx() {
        let mut read = fake(vec![("uname -a", b"Linux box 5 x armv7".to_vec())]);
        assert_eq!(capture(&mut read, None).unwrap_err(), "expected an ARM QNX head unit");
    }

    #[test]
    fn rejects_mismatched_manual_firmware() {
        let err = capture(&mut fake(direct()), Some("NBTevo_P18362I")).unwrap_err();
        assert!(err.contains("differs"));
    }

    #[test]
    fn needs_firmware() {
        let mut files = direct();
        files.retain(|(c, _)| !c.contains("nbt_version"));
        assert!(capture(&mut fake(files), None).unwrap_err().contains("firmware code unavailable"));
        let mut files = direct();
        files.retain(|(c, _)| !c.contains("nbt_version"));
        assert_eq!(capture(&mut fake(files), Some("NBTevo_N18032I")).unwrap().firmware_source, "manual");
    }

    #[test]
    fn rejects_non_arm_elf() {
        let mut files = direct();
        files.retain(|(c, _)| !c.ends_with("libCoreFramework.A.so"));
        files.push(("cat /opt/hmi/ID5/lib/libCoreFramework.A.so", b"junk".to_vec()));
        assert!(capture(&mut fake(files), None).unwrap_err().contains("not a little-endian ARM"));
    }
}

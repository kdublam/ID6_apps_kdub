//! Compatibility profile matching against `profiles.json`.

use crate::capture::{Report, FRAMEWORKS};
use serde::{Deserialize, Serialize};

const PROFILES_JSON: &str = include_str!("../profiles.json");

#[derive(Deserialize, Clone)]
pub struct Profile {
    pub firmware: String,
    pub app_framework_sha256: String,
    pub core_framework_sha256: String,
    pub evidence: String,
}

#[derive(Deserialize)]
pub struct Profiles {
    pub layouts: Vec<(u32, u32)>,
    pub profiles: Vec<Profile>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Supported,
    PortingNeeded,
    Unknown,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Assessment {
    pub verdict: Verdict,
    pub checks: Vec<Check>,
    pub evidence: Option<String>,
}

pub fn load() -> Profiles {
    serde_json::from_str(PROFILES_JSON).expect("profiles.json is valid")
}

fn check(name: &str, ok: bool, detail: impl Into<String>) -> Check {
    Check { name: name.into(), ok, detail: detail.into() }
}

pub fn assess(report: &Report, profiles: &Profiles) -> Assessment {
    let hash = |name: &str| report.frameworks.get(name).map(|f| f.sha256.as_str()).unwrap_or("");
    let (app, core) = (hash(FRAMEWORKS[0]), hash(FRAMEWORKS[1]));
    // Profiles are keyed on the framework hashes; the firmware name only picks
    // the preferred entry when several profiles share identical frameworks.
    let mut matches = profiles
        .profiles
        .iter()
        .filter(|p| p.app_framework_sha256 == app && p.core_framework_sha256 == core);
    let first = matches.next();
    let profile = profiles
        .profiles
        .iter()
        .find(|p| p.firmware == report.firmware && p.app_framework_sha256 == app && p.core_framework_sha256 == core)
        .or(first);
    let mut checks = vec![check(
        "Firmware",
        profile.is_some(),
        match profile {
            Some(p) if p.firmware == report.firmware => report.firmware.clone(),
            Some(p) => format!("{} (frameworks match {})", report.firmware, p.firmware),
            None => format!("{} has no verified profile", report.firmware),
        },
    )];
    for name in FRAMEWORKS.iter() {
        checks.push(check(name, profile.is_some(), hash(name)));
    }
    let layout = report
        .display
        .as_ref()
        .map(|d| (d.width, d.height))
        .filter(|d| profiles.layouts.contains(d));
    checks.push(check(
        "Display",
        layout.is_some(),
        match &report.display {
            Some(d) if layout.is_some() => format!("{} x {}", d.width, d.height),
            Some(d) => format!("{} x {} has no packaged layout", d.width, d.height),
            None => "resolution not detected".into(),
        },
    ));
    let verdict = if checks.iter().all(|c| c.ok) {
        Verdict::Supported
    } else if profile.is_none() {
        Verdict::Unknown
    } else {
        Verdict::PortingNeeded
    };
    Assessment { verdict, checks, evidence: profile.map(|p| p.evidence.clone()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Display, FrameworkInfo};
    use std::collections::BTreeMap;

    fn report(firmware: &str, app: &str, core: &str, display: Option<(u32, u32)>) -> Report {
        let fw = |h: &str| FrameworkInfo { sha256: h.into(), size_bytes: 1 };
        Report {
            firmware: firmware.into(),
            firmware_source: "ssh".into(),
            os: "QNX".into(),
            os_release: "6.5.0".into(),
            architecture: "armle".into(),
            ssh_node: "hu-omap".into(),
            hmi_node_ip: None,
            framework_dir: "/x".into(),
            display: display.map(|(width, height)| Display { width, height }),
            frameworks: BTreeMap::from([(FRAMEWORKS[0].to_string(), fw(app)), (FRAMEWORKS[1].to_string(), fw(core))]),
        }
    }

    fn reference() -> (String, String) {
        let p = &load().profiles[0];
        (p.app_framework_sha256.clone(), p.core_framework_sha256.clone())
    }

    #[test]
    fn reference_unit_is_supported() {
        let (a, c) = reference();
        assert_eq!(assess(&report("NBTevo_N18032I", &a, &c, Some((1280, 480))), &load()).verdict, Verdict::Supported);
    }

    #[test]
    fn matching_hashes_with_unlisted_firmware_is_supported() {
        let (a, c) = reference();
        assert_eq!(assess(&report("NBTevo_Z99999Z", &a, &c, Some((1280, 480))), &load()).verdict, Verdict::Supported);
    }

    #[test]
    fn unknown_everything() {
        assert_eq!(assess(&report("NBTevo_Z99999Z", "a", "b", None), &load()).verdict, Verdict::Unknown);
    }

    #[test]
    fn odd_resolution_needs_porting() {
        let (a, c) = reference();
        assert_eq!(assess(&report("NBTevo_N18032I", &a, &c, Some((1000, 500))), &load()).verdict, Verdict::PortingNeeded);
    }

    #[test]
    fn profiles_parse() {
        assert_eq!(load().profiles.len(), 5);
    }
}

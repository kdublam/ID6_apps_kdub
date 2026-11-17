mod capture;
mod profiles;
mod session;

use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Serialize)]
struct EnetInterface {
    name: String,
    ip: String,
}

#[derive(Serialize)]
struct CheckResult {
    report: capture::Report,
    assessment: profiles::Assessment,
}

fn parse_ip(value: &str) -> Result<Ipv4Addr, String> {
    session::enet_ip(value)
}

#[tauri::command]
fn detect_enet() -> Vec<EnetInterface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(ip) if ip.is_link_local() => Some(EnetInterface { name: i.name, ip: ip.to_string() }),
            _ => None,
        })
        .collect()
}

#[tauri::command]
async fn probe_host_key(head: String) -> Result<String, String> {
    let ip = parse_ip(&head)?;
    tauri::async_runtime::spawn_blocking(move || session::probe_host_key(ip)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn run_check(
    head: String,
    host_key: String,
    password: Option<String>,
    firmware: Option<String>,
) -> Result<CheckResult, String> {
    let ip = parse_ip(&head)?;
    tauri::async_runtime::spawn_blocking(move || {
        let ssh = session::connect(ip, &host_key, password.as_deref())?;
        let report = capture::capture(&mut |cmd, optional| session::run(&ssh, cmd, optional), firmware.as_deref())?;
        let assessment = profiles::assess(&report, &profiles::load());
        Ok(CheckResult { report, assessment })
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn save_report(app: tauri::AppHandle, result: serde_json::Value) -> Result<String, String> {
    use tauri::Manager;
    let dir = app.path().download_dir().map_err(|e| e.to_string())?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let path = dir.join(format!("id6-compatibility-{stamp}.json"));
    let text = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    std::fs::write(&path, text + "\n").map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![detect_enet, probe_host_key, run_check, save_report])
        .run(tauri::generate_context!())
        .expect("error while running the app");
}

mod applog;
mod capture;
mod install;
mod profiles;
mod session;

use serde::Serialize;
use tauri::{Emitter, Manager};
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
    tauri::async_runtime::spawn_blocking(move || {
        let r = session::probe_host_key(ip);
        match &r {
            Ok(fp) => applog::line(&format!("probe_host_key {ip}: fingerprint {fp}")),
            Err(e) => applog::line(&format!("probe_host_key {ip}: FAILED {e}")),
        }
        r
    })
    .await
    .map_err(|e| e.to_string())?
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
        applog::line(&format!("run_check {ip} (manual firmware: {})", firmware.as_deref().unwrap_or("none")));
        let result: Result<CheckResult, String> = (|| {
            let ssh = session::connect(ip, &host_key, password.as_deref())?;
            let report = capture::capture(&mut |cmd, optional| session::run(&ssh, cmd, optional), firmware.as_deref())?;
            let assessment = profiles::assess(&report, &profiles::load());
            Ok(CheckResult { report, assessment })
        })();
        match &result {
            Ok(r) => {
                let checks: Vec<String> = r.assessment.checks.iter().map(|c| format!("{}={} ({})", c.name, if c.ok { "ok" } else { "FAIL" }, c.detail)).collect();
                applog::line(&format!("run_check result: {:?}; firmware {}; {}", r.assessment.verdict, r.report.firmware, checks.join("; ")));
            }
            Err(e) => applog::line(&format!("run_check FAILED: {}", applog::clip(e))),
        }
        result
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
struct InstallResult {
    backup_id: String,
    remote_backup: String,
    local_backup: String,
    changed: Vec<String>,
    log_file: String,
}

#[derive(Serialize)]
struct BackupEntry {
    id: String,
    created: u64,
    apps: Vec<String>,
}

fn result_of(d: install::Done, log: &std::path::Path) -> InstallResult {
    InstallResult {
        backup_id: d.backup_id,
        remote_backup: d.remote_backup,
        local_backup: d.local_backup,
        changed: d.changed,
        log_file: log.display().to_string(),
    }
}

fn packages_dir(app: &tauri::AppHandle) -> std::path::PathBuf {
    let bundled = app.path().resource_dir().map(|d| d.join("packages")).ok().filter(|d| d.is_dir());
    bundled.unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages"))
}

fn local_root(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    app.path().app_data_dir().map_err(|e| e.to_string())
}

/// Opens a timestamped log file under the app data folder and returns a reporter that appends every
/// message to it and also streams it to the UI.
fn open_log<'a>(app: &'a tauri::AppHandle, kind: &str) -> Result<(std::path::PathBuf, impl FnMut(&str) + 'a), String> {
    use std::io::Write;
    let dir = local_root(app)?.join("logs");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{kind}-{}.log", install::now_secs()));
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path).map_err(|e| e.to_string())?;
    let kind = kind.to_string();
    applog::line(&format!("operation {kind} started; operation log {}", path.display()));
    let report = move |msg: &str| {
        applog::line(&format!("[{kind}] {msg}"));
        let _ = writeln!(file, "[{}] {msg}", install::now_secs());
        let _ = file.flush();
        let _ = app.emit("progress", msg.to_string());
    };
    Ok((path, report))
}

fn with_log(r: Result<install::Done, String>, log: &std::path::Path) -> Result<InstallResult, String> {
    match r {
        Ok(d) => Ok(result_of(d, log)),
        Err(e) => Err(format!("{e} (log: {})", log.display())),
    }
}

/// Installs the selected apps (after re-checking compatibility) and/or removes apps, with a backup first.
#[tauri::command]
async fn install_apps(
    app: tauri::AppHandle,
    head: String,
    host_key: String,
    password: Option<String>,
    firmware: Option<String>,
    install: Vec<String>,
    remove: Vec<String>,
    gateway: Option<String>,
) -> Result<InstallResult, String> {
    let ip = parse_ip(&head)?;
    let gateway = match gateway.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
        Some(g) => Some(g.parse::<Ipv4Addr>().map_err(|_| "enter the diagnostic gateway as an IPv4 address".to_string())?),
        None => None,
    };
    let defs = if install.is_empty() { vec![] } else { install::resolve(&install)? };
    let packages = packages_dir(&app);
    let local = local_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let staged = defs.iter().map(|d| install::load_staged(&packages, d, gateway)).collect::<Result<Vec<_>, _>>()?;
        let mut ssh = session::connect(ip, &host_key, password.as_deref())?;
        if !staged.is_empty() {
            let report = capture::capture(&mut |cmd, optional| session::run(&ssh, cmd, optional), firmware.as_deref())?;
            if profiles::assess(&report, &profiles::load()).verdict != profiles::Verdict::Supported {
                return Err("this head unit is not a supported match; installing is blocked".to_string());
            }
        }
        let id = format!("b{}", install::now_secs());
        let (log, mut progress) = open_log(&app, "install")?;
        let r = install::prepare_hmi(&mut ssh, &mut progress)
            .and_then(|(mut hmi, root)| install::apply(&mut hmi, &root, &local, &id, &staged, &remove, &mut progress));
        with_log(r, &log)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_backups(head: String, host_key: String, password: Option<String>) -> Result<Vec<BackupEntry>, String> {
    let ip = parse_ip(&head)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut ssh = session::connect(ip, &host_key, password.as_deref())?;
        let (mut hmi, root) = install::prepare_hmi(&mut ssh, &mut |m: &str| applog::line(&format!("[list_backups] {m}")))?;
        Ok(install::list_backups(&mut hmi, &root)?
            .into_iter()
            .map(|b| BackupEntry {
                created: b.id.trim_start_matches('b').parse().unwrap_or(0),
                apps: b.apps.into_iter().map(|(a, _)| a).collect(),
                id: b.id,
            })
            .collect())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Reverts the apps recorded in a backup to their backed-up state.
#[tauri::command]
async fn restore_backup(
    app: tauri::AppHandle,
    head: String,
    host_key: String,
    password: Option<String>,
    backup_id: String,
) -> Result<InstallResult, String> {
    let ip = parse_ip(&head)?;
    let local = local_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut ssh = session::connect(ip, &host_key, password.as_deref())?;
        let (log, mut progress) = open_log(&app, "restore")?;
        let r = install::prepare_hmi(&mut ssh, &mut progress)
            .and_then(|(mut hmi, root)| install::restore(&mut hmi, &root, &local, &backup_id, &mut progress));
        with_log(r, &log)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Deletes a backup (leaving installed apps alone). Returns the log file path.
#[tauri::command]
async fn delete_backup(
    app: tauri::AppHandle,
    head: String,
    host_key: String,
    password: Option<String>,
    backup_id: String,
    delete_local: bool,
) -> Result<String, String> {
    let ip = parse_ip(&head)?;
    let local = local_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut ssh = session::connect(ip, &host_key, password.as_deref())?;
        let (log, mut progress) = open_log(&app, "delete-backup")?;
        let r = install::prepare_hmi(&mut ssh, &mut progress)
            .and_then(|(mut hmi, root)| install::delete_backup(&mut hmi, &root, &local, &backup_id, delete_local, &mut progress));
        r.map(|_| log.display().to_string()).map_err(|e| format!("{e} (log: {})", log.display()))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Backs up everything under Plugins without changing anything on the head unit except the backup folder.
#[tauri::command]
async fn backup_now(app: tauri::AppHandle, head: String, host_key: String, password: Option<String>) -> Result<InstallResult, String> {
    let ip = parse_ip(&head)?;
    let local = local_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut ssh = session::connect(ip, &host_key, password.as_deref())?;
        let id = format!("b{}", install::now_secs());
        let (log, mut progress) = open_log(&app, "backup")?;
        progress(&format!("Connected to {ip}; backup id {id}"));
        let r = install::prepare_hmi(&mut ssh, &mut progress)
            .and_then(|(mut hmi, root)| install::backup_all(&mut hmi, &root, &local, &id, &mut progress));
        with_log(r, &log)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Records a front end event or error in the app log.
#[tauri::command]
fn log_ui(message: String) {
    applog::line(&format!("ui: {}", applog::clip(&message)));
}

#[tauri::command]
fn open_logs_folder(app: tauri::AppHandle) -> Result<String, String> {
    let dir = local_root(&app)?.join("logs");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener).arg(&dir).spawn().map_err(|e| format!("cannot open {}: {e}", dir.display()))?;
    Ok(dir.display().to_string())
}

/// Writes the newest logs plus version and OS details into one file in Downloads to attach to a bug report.
#[tauri::command]
fn save_diagnostics(app: tauri::AppHandle) -> Result<String, String> {
    let logs = local_root(&app)?.join("logs");
    let dir = app.path().download_dir().map_err(|e| e.to_string())?;
    let path = dir.join(format!("id6-diagnostics-{}.txt", install::now_secs()));
    std::fs::write(&path, applog::diagnostics(&logs)).map_err(|e| e.to_string())?;
    applog::line(&format!("diagnostics saved to {}", path.display()));
    Ok(path.display().to_string())
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
        .setup(|app| {
            if let Ok(dir) = app.path().app_data_dir() {
                applog::init(&dir.join("logs"));
            }
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![detect_enet, probe_host_key, run_check, save_report, install_apps, list_backups, restore_backup, backup_now, delete_backup, log_ui, open_logs_folder, save_diagnostics])
        .run(tauri::generate_context!())
        .expect("error while running the app");
}

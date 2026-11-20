//! Transactional install, uninstall, backup and restore of head unit plugin folders.
//!
//! Safety model:
//! 1. Files are uploaded to a staging folder outside `Plugins` and read back byte for byte.
//! 2. The folders about to change are copied to a backup (on the head unit and on this computer)
//!    and the copy is verified before anything is touched.
//! 3. Publishing runs as one remote shell script under an install lock. It moves the old folder
//!    aside, moves the staged folder in and rolls everything back if any step fails.
//! 4. Restore replaces the changed folders with the backup, again under the lock, keeping the
//!    folders it replaced.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const ROOT: &str = "/var/opt/hmi/data/ID5";

/// Where the HMI data folder can be on a split-node unit. The SSH node (hu-jacinto) has no such folder;
/// the OMAP (hu-omap) owns it and exposes its filesystem to the Jacinto over Qnet.
const ROOT_CANDIDATES: [&str; 5] = [
    ROOT,
    "/net/hu-omap/fs/sda1/var/opt/hmi/data/ID5",
    "/net/hu-omap/var/opt/hmi/data/ID5",
    "/net/hu-omap/fs/sda0/var/opt/hmi/data/ID5",
    "/net/hu-omap/fs/sda1/opt/hmi/data/ID5",
];

const FIND_ROOT: &str = r#"echo "node: $(uname -n 2>/dev/null)"
echo "PATH: $PATH"
for t in cat ls find mkdir mv cp rm chmod test; do
    if type $t >/dev/null 2>&1; then echo "tool ok: $t = $(type $t 2>&1)"; else echo "tool missing: $t"; fi
done
echo "tool folders:"
ls -d /bin /usr/bin /sbin /usr/sbin /proc/boot /usr/local/bin 2>&1
for t in find chmod; do ls /bin/$t /usr/bin/$t /sbin/$t /usr/sbin/$t /proc/boot/$t 2>&1; done
for t in wc tr head tail df sed rmdir; do
    if type $t >/dev/null 2>&1; then echo "optional tool present (not used): $t"; else echo "optional tool absent (not used): $t"; fi
done
for c in __CANDIDATES__; do
    if test -d "$c"; then echo "candidate exists: $c"; else echo "candidate missing: $c"; fi
done
echo "Qnet nodes:"
ls -d /net/* 2>&1
echo "hu-omap mounts:"
ls /net/hu-omap/fs 2>&1
echo "hu-omap /var/opt/hmi/data candidates:"
ls -d /net/hu-omap/fs/*/var/opt/hmi/data/* /net/hu-omap/var/opt/hmi/data/* 2>&1
true
"#;

/// Finds the HMI data folder on this unit, logging every candidate checked. Read-only.
/// Falls back from the local path to the OMAP's filesystem over Qnet on split-node units.
pub fn find_root(shell: &mut dyn Shell, candidates: &[&str], progress: &mut dyn FnMut(&str)) -> Result<String, String> {
    progress("Looking for the HMI data folder (ID5) on the head unit");
    let list = candidates.iter().map(|c| q(c)).collect::<Vec<_>>().join(" ");
    let out = script(shell, &FIND_ROOT.replace("__CANDIDATES__", &list))?;
    for line in out.lines() {
        progress(&format!("  {line}"));
    }
    let missing: Vec<&str> = out.lines().filter_map(|l| l.trim().strip_prefix("tool missing: ")).collect();
    if !missing.is_empty() {
        return Err(format!("the head unit shell is missing required tools ({}). Nothing was changed", missing.join(", ")));
    }
    for c in candidates {
        if out.lines().any(|l| l.trim() == format!("candidate exists: {c}")) {
            progress(&format!("Using {c}"));
            return Ok(c.to_string());
        }
    }
    Err(format!(
        "no HMI data folder (ID5) was found. Checked: {}. Nothing was changed. See the log for the Qnet nodes and mounts that were visible",
        candidates.join(", ")
    ))
}

pub fn find_default_root(shell: &mut dyn Shell, progress: &mut dyn FnMut(&str)) -> Result<String, String> {
    find_root(shell, &ROOT_CANDIDATES, progress)
}

/// Runs commands on the head unit. `input` is sent on standard input.
pub trait Shell {
    fn exec(&mut self, command: &str, input: Option<&[u8]>) -> Result<Vec<u8>, String>;
}

impl Shell for crate::session::Connection {
    fn exec(&mut self, command: &str, input: Option<&[u8]>) -> Result<Vec<u8>, String> {
        match input {
            Some(data) => crate::session::run_input(self, command, data),
            None => crate::session::run(self, command, false),
        }
    }
}

/// Runs commands either directly on the SSH node or forwarded to `hu-omap` via `on -f hu-omap`
/// on split-node units where SSH lands on `hu-jacinto`.
pub struct TargetShell<'a> {
    inner: &'a mut dyn Shell,
    via_omap: bool,
}

impl<'a> TargetShell<'a> {
    pub fn wrap(inner: &'a mut dyn Shell, via_omap: bool) -> Self {
        Self { inner, via_omap }
    }
}

impl Shell for TargetShell<'_> {
    fn exec(&mut self, command: &str, input: Option<&[u8]>) -> Result<Vec<u8>, String> {
        if !self.via_omap {
            return self.inner.exec(command, input);
        }
        let wrapped = if command == "sh -s" {
            "on -f hu-omap sh -s".to_string()
        } else {
            format!("on -f hu-omap sh -c {}", q(command))
        };
        self.inner.exec(&wrapped, input)
    }
}

/// Detects whether SSH landed on `hu-jacinto` (split-node unit) and, if so, wraps the shell to run
/// HMI commands on `hu-omap`, then locates the HMI data folder.
pub fn prepare_hmi<'a>(
    shell: &'a mut dyn Shell,
    progress: &mut dyn FnMut(&str),
) -> Result<(TargetShell<'a>, String), String> {
    let node = String::from_utf8_lossy(&shell.exec("uname -n", None)?).trim().to_string();
    let via_omap = node.contains("hu-jacinto");
    if via_omap {
        progress("SSH landed on hu-jacinto (split-node unit); running HMI operations on hu-omap");
    }
    let mut target = TargetShell::wrap(shell, via_omap);
    let root = find_default_root(&mut target, progress)?;
    Ok((target, root))
}

pub struct AppDef {
    pub id: &'static str,
    pub dir: &'static str,
    pub zip: &'static str,
    pub workers: &'static [&'static str],
}

pub const APPS: [AppDef; 7] = [
    AppDef { id: "mhd", dir: "MhdMaps", zip: "dashboard.zip", workers: &["mhd-maps-qnx", "exhaust-flap-worker-qnx"] },
    AppDef { id: "bm3", dir: "Bootmod3Suite", zip: "bootmod3.zip", workers: &["bootmod3-qnx"] },
    AppDef { id: "boostdeck", dir: "BoostDeck", zip: "dashboard.zip", workers: &["boostdeck-collector-qnx"] },
    AppDef { id: "shiftdeck", dir: "ShiftDeck", zip: "dashboard.zip", workers: &["shift-deck-qnx"] },
    AppDef { id: "enginecodes", dir: "EngineCodes", zip: "dashboard.zip", workers: &["engine-codes-qnx"] },
    AppDef { id: "xdrive", dir: "XDriveControl", zip: "xdrive.zip", workers: &["xdrive-control-qnx"] },
    AppDef { id: "hud", dir: "HudTest", zip: "hud-gauges.zip", workers: &["hud-shape-qnx"] },
];

/// The standalone plugin that MhdMaps replaces; it is backed up and removed with MhdMaps.
const LEGACY_EXHAUST_FLAP: &str = "ExhaustFlap";

pub fn app_by_id(id: &str) -> Result<&'static AppDef, String> {
    APPS.iter().find(|a| a.id == id).ok_or_else(|| format!("unknown app {id}"))
}

/// Validates a selection of app ids. MHD+ and Bootmod3 share a menu, so only one may be chosen.
pub fn resolve(ids: &[String]) -> Result<Vec<&'static AppDef>, String> {
    if ids.is_empty() {
        return Err("select at least one app".into());
    }
    let mut apps = Vec::new();
    for id in ids {
        let app = app_by_id(id)?;
        if !apps.iter().any(|a: &&AppDef| a.id == app.id) {
            apps.push(app);
        }
    }
    if apps.iter().any(|a| a.id == "mhd") && apps.iter().any(|a| a.id == "bm3") {
        return Err("choose either MHD+ Suite or Bootmod3 Suite, not both".into());
    }
    Ok(apps)
}

fn safe_name(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------- packages

pub struct File {
    pub bytes: Vec<u8>,
    pub exec: bool,
}

pub struct Staged {
    pub dir: String,
    pub workers: Vec<String>,
    pub files: BTreeMap<String, File>,
}

/// Reads one app folder out of a package ZIP, verifying `SHA256SUMS` when the package has one.
pub fn load_staged(packages: &Path, app: &AppDef, gateway: Option<Ipv4Addr>) -> Result<Staged, String> {
    let path = packages.join(app.zip);
    let file = std::fs::File::open(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("{} is not a valid package: {e}", app.zip))?;
    let prefix = format!("{}/", app.dir);
    let mut sums: BTreeMap<String, String> = BTreeMap::new();
    let mut files = BTreeMap::new();
    let mut all: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if name == "SHA256SUMS" {
            for line in String::from_utf8_lossy(&bytes).lines() {
                if let Some((h, f)) = line.split_once(char::is_whitespace) {
                    sums.insert(f.trim().trim_start_matches('*').to_string(), h.to_string());
                }
            }
        }
        all.insert(name, bytes);
    }
    for (name, bytes) in all {
        let Some(rel) = name.strip_prefix(&prefix) else { continue };
        if !rel.split('/').all(safe_name) {
            return Err(format!("{} contains an unsafe path: {name}", app.zip));
        }
        if let Some(expected) = sums.get(&name) {
            if *expected != hex(&bytes) {
                return Err(format!("{name} does not match SHA256SUMS in {}", app.zip));
            }
        }
        let exec = app.workers.contains(&rel);
        files.insert(rel.to_string(), File { bytes, exec });
    }
    if !files.contains_key(&format!("{}.manifest", app.dir)) {
        return Err(format!("{} has no {}/{}.manifest", app.zip, app.dir, app.dir));
    }
    for w in app.workers {
        if !files.contains_key(*w) {
            return Err(format!("{} is missing the worker {}/{w}", app.zip, app.dir));
        }
    }
    if let Some(ip) = gateway {
        files.insert("gateway-ip.txt".into(), File { bytes: format!("{ip}\n").into_bytes(), exec: false });
    }
    Ok(Staged { dir: app.dir.into(), workers: app.workers.iter().map(|s| s.to_string()).collect(), files })
}

// ---------------------------------------------------------------- remote helpers

fn base(root: &str) -> String {
    format!("{root}/ID6Installer")
}

fn script(shell: &mut dyn Shell, text: &str) -> Result<String, String> {
    shell.exec("sh -s", Some(text.as_bytes())).map(|o| String::from_utf8_lossy(&o).into_owned())
}

/// Downloads every regular file under `dir` in one round trip.
pub fn fetch_tree(shell: &mut dyn Shell, dir: &str) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let cmd = format!(
        "cd {} || exit 1\nfsize() {{ s=$(wc -c < \"$1\" 2>/dev/null) && test -n \"$s\" && {{ echo $s; return 0; }}; set -- $(ls -ln \"$1\" 2>/dev/null); echo $5; }}\nfind . -type f | while read -r f; do echo \"ID6FILE $(fsize \"$f\") $f\"; cat \"$f\"; done\n",
        q(dir)
    );
    let out = shell.exec("sh -s", Some(cmd.as_bytes()))?;
    let mut files = BTreeMap::new();
    let mut pos = 0;
    while pos < out.len() {
        let nl = out[pos..].iter().position(|&b| b == b'\n').ok_or("truncated listing from head unit")? + pos;
        let header = String::from_utf8_lossy(&out[pos..nl]).into_owned();
        let mut parts = header.splitn(3, ' ');
        if parts.next() != Some("ID6FILE") {
            return Err(format!("unexpected listing from head unit: {header}"));
        }
        let size: usize = parts.next().and_then(|s| s.parse().ok()).ok_or("bad size in listing")?;
        let name = parts.next().ok_or("bad name in listing")?.trim_start_matches("./").to_string();
        let start = nl + 1;
        if start + size > out.len() {
            return Err("truncated file data from head unit".into());
        }
        files.insert(name, out[start..start + size].to_vec());
        pos = start + size;
    }
    Ok(files)
}

fn compare(local: &BTreeMap<String, Vec<u8>>, remote: &BTreeMap<String, Vec<u8>>, what: &str) -> Result<(), String> {
    let l: BTreeSet<_> = local.keys().collect();
    let r: BTreeSet<_> = remote.keys().collect();
    if l != r {
        let diff: Vec<_> = l.symmetric_difference(&r).map(|s| s.to_string()).collect();
        return Err(format!("{what}: file list differs ({})", diff.join(", ")));
    }
    for (name, bytes) in local {
        if hex(bytes) != hex(&remote[name]) {
            return Err(format!("{what}: {name} does not match after upload"));
        }
    }
    Ok(())
}

fn staged_bytes(s: &Staged) -> BTreeMap<String, Vec<u8>> {
    s.files.iter().map(|(k, v)| (k.clone(), v.bytes.clone())).collect()
}

fn connector_ids(manifest: &str) -> Vec<String> {
    Regex::new(r"(?s)<pluginAppConnector>.*?<id>\s*(\d+)\s*</id>")
        .unwrap()
        .captures_iter(manifest)
        .map(|c| c[1].to_string())
        .collect()
}

/// Fails when an installed plugin that is not being replaced already uses a connector id we need.
fn check_connectors(shell: &mut dyn Shell, root: &str, staged: &[Staged], touching: &BTreeSet<String>) -> Result<(), String> {
    let cmd = format!(
        "for m in {r}/Plugins/*/*.manifest; do test -f \"$m\" || continue; echo \"ID6MANIFEST $m\"; cat \"$m\"; echo; done\n",
        r = q(root)
    );
    let out = String::from_utf8_lossy(&shell.exec("sh -s", Some(cmd.as_bytes()))?).into_owned();
    let mut used: BTreeMap<String, String> = BTreeMap::new();
    for chunk in out.split("ID6MANIFEST ").skip(1) {
        let (path, body) = chunk.split_once('\n').unwrap_or((chunk, ""));
        let dir = path.rsplit('/').nth(1).unwrap_or("").to_string();
        if touching.contains(&dir) {
            continue;
        }
        for id in connector_ids(body) {
            used.entry(id).or_insert_with(|| dir.clone());
        }
    }
    for s in staged {
        let manifest = s.files.get(&format!("{}.manifest", s.dir)).map(|f| String::from_utf8_lossy(&f.bytes).into_owned()).unwrap_or_default();
        for id in connector_ids(&manifest) {
            if let Some(owner) = used.get(&id) {
                return Err(format!("connector {id} needed by {} is already used by the installed app {owner}", s.dir));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- scripts

const PRECHECK: &str = r#"root=__ROOT__
node=$(uname -n 2>/dev/null)
if test ! -d "$root"; then
    echo "$root does not exist on this head unit node (${node:-unknown}). Nothing was changed. On a split-node unit (hu-jacinto) the plugin folder lives on the OMAP (hu-omap), not on this node." >&2
    exit 1
fi
test ! -L "$root" || { echo "$root is a symbolic link. Nothing was changed." >&2; exit 1; }
test -w "$root" || { echo "$root is not writable. Nothing was changed." >&2; exit 1; }
test ! -L "$root/Plugins" || { echo 'The Plugins folder is a symbolic link. Nothing was changed.' >&2; exit 1; }
if test -e "$root/Plugins"; then
    test -d "$root/Plugins" || { echo 'Plugins is not a folder. Nothing was changed.' >&2; exit 1; }
    test -w "$root/Plugins" || { echo 'The Plugins folder is not writable. Nothing was changed.' >&2; exit 1; }
else
    echo "note: $root/Plugins does not exist yet"
fi
if test -e "$root/ID6Installer/lock"; then echo "An install lock exists at $root/ID6Installer/lock. Check for an interrupted install before retrying." >&2; exit 1; fi
echo "node: ${node:-unknown}"
echo "uname: $(uname -a 2>&1)"
echo "root: $root (exists, writable)"
echo "free space:"
df -k "$root" 2>&1
true
echo "Plugins contents:"
ls -la "$root/Plugins" 2>&1
true
"#;

const PUBLISH: &str = r#"root=__ROOT__
tx=__TX__
apps=__APPS__
lock="$root/ID6Installer/lock"
fail() { echo "$1" >&2; exit 1; }
exists() { test -e "$1" || test -L "$1"; }
rm_empty_dir() {
    test -d "$1" && test ! -L "$1" || return 1
    for m in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        if exists "$m"; then return 1; fi
    done
    rm -rf "$1"
}
locked=0
done_ok=0
cleanup() {
    if test "$locked" = 0; then return; fi
    rollback_failed=0
    if test "$done_ok" = 0; then
        for entry in $apps; do
            app=${entry%%:*}
            live="$root/Plugins/$app"; old="$tx/old-$app"; stage="$tx/new-$app"; fresh="$tx/fresh-$app"
            if test -d "$old" || test -f "$fresh"; then
                if test ! -e "$stage" && test -d "$live"; then mv "$live" "$stage" || rollback_failed=1; fi
                if test -d "$old"; then
                    if exists "$live"; then rollback_failed=1; else mv "$old" "$live" || rollback_failed=1; fi
                fi
            fi
        done
    fi
    if test "$rollback_failed" = 1; then
        echo 'Rollback needs inspection. The install lock, staged files and backup were kept.' >&2
        exit 3
    fi
    rm_empty_dir "$lock" || echo 'Could not release the install lock.' >&2
}
trap cleanup 0
trap 'fail "Publication received a stop signal."' HUP INT TERM
mkdir -p "$root/ID6Installer" || fail 'Could not create the installer folder.'
mkdir "$lock" 2>/dev/null || fail "The install lock already exists ($lock). Check for an interrupted install before retrying."
locked=1
test ! -L "$root/Plugins" || fail 'The Plugins folder is a symbolic link.'
mkdir -p "$root/Plugins" "$tx" || fail 'Could not create the Plugins folder.'
for entry in $apps; do
    app=${entry%%:*}
    rest=${entry#*:}
    mode=${rest%%:*}
    case "$rest" in *:*) workers=${rest#*:} ;; *) workers= ;; esac
    live="$root/Plugins/$app"; old="$tx/old-$app"; stage="$tx/new-$app"; fresh="$tx/fresh-$app"
    test ! -L "$live" || fail "$app plugin path is a symbolic link."
    if exists "$live"; then
        test -d "$live" || fail "$app plugin path is not a folder."
        mv "$live" "$old" || fail "Could not move $app aside."
    else
        : > "$fresh" || fail "Could not record the new $app install."
    fi
    if test "$mode" = remove; then
        if exists "$live"; then fail "Could not remove $app."; fi
        echo "removed $app"
        continue
    fi
    mv "$stage" "$live" || fail "Could not publish $app."
    test -f "$live/$app.manifest" || fail "Published $app is missing its manifest."
    ws=$workers
    while test -n "$ws"; do
        w=${ws%%:*}
        test -x "$live/$w" || fail "Published $app is missing the executable worker $w."
        case "$ws" in *:*) ws=${ws#*:} ;; *) ws= ;; esac
    done
    echo "published $app"
done
done_ok=1
"#;

const SNAPSHOT: &str = r#"root=__ROOT__
bk=__BK__
apps=__APPS__
mkdir -p "$bk/snapshot" || exit 1
: > "$bk/apps" || exit 1
for app in $apps; do
    live="$root/Plugins/$app"
    if test -L "$live"; then echo "$app plugin path is a symbolic link." >&2; exit 1; fi
    if test -d "$live"; then
        cp -Rp "$live" "$bk/snapshot/$app" || { echo "Could not back up $app." >&2; exit 1; }
        echo "$app present" >> "$bk/apps"
    elif test -e "$live"; then
        echo "$app plugin path is not a folder." >&2; exit 1
    else
        echo "$app absent" >> "$bk/apps"
    fi
done
"#;

const RESTORE: &str = r#"root=__ROOT__
bk=__BK__
rtx=__RTX__
entries=__ENTRIES__
lock="$root/ID6Installer/lock"
fail() { echo "$1" >&2; exit 1; }
exists() { test -e "$1" || test -L "$1"; }
rm_empty_dir() {
    test -d "$1" && test ! -L "$1" || return 1
    for m in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        if exists "$m"; then return 1; fi
    done
    rm -rf "$1"
}
locked=0
done_ok=0
cleanup() {
    if test "$locked" = 0; then return; fi
    rollback_failed=0
    if test "$done_ok" = 0; then
        for entry in $entries; do
            app=${entry%%:*}
            live="$root/Plugins/$app"
            if exists "$rtx/new-$app"; then rm -rf "$live" || rollback_failed=1; fi
            if test -d "$rtx/cur-$app"; then
                if exists "$live"; then rollback_failed=1; else mv "$rtx/cur-$app" "$live" || rollback_failed=1; fi
            fi
        done
    fi
    if test "$rollback_failed" = 1; then
        echo 'Rollback needs inspection. The install lock and current folders were kept.' >&2
        exit 3
    fi
    rm_empty_dir "$lock" || echo 'Could not release the install lock.' >&2
}
trap cleanup 0
trap 'fail "Restore received a stop signal."' HUP INT TERM
mkdir -p "$root/ID6Installer" || fail 'Could not create the installer folder.'
mkdir "$lock" 2>/dev/null || fail "The install lock already exists ($lock). Check for an interrupted install before retrying."
locked=1
test ! -L "$root/Plugins" || fail 'The Plugins folder is a symbolic link.'
mkdir -p "$root/Plugins" "$rtx" || fail 'Could not create the Plugins folder.'
for entry in $entries; do
    app=${entry%%:*}
    state=${entry#*:}
    live="$root/Plugins/$app"
    test ! -L "$live" || fail "$app plugin path is a symbolic link."
    if exists "$live"; then
        mv "$live" "$rtx/cur-$app" || fail "Could not move the current $app aside."
    fi
    if test "$state" = present; then
        : > "$rtx/new-$app" || fail "Could not record the restore of $app."
        cp -Rp "$bk/snapshot/$app" "$live" || fail "Could not restore $app."
        test -f "$live/$app.manifest" || fail "Restored $app is missing its manifest."
        echo "restored $app"
    else
        echo "removed $app (it was not installed originally)"
    fi
done
done_ok=1
"#;

fn fill(t: &str, pairs: &[(&str, String)]) -> String {
    let mut s = t.to_string();
    for (k, v) in pairs {
        s = s.replace(k, v);
    }
    s
}

// ---------------------------------------------------------------- operations

pub type Progress<'a> = &'a mut dyn FnMut(&str);

/// Runs the path and safety check, logging what it found. Stops (with nothing changed) if the folder is missing.
fn precheck(shell: &mut dyn Shell, root: &str, progress: &mut dyn FnMut(&str)) -> Result<(), String> {
    progress(&format!("Checking that {root} exists on the head unit"));
    let out = script(shell, &fill(PRECHECK, &[("__ROOT__", q(root))]))?;
    for line in out.lines() {
        progress(&format!("  {line}"));
    }
    Ok(())
}

fn summarize(files: &BTreeMap<String, Vec<u8>>) -> (usize, usize) {
    (files.len(), files.values().map(|b| b.len()).sum())
}

/// Copies `touched` app folders into a backup on the head unit and on this computer, verifying every file
/// three ways (live folder, head unit copy, local copy) and logging each step.
fn backup(
    shell: &mut dyn Shell,
    root: &str,
    bk: &str,
    local: &Path,
    touched: &[String],
    progress: &mut dyn FnMut(&str),
) -> Result<(), String> {
    progress(&format!("Backup destination on the head unit: {bk}"));
    progress(&format!("Backup destination on this computer: {}", local.display()));
    progress(&format!("Folders to back up: {}", touched.join(", ")));
    let apps_arg = q(&touched.join(" "));
    script(shell, &fill(SNAPSHOT, &[("__ROOT__", q(root)), ("__BK__", q(bk)), ("__APPS__", apps_arg)]))?;
    let states = parse_apps_file(&String::from_utf8_lossy(&shell.exec(&format!("cat {}", q(&format!("{bk}/apps"))), None)?));
    if states.len() != touched.len() {
        return Err(format!("backup record lists {} folders but {} were requested", states.len(), touched.len()));
    }
    std::fs::create_dir_all(local).map_err(|e| e.to_string())?;
    let mut list = String::new();
    let mut manifest = String::new();
    let (mut total_files, mut total_bytes) = (0, 0);
    for (app, present) in &states {
        list.push_str(&format!("{app} {}\n", if *present { "present" } else { "absent" }));
        if !*present {
            progress(&format!("{app}: not installed, recorded as absent"));
            continue;
        }
        let live = fetch_tree(shell, &format!("{root}/Plugins/{app}"))?;
        let snap = fetch_tree(shell, &format!("{bk}/snapshot/{app}"))?;
        compare(&live, &snap, &format!("backup of {app}"))?;
        let (n, bytes) = summarize(&live);
        progress(&format!("{app}: {n} files, {bytes} bytes; head unit copy matches the live folder"));
        write_local(&local.join(app), &live)?;
        let mut disk = BTreeMap::new();
        collect_local(&local.join(app), Path::new(""), &mut disk)?;
        compare(&live, &disk, &format!("local copy of {app}"))?;
        progress(&format!("{app}: local copy matches the live folder"));
        for (rel, data) in &live {
            let line = format!("{}  {app}/{rel}  {} bytes", hex(data), data.len());
            progress(&format!("  {line}"));
            manifest.push_str(&line);
            manifest.push('\n');
        }
        total_files += n;
        total_bytes += bytes;
    }
    std::fs::write(local.join("apps"), list).map_err(|e| e.to_string())?;
    std::fs::write(local.join("manifest.txt"), manifest).map_err(|e| e.to_string())?;
    progress(&format!("Backup verified: {total_files} files, {total_bytes} bytes in {} folders", states.iter().filter(|s| s.1).count()));
    Ok(())
}

/// Backs up every folder under Plugins (and every app this installer manages, as "absent" when missing)
/// without changing anything else. Restoring the result returns those folders to their current state.
pub fn backup_all(shell: &mut dyn Shell, root: &str, local_root: &Path, id: &str, progress: Progress) -> Result<Done, String> {
    if !safe_name(id) {
        return Err("invalid backup id".into());
    }
    precheck(shell, root, progress)?;
    let list_cmd = format!(
        "for d in {}/Plugins/*; do test -e \"$d\" || continue; echo \"${{d##*/}}\"; done\n",
        q(root)
    );
    let listing = script(shell, &list_cmd)?;
    let mut touched: Vec<String> = Vec::new();
    for name in listing.lines().map(str::trim).filter(|n| !n.is_empty()) {
        if !safe_name(name) {
            return Err(format!("the Plugins folder contains an entry with an unsupported name: {name}"));
        }
        touched.push(name.to_string());
    }
    for d in APPS.iter().map(|a| a.dir).chain([LEGACY_EXHAUST_FLAP]) {
        if !touched.iter().any(|t| t == d) {
            touched.push(d.to_string());
        }
    }
    let bk = format!("{}/backups/{id}", base(root));
    let local = local_root.join("backups").join(id);
    let result = backup(shell, root, &bk, &local, &touched, progress);
    if let Err(e) = result {
        progress(&format!("Backup failed: {e}"));
        let _ = shell.exec(&format!("rm -rf {}", q(&bk)), None);
        let _ = std::fs::remove_dir_all(&local);
        return Err(e);
    }
    Ok(Done { backup_id: id.into(), remote_backup: bk, local_backup: local.display().to_string(), changed: touched })
}

#[derive(Debug)]
pub struct Done {
    pub backup_id: String,
    pub remote_backup: String,
    pub local_backup: String,
    pub changed: Vec<String>,
}

fn write_local(dir: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for (rel, bytes) in files {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&p, bytes).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
    }
    Ok(())
}

fn parse_apps_file(text: &str) -> Vec<(String, bool)> {
    text.lines()
        .filter_map(|l| {
            let (app, state) = l.split_once(' ')?;
            safe_name(app).then(|| (app.to_string(), state.trim() == "present"))
        })
        .collect()
}

/// Installs `staged` apps and removes `remove` apps in one transaction, after backing up everything touched.
pub fn apply(
    shell: &mut dyn Shell,
    root: &str,
    local_root: &Path,
    id: &str,
    staged: &[Staged],
    remove: &[String],
    progress: Progress,
) -> Result<Done, String> {
    if !safe_name(id) || staged.is_empty() && remove.is_empty() {
        return Err("nothing to do".into());
    }
    let mut touched: Vec<String> = staged.iter().map(|s| s.dir.clone()).collect();
    for r in remove {
        if !safe_name(r) {
            return Err(format!("invalid app name {r}"));
        }
        if !touched.contains(r) {
            touched.push(r.clone());
        }
    }
    if staged.iter().any(|s| s.dir == "MhdMaps") && !touched.iter().any(|t| t == LEGACY_EXHAUST_FLAP) {
        touched.push(LEGACY_EXHAUST_FLAP.into());
    }
    let remove_set: BTreeSet<String> = touched.iter().filter(|t| !staged.iter().any(|s| &s.dir == *t)).cloned().collect();
    let touching: BTreeSet<String> = touched.iter().cloned().collect();

    let bk = format!("{}/backups/{id}", base(root));
    let tx = format!("{}/tx-{id}", base(root));
    let local = local_root.join("backups").join(id);

    precheck(shell, root, progress)?;
    check_connectors(shell, root, staged, &touching)?;
    progress("No connector id conflicts with the other installed apps");

    let mut published = false;
    let result = (|| -> Result<(), String> {
        progress("Backing up the current apps");
        backup(shell, root, &bk, &local, &touched, progress)?;

        for s in staged {
            progress(&format!("Uploading {}", s.dir));
            let stage = format!("{tx}/new-{}", s.dir);
            for (rel, file) in &s.files {
                let path = format!("{stage}/{rel}");
                let parent = path.rsplit_once('/').map(|p| p.0).unwrap_or(&stage);
                let mode = if file.exec { "755" } else { "644" };
                let cmd = format!("mkdir -p {} && cat > {} && chmod {mode} {}", q(parent), q(&path), q(&path));
                shell.exec(&cmd, Some(&file.bytes))?;
            }
            let back = fetch_tree(shell, &stage)?;
            compare(&staged_bytes(s), &back, &format!("upload of {}", s.dir))?;
        }

        progress("Publishing");
        let entries: Vec<String> = touched
            .iter()
            .map(|t| match staged.iter().find(|s| &s.dir == t) {
                Some(s) => format!("{t}:stage:{}", s.workers.join(":")),
                None => format!("{t}:remove:"),
            })
            .collect();
        published = true;
        script(shell, &fill(PUBLISH, &[("__ROOT__", q(root)), ("__TX__", q(&tx)), ("__APPS__", q(&entries.join(" ")))]))?;

        progress("Verifying the result");
        for s in staged {
            let live = fetch_tree(shell, &format!("{root}/Plugins/{}", s.dir))?;
            compare(&staged_bytes(s), &live, &format!("installed {}", s.dir))?;
        }
        for r in &remove_set {
            let gone = shell.exec(&format!("test ! -e {}", q(&format!("{root}/Plugins/{r}"))), None);
            gone.map_err(|_| format!("{r} is still present"))?;
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            let _ = shell.exec(&format!("rm -rf {}", q(&tx)), None);
            Ok(Done { backup_id: id.into(), remote_backup: bk, local_backup: local.display().to_string(), changed: touched })
        }
        Err(e) => {
            // Exit status 3 means the rollback itself failed: keep everything for inspection.
            if !e.contains("exit status 3") {
                let _ = shell.exec(&format!("rm -rf {}", q(&tx)), None);
                if !published {
                    let _ = shell.exec(&format!("rm -rf {}", q(&bk)), None);
                    let _ = std::fs::remove_dir_all(&local);
                }
            }
            Err(e)
        }
    }
}

pub struct BackupInfo {
    pub id: String,
    pub apps: Vec<(String, bool)>,
}

pub fn list_backups(shell: &mut dyn Shell, root: &str) -> Result<Vec<BackupInfo>, String> {
    let cmd = format!(
        "for d in {r}/backups/*; do test -f \"$d/apps\" || continue; echo \"ID6BACKUP ${{d##*/}}\"; cat \"$d/apps\"; done\n",
        r = q(&base(root))
    );
    let out = String::from_utf8_lossy(&shell.exec("sh -s", Some(cmd.as_bytes()))?).into_owned();
    let mut v: Vec<BackupInfo> = out
        .split("ID6BACKUP ")
        .skip(1)
        .filter_map(|c| {
            let (id, body) = c.split_once('\n').unwrap_or((c, ""));
            safe_name(id.trim()).then(|| BackupInfo { id: id.trim().to_string(), apps: parse_apps_file(body) })
        })
        .collect();
    v.sort_by(|a, b| b.id.cmp(&a.id));
    Ok(v)
}

/// Puts the apps recorded in backup `backup_id` back to their backed-up state. If the backup is gone
/// from the head unit, it is re-uploaded from the copy on this computer first.
pub fn restore(shell: &mut dyn Shell, root: &str, local_root: &Path, backup_id: &str, progress: Progress) -> Result<Done, String> {
    if !safe_name(backup_id) {
        return Err("invalid backup id".into());
    }
    let bk = format!("{}/backups/{backup_id}", base(root));
    let local = local_root.join("backups").join(backup_id);
    precheck(shell, root, progress)?;

    let apps_text = match shell.exec(&format!("cat {}", q(&format!("{bk}/apps"))), None) {
        Ok(o) => String::from_utf8_lossy(&o).into_owned(),
        Err(_) => {
            progress("Backup not found on the head unit; restoring it from this computer");
            let text = std::fs::read_to_string(local.join("apps")).map_err(|_| format!("backup {backup_id} was not found on the head unit or this computer"))?;
            for (app, present) in parse_apps_file(&text) {
                if !present {
                    continue;
                }
                let mut files = BTreeMap::new();
                collect_local(&local.join(&app), Path::new(""), &mut files)?;
                let workers: &[&str] = APPS.iter().find(|a| a.dir == app).map(|a| a.workers).unwrap_or(&[]);
                for (rel, bytes) in &files {
                    let path = format!("{bk}/snapshot/{app}/{rel}");
                    let parent = path.rsplit_once('/').map(|p| p.0).unwrap_or(&bk);
                    let mode = if workers.contains(&rel.as_str()) { "755" } else { "644" };
                    shell.exec(&format!("mkdir -p {} && cat > {} && chmod {mode} {}", q(parent), q(&path), q(&path)), Some(bytes))?;
                }
                let back = fetch_tree(shell, &format!("{bk}/snapshot/{app}"))?;
                compare(&files, &back, &format!("re-upload of {app}"))?;
            }
            shell.exec(&format!("mkdir -p {0} && cat > {1}", q(&bk), q(&format!("{bk}/apps"))), Some(text.as_bytes()))?;
            text
        }
    };
    let apps = parse_apps_file(&apps_text);
    if apps.is_empty() {
        return Err(format!("backup {backup_id} lists no apps"));
    }
    let rtx = format!("{}/restored-{}-{}", base(root), backup_id, now_secs());
    let entries: Vec<String> = apps.iter().map(|(a, p)| format!("{a}:{}", if *p { "present" } else { "absent" })).collect();

    progress("Restoring");
    script(
        shell,
        &fill(RESTORE, &[("__ROOT__", q(root)), ("__BK__", q(&bk)), ("__RTX__", q(&rtx)), ("__ENTRIES__", q(&entries.join(" ")))]),
    )?;

    progress("Verifying the result");
    for (app, present) in &apps {
        if *present {
            let live = fetch_tree(shell, &format!("{root}/Plugins/{app}"))?;
            let snap = fetch_tree(shell, &format!("{bk}/snapshot/{app}"))?;
            compare(&snap, &live, &format!("restored {app}"))?;
        } else {
            shell
                .exec(&format!("test ! -e {}", q(&format!("{root}/Plugins/{app}"))), None)
                .map_err(|_| format!("{app} is still present"))?;
        }
    }
    Ok(Done {
        backup_id: backup_id.into(),
        remote_backup: bk,
        local_backup: format!("{} (the folders replaced by the restore were kept in {rtx})", local.display()),
        changed: apps.into_iter().map(|(a, _)| a).collect(),
    })
}

/// Deletes backup `backup_id` from the head unit (and optionally from this computer). When it was the last
/// thing in the installer folder, that folder is removed too, leaving no trace of the installer on the unit.
/// Does not touch any installed app.
pub fn delete_backup(shell: &mut dyn Shell, root: &str, local_root: &Path, backup_id: &str, delete_local: bool, progress: Progress) -> Result<String, String> {
    if !safe_name(backup_id) {
        return Err("invalid backup id".into());
    }
    precheck(shell, root, progress)?;
    let b = base(root);
    let bk = format!("{b}/backups/{backup_id}");
    shell
        .exec(&format!("test -f {}", q(&format!("{bk}/apps"))), None)
        .map_err(|_| format!("backup {backup_id} was not found on the head unit"))?;
    progress(&format!("Deleting the backup on the head unit: {bk}"));
    shell.exec(&format!("rm -rf {}", q(&bk)), None)?;
    shell.exec(&format!("test ! -e {}", q(&bk)), None).map_err(|_| format!("{bk} could not be fully deleted"))?;
    progress("Backup deleted from the head unit");
    let leftovers = String::from_utf8_lossy(&shell.exec(&format!("ls -a {} 2>/dev/null; true", q(&b)), None)?).into_owned();
    let names: Vec<&str> = leftovers.split_whitespace().filter(|n| *n != "." && *n != "..").collect();
    let only_empty_backups = names.is_empty() || names == ["backups"];
    if only_empty_backups {
        let clean_cmd = format!(
            "exists() {{ test -e \"$1\" || test -L \"$1\"; }}\n\
             rm_empty_dir() {{\n\
                 test -d \"$1\" && test ! -L \"$1\" || return 1\n\
                 for m in \"$1\"/* \"$1\"/.[!.]* \"$1\"/..?*; do\n\
                     if exists \"$m\"; then return 1; fi\n\
                 done\n\
                 rm -rf \"$1\"\n\
             }}\n\
             rm_empty_dir {0}/backups 2>/dev/null\n\
             rm_empty_dir {0} 2>/dev/null\n\
             true\n",
            q(&b)
        );
        let _ = script(shell, &clean_cmd);
        let gone = shell.exec(&format!("test ! -e {}", q(&b)), None).is_ok();
        if gone {
            progress("No backups remain: the ID6Installer folder was removed from the head unit");
        } else if shell.exec(&format!("test -d {}/backups", q(&b)), None).is_ok() {
            progress("Other backups remain: the ID6Installer folder was kept");
        } else {
            progress("The ID6Installer folder could not be removed");
        }
    } else {
        progress(&format!("The ID6Installer folder was kept because it still contains: {}", names.join(", ")));
    }
    if delete_local {
        let local = local_root.join("backups").join(backup_id);
        if local.exists() {
            std::fs::remove_dir_all(&local).map_err(|e| format!("cannot delete {}: {e}", local.display()))?;
            progress(&format!("Deleted the copy on this computer: {}", local.display()));
        }
    } else {
        progress("The copy on this computer was kept");
    }
    Ok(format!("Backup {backup_id} deleted"))
}

fn collect_local(dir: &Path, rel: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel: PathBuf = rel.join(&name);
        if entry.path().is_dir() {
            collect_local(&entry.path(), &rel, out)?;
        } else {
            out.insert(rel.to_string_lossy().into_owned(), std::fs::read(entry.path()).map_err(|e| e.to_string())?);
        }
    }
    Ok(())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// A PATH holding only the tools the head unit is known to have. The unit has no `head`, `tail`, `tr`,
    /// `wc` or `sed` in the scripts' reach, so any script that needs them fails here too.
    fn unit_path() -> String {
        static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PATH.get_or_init(build_unit_path).clone()
    }

    fn build_unit_path() -> String {
        let dir = std::env::temp_dir().join(format!("id6-unit-bin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for tool in ["sh", "cat", "ls", "find", "mkdir", "mv", "cp", "rm", "chmod", "uname", "df", "test"] {
            for prefix in ["/bin", "/usr/bin", "/sbin"] {
                let src = format!("{prefix}/{tool}");
                if Path::new(&src).exists() {
                    let _ = std::os::unix::fs::symlink(&src, dir.join(tool));
                    break;
                }
            }
        }
        dir.display().to_string()
    }

    /// Runs the real shell scripts against a temporary folder on this computer.
    struct Local;
    impl Shell for Local {
        fn exec(&mut self, command: &str, input: Option<&[u8]>) -> Result<Vec<u8>, String> {
            let mut child = Command::new("/bin/sh")
                .env("PATH", unit_path())
                .arg("-c")
                .arg(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let data = input.map(|d| d.to_vec()).unwrap_or_default();
            let t = std::thread::spawn(move || {
                let _ = stdin.write_all(&data);
            });
            let out = child.wait_with_output().unwrap();
            t.join().unwrap();
            if out.status.success() {
                Ok(out.stdout)
            } else {
                Err(format!("exit status {}: {}", out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).trim()))
            }
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("id6-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn staged(dir: &str, extra: &[(&str, &str)]) -> Staged {
        let mut files = BTreeMap::new();
        let manifest = format!("<plugin><name>{dir}</name><pluginAppConnector><id>150</id></pluginAppConnector></plugin>");
        files.insert(format!("{dir}.manifest"), File { bytes: manifest.into_bytes(), exec: false });
        files.insert("worker-qnx".into(), File { bytes: b"#!/bin/sh\n".to_vec(), exec: true });
        for (k, v) in extra {
            files.insert(k.to_string(), File { bytes: v.as_bytes().to_vec(), exec: false });
        }
        Staged { dir: dir.into(), workers: vec!["worker-qnx".into()], files }
    }

    fn seed(root: &Path, dir: &str, content: &str) {
        let d = root.join("Plugins").join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("{dir}.manifest")), content).unwrap();
        std::fs::write(d.join("original.txt"), content).unwrap();
    }

    fn quiet() -> impl FnMut(&str) {
        |_: &str| {}
    }

    #[test]
    fn install_backup_and_restore_round_trip() {
        let root = tmp("rt-root");
        let loc = tmp("rt-local");
        let r = root.to_str().unwrap();
        seed(&root, "BoostDeck", "old boostdeck");
        seed(&root, "Other", "keep me");

        let done = apply(&mut Local, r, &loc, "b1", &[staged("BoostDeck", &[("new.txt", "new")]), staged("ShiftDeck", &[])], &[], &mut quiet()).unwrap();
        assert_eq!(done.changed, vec!["BoostDeck", "ShiftDeck"]);
        assert!(root.join("Plugins/BoostDeck/new.txt").exists());
        assert!(!root.join("Plugins/BoostDeck/original.txt").exists());
        assert!(root.join("Plugins/ShiftDeck/ShiftDeck.manifest").exists());
        assert_eq!(std::fs::read_to_string(root.join("Plugins/Other/original.txt")).unwrap(), "keep me");
        assert!(!root.join("ID6Installer/lock").exists());
        assert!(!root.join("ID6Installer/tx-b1").exists());
        assert!(loc.join("backups/b1/BoostDeck/original.txt").exists());

        let backups = list_backups(&mut Local, r).unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].apps, vec![("BoostDeck".to_string(), true), ("ShiftDeck".to_string(), false)]);

        restore(&mut Local, r, &loc, "b1", &mut quiet()).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("Plugins/BoostDeck/original.txt")).unwrap(), "old boostdeck");
        assert!(!root.join("Plugins/BoostDeck/new.txt").exists());
        assert!(!root.join("Plugins/ShiftDeck").exists());
        assert_eq!(std::fs::read_to_string(root.join("Plugins/Other/original.txt")).unwrap(), "keep me");
        assert!(!root.join("ID6Installer/lock").exists());
    }

    #[test]
    fn restore_falls_back_to_local_copy() {
        let root = tmp("fb-root");
        let loc = tmp("fb-local");
        let r = root.to_str().unwrap();
        seed(&root, "BoostDeck", "precious");
        apply(&mut Local, r, &loc, "b2", &[staged("BoostDeck", &[])], &[], &mut quiet()).unwrap();
        std::fs::remove_dir_all(root.join("ID6Installer/backups")).unwrap();
        restore(&mut Local, r, &loc, "b2", &mut quiet()).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("Plugins/BoostDeck/original.txt")).unwrap(), "precious");
    }

    #[test]
    fn uninstall_moves_app_to_backup_and_restore_returns_it() {
        let root = tmp("un-root");
        let loc = tmp("un-local");
        let r = root.to_str().unwrap();
        seed(&root, "EngineCodes", "codes");
        apply(&mut Local, r, &loc, "b3", &[], &["EngineCodes".to_string()], &mut quiet()).unwrap();
        assert!(!root.join("Plugins/EngineCodes").exists());
        restore(&mut Local, r, &loc, "b3", &mut quiet()).unwrap();
        assert!(root.join("Plugins/EngineCodes/original.txt").exists());
    }

    #[test]
    fn failed_publish_rolls_back() {
        let root = tmp("rb-root");
        let loc = tmp("rb-local");
        let r = root.to_str().unwrap();
        seed(&root, "BoostDeck", "original");
        // The second app declares a worker that the staged folder does not have, so publish fails after the first moved.
        let mut bad = staged("ShiftDeck", &[]);
        bad.workers = vec!["missing-qnx".into()];
        let err = apply(&mut Local, r, &loc, "b4", &[staged("BoostDeck", &[("new.txt", "x")]), bad], &[], &mut quiet()).unwrap_err();
        assert!(err.contains("missing-qnx"), "{err}");
        assert_eq!(std::fs::read_to_string(root.join("Plugins/BoostDeck/original.txt")).unwrap(), "original");
        assert!(!root.join("Plugins/BoostDeck/new.txt").exists());
        assert!(!root.join("Plugins/ShiftDeck").exists());
        assert!(!root.join("ID6Installer/lock").exists());
    }

    #[test]
    fn existing_lock_blocks_install() {
        let root = tmp("lk-root");
        let loc = tmp("lk-local");
        std::fs::create_dir_all(root.join("ID6Installer/lock")).unwrap();
        let err = apply(&mut Local, root.to_str().unwrap(), &loc, "b5", &[staged("BoostDeck", &[])], &[], &mut quiet()).unwrap_err();
        assert!(err.contains("lock"), "{err}");
        assert!(root.join("ID6Installer/lock").exists());
    }

    #[test]
    fn connector_conflict_is_rejected() {
        let root = tmp("cc-root");
        let loc = tmp("cc-local");
        seed(&root, "Stranger", "<pluginAppConnector><id>150</id></pluginAppConnector>");
        let err = apply(&mut Local, root.to_str().unwrap(), &loc, "b6", &[staged("BoostDeck", &[])], &[], &mut quiet()).unwrap_err();
        assert!(err.contains("connector 150") && err.contains("Stranger"), "{err}");
    }

    #[test]
    fn mhd_install_also_retires_legacy_exhaust_flap() {
        let root = tmp("ef-root");
        let loc = tmp("ef-local");
        let r = root.to_str().unwrap();
        seed(&root, "ExhaustFlap", "legacy");
        apply(&mut Local, r, &loc, "b7", &[staged("MhdMaps", &[])], &[], &mut quiet()).unwrap();
        assert!(!root.join("Plugins/ExhaustFlap").exists());
        restore(&mut Local, r, &loc, "b7", &mut quiet()).unwrap();
        assert!(root.join("Plugins/ExhaustFlap/original.txt").exists());
        assert!(!root.join("Plugins/MhdMaps").exists());
    }

    #[test]
    fn missing_hmi_folder_stops_before_changing_anything() {
        let parent = tmp("nr-parent");
        let root = parent.join("does-not-exist");
        let loc = tmp("nr-local");
        let r = root.to_str().unwrap();
        for result in [
            apply(&mut Local, r, &loc, "b8", &[staged("BoostDeck", &[])], &[], &mut quiet()).map(|_| ()),
            backup_all(&mut Local, r, &loc, "b8", &mut quiet()).map(|_| ()),
            restore(&mut Local, r, &loc, "b8", &mut quiet()).map(|_| ()),
        ] {
            let err = result.unwrap_err();
            assert!(err.contains("does not exist") && err.contains("Nothing was changed"), "{err}");
        }
        assert!(!root.exists());
        assert!(!loc.join("backups").exists());
    }

    #[test]
    fn backup_all_changes_nothing_and_logs_every_file() {
        let root = tmp("ba-root");
        let loc = tmp("ba-local");
        let r = root.to_str().unwrap();
        seed(&root, "BoostDeck", "alpha");
        seed(&root, "Stranger", "beta");
        let mut log: Vec<String> = Vec::new();
        let done = backup_all(&mut Local, r, &loc, "b9", &mut |m: &str| log.push(m.to_string())).unwrap();
        let text = log.join("\n");
        assert!(text.contains("exists on the head unit") && text.contains("root:"), "{text}");
        assert!(text.contains("BoostDeck: 2 files") && text.contains("Stranger: 2 files"), "{text}");
        assert!(text.contains("local copy matches the live folder"), "{text}");
        assert!(text.contains(&hex(b"alpha")), "{text}");
        assert!(text.contains("Backup verified: 4 files"), "{text}");
        assert!(done.changed.contains(&"Stranger".to_string()) && done.changed.contains(&"MhdMaps".to_string()));
        // Live folders untouched, no lock left, local manifest written.
        assert_eq!(std::fs::read_to_string(root.join("Plugins/BoostDeck/original.txt")).unwrap(), "alpha");
        assert!(!root.join("ID6Installer/lock").exists());
        assert!(loc.join("backups/b9/manifest.txt").exists());
        // Restoring it later puts everything back, including an app that appeared in between.
        std::fs::write(root.join("Plugins/BoostDeck/original.txt"), "changed").unwrap();
        seed(&root, "MhdMaps", "added later");
        restore(&mut Local, r, &loc, "b9", &mut quiet()).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("Plugins/BoostDeck/original.txt")).unwrap(), "alpha");
        assert!(!root.join("Plugins/MhdMaps").exists());
    }

    #[test]
    fn find_root_picks_first_existing_candidate_and_logs() {
        let a = tmp("fr-a");
        let b = tmp("fr-b");
        let missing = a.join("nope");
        let mut log: Vec<String> = Vec::new();
        let found = find_root(&mut Local, &[missing.to_str().unwrap(), b.to_str().unwrap(), a.to_str().unwrap()], &mut |m: &str| log.push(m.into())).unwrap();
        assert_eq!(found, b.to_str().unwrap());
        let text = log.join("\n");
        assert!(text.contains("candidate missing") && text.contains("candidate exists") && text.contains("Using"), "{text}");
        let err = find_root(&mut Local, &[missing.to_str().unwrap()], &mut quiet()).unwrap_err();
        assert!(err.contains("Nothing was changed"), "{err}");
    }

    #[test]
    fn delete_backup_cleans_up_without_touching_apps() {
        let root = tmp("db-root");
        let loc = tmp("db-local");
        let r = root.to_str().unwrap();
        seed(&root, "BoostDeck", "mine");
        backup_all(&mut Local, r, &loc, "b10", &mut quiet()).unwrap();
        backup_all(&mut Local, r, &loc, "b11", &mut quiet()).unwrap();
        let mut log: Vec<String> = Vec::new();
        delete_backup(&mut Local, r, &loc, "b10", false, &mut |m: &str| log.push(m.into())).unwrap();
        assert!(!root.join("ID6Installer/backups/b10").exists());
        assert!(root.join("ID6Installer/backups/b11").exists());
        assert!(loc.join("backups/b10").exists(), "local copy kept");
        // Deleting the last backup removes the installer folder and optionally the local copy.
        delete_backup(&mut Local, r, &loc, "b11", true, &mut |m: &str| log.push(m.into())).unwrap();
        assert!(!root.join("ID6Installer").exists());
        assert!(!loc.join("backups/b11").exists());
        assert!(log.join("\n").contains("ID6Installer folder was removed"));
        assert_eq!(std::fs::read_to_string(root.join("Plugins/BoostDeck/original.txt")).unwrap(), "mine");
        assert!(delete_backup(&mut Local, r, &loc, "b11", false, &mut quiet()).unwrap_err().contains("not found"));
        assert!(delete_backup(&mut Local, r, &loc, "../x", false, &mut quiet()).is_err());
    }

    #[test]
    fn target_shell_wraps_commands_for_hu_omap() {
        struct Record(Vec<String>);
        impl Shell for Record {
            fn exec(&mut self, command: &str, _input: Option<&[u8]>) -> Result<Vec<u8>, String> {
                self.0.push(command.to_string());
                Ok(vec![])
            }
        }
        let mut rec = Record(vec![]);
        {
            let mut sh = TargetShell::wrap(&mut rec, true);
            sh.exec("sh -s", Some(b"true\n")).unwrap();
            sh.exec("cat '/var/opt/hmi/data/ID5/apps'", None).unwrap();
        }
        assert_eq!(rec.0[0], "on -f hu-omap sh -s");
        assert_eq!(rec.0[1], "on -f hu-omap sh -c 'cat '\\''/var/opt/hmi/data/ID5/apps'\\'''");
    }

    #[test]
    fn selection_rules() {
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(resolve(&ids(&["mhd", "bm3"])).is_err());
        assert!(resolve(&ids(&[])).is_err());
        assert!(resolve(&ids(&["nope"])).is_err());
        assert_eq!(resolve(&ids(&["mhd", "boostdeck", "mhd"])).unwrap().len(), 2);
    }

    #[test]
    fn bundled_packages_load_and_verify() {
        let packages = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages");
        for app in APPS.iter() {
            let s = load_staged(&packages, app, Some("169.254.21.3".parse().unwrap())).unwrap_or_else(|e| panic!("{}: {e}", app.dir));
            assert!(s.files[app.workers[0]].exec);
            assert_eq!(s.files["gateway-ip.txt"].bytes, b"169.254.21.3\n");
        }
    }
}

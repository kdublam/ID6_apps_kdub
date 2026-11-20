import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import "./style.css";

type Check = { name: string; ok: boolean; detail: string };
type Result = {
  report: Record<string, unknown>;
  assessment: { verdict: "supported" | "porting_needed" | "unknown"; checks: Check[]; evidence: string | null };
};
type Enet = { name: string; ip: string };
type Done = { backup_id: string; remote_backup: string; local_backup: string; changed: string[]; log_file: string };
type Backup = { id: string; created: number; apps: string[] };

const APPS: { id: string; name: string; text: string; dir: string }[] = [
  { id: "mhd", name: "MHD+ Suite", text: "Four map slots, Exhaust Flap and Max Cooling.", dir: "MhdMaps" },
  { id: "bm3", name: "Bootmod3 Suite", text: "Beta. Compatible CustomROM tunes.", dir: "Bootmod3Suite" },
  { id: "boostdeck", name: "BoostDeck", text: "Boost, AFR and other live gauges.", dir: "BoostDeck" },
  { id: "shiftdeck", name: "ShiftDeck", text: "Speed, RPM bar and shift lights.", dir: "ShiftDeck" },
  { id: "enginecodes", name: "Engine Fault Codes", text: "Read engine codes.", dir: "EngineCodes" },
  { id: "xdrive", name: "xDrive Control", text: "Beta. The engine must be off before switching AWD and RWD.", dir: "XDriveControl" },
  { id: "hud", name: "HUD Gauges", text: "Requires a factory windshield HUD.", dir: "HudTest" },
];

const STEPS = ["Prepare", "Connect", "Check", "Choose apps", "Backups", "Result"];
const state = {
  step: 0,
  consent: [false, false, false],
  head: "",
  hostKey: "",
  password: "",
  firmware: "",
  enet: [] as Enet[],
  busy: false,
  error: "",
  result: null as Result | null,
  saved: "",
  op: "install" as "install" | "uninstall",
  selected: new Set<string>(["mhd", "boostdeck", "shiftdeck", "enginecodes"]),
  gateway: "",
  backups: null as Backup[] | null,
  progress: "",
  done: null as Done | null,
  doneKind: "",
  pending: "",
  log: [] as string[],
  deleteLocal: false,
  diag: "",
  notice: "",
};

const root = document.querySelector<HTMLDivElement>("#app")!;
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

function prepare() {
  const items = [
    "The car is parked and iDrive is awake.",
    "This computer is connected to the car over wired ENET.",
    "I am authorized to work on this car. The compatibility check only reads. Installing, removing and restoring write to the head unit, and a backup is taken first.",
  ];
  return `<h2>Before you start</h2>
    ${items.map((t, i) => `<label class="row"><input type="checkbox" data-consent="${i}" ${state.consent[i] ? "checked" : ""}/> ${t}</label>`).join("")}
    <div class="actions"><button id="next" ${state.consent.every(Boolean) ? "" : "disabled"}>Continue</button></div>`;
}

function connect() {
  const detected = state.enet.length
    ? `Detected ENET adapter: ${state.enet.map((e) => `<code>${esc(e.name)} ${esc(e.ip)}</code>`).join(", ")}`
    : "No 169.254.x.x ENET adapter detected. Check the cable.";
  return `<h2>Connect</h2>
    <p class="hint">${detected}</p>
    <label>Head unit SSH address<input type="text" id="head" placeholder="169.254.x.x" value="${esc(state.head)}"/></label>
    <p class="hint">SSH must already be unlocked with a tool such as <a href="https://ssh.bavarian-aa.uk/" data-ext>Bavarian SSH Client</a>.</p>
    ${state.hostKey ? `<p>Host key fingerprint:<br/><code>${esc(state.hostKey)}</code></p><p class="hint">Confirm it matches the unlock tool before continuing.</p>
    <label>Password (optional, the default head unit password is used when empty)<input type="password" id="password" value="${esc(state.password)}"/></label>` : ""}
    <p class="hint"><a href="#" id="open-logs">Open logs folder</a> · <a href="#" id="save-diag">Save diagnostics file for a bug report</a>${state.diag ? ` (saved to <code>${esc(state.diag)}</code>)` : ""}</p>
    <div class="actions">
      <button class="secondary" id="back">Back</button>
      ${state.hostKey
        ? `<button class="secondary" id="backups" ${state.busy ? "disabled" : ""}>Backups &amp; restore</button><button id="trust" ${state.busy ? "disabled" : ""}>Trust and run check</button>`
        : `<button id="probe" ${state.busy ? "disabled" : ""}>Connect</button>`}
    </div>`;
}

function check() {
  const r = state.result;
  if (!r) return `<h2>Check</h2><p>Reading firmware, framework hashes and display from the head unit...</p>
    ${state.error ? `<label>Firmware code shown on iDrive<input type="text" id="firmware" placeholder="NBTevo_N18032I" value="${esc(state.firmware)}"/></label>
    <div class="actions"><button class="secondary" id="back">Back</button><button id="retry">Retry</button></div>` : ""}`;
  const label = { supported: "Supported", porting_needed: "Porting needed", unknown: "Unknown firmware" }[r.assessment.verdict];
  return `<h2>Check</h2>
    <div class="verdict ${r.assessment.verdict === "supported" ? "ok" : "bad"}">${label}</div>
    ${r.assessment.evidence ? `<p class="hint">${esc(r.assessment.evidence)}</p>` : ""}
    ${r.assessment.checks.map((c) => `<div class="check"><b class="${c.ok ? "ok" : "bad"}">${c.ok ? "✓" : "✗"}</b><div><div>${esc(c.name)}</div><code>${esc(c.detail)}</code></div></div>`).join("")}
    ${r.assessment.verdict !== "supported" ? `<p class="hint">See the porting workflow in <code>source/docs/PORTING.md</code> before installing anything.</p>` : ""}
    <div class="actions">
      <button class="secondary" id="save">Export report</button>
      <button id="next" ${r.assessment.verdict === "supported" ? "" : "disabled"}>Choose apps</button>
    </div>
    ${state.saved ? `<p class="hint">Saved to <code>${esc(state.saved)}</code></p>` : ""}`;
}

function apps() {
  const removing = state.op === "uninstall";
  const row = (a: (typeof APPS)[number], type: string) =>
    `<label class="row"><input type="${type}" name="${type === "radio" ? "tune" : "app"}" data-app="${a.id}" ${state.selected.has(a.id) ? "checked" : ""}/> <span><b>${a.name}</b><br/><span class="hint">${a.text}</span></span></label>`;
  const tune = APPS.filter((a) => a.id === "mhd" || a.id === "bm3");
  const rest = APPS.filter((a) => a.id !== "mhd" && a.id !== "bm3");
  const none = !state.selected.has("mhd") && !state.selected.has("bm3");
  return `<h2>Choose apps</h2>
    <label>Operation<select id="op"><option value="install" ${removing ? "" : "selected"}>Install</option><option value="uninstall" ${removing ? "selected" : ""}>Uninstall</option></select></label>
    <p class="hint">${removing
      ? "Selected apps are moved to a backup on the head unit. You can bring them back from Backups &amp; restore."
      : "Everything this changes is backed up first, on the head unit and on this computer, and can be reverted from Backups &amp; restore."}</p>
    <div class="apps">
      ${removing ? APPS.map((a) => row(a, "checkbox")).join("") : `${tune.map((a) => row(a, "radio")).join("")}
      <label class="row"><input type="radio" name="tune" data-app="none" ${none ? "checked" : ""}/> <span><b>No tuning suite</b></span></label>
      ${rest.map((a) => row(a, "checkbox")).join("")}`}
    </div>
    ${removing ? "" : `<label>Diagnostic gateway IP (optional, default 169.254.21.3)<input type="text" id="gateway" placeholder="169.254.21.3" value="${esc(state.gateway)}"/></label>`}
    <div class="actions">
      <button class="secondary" id="back">Back</button>
      <button id="apply" ${state.busy || state.selected.size === 0 ? "disabled" : ""}>${state.pending === "apply" ? "Confirm: the car stays parked with iDrive awake" : removing ? "Uninstall selected apps" : "Install selected apps"}</button>
    </div>
    ${logPanel()}`;
}

const logPanel = () =>
  state.log.length ? `<details ${state.busy ? "open" : ""}><summary>Log (${state.log.length} lines)</summary><pre class="log">${esc(state.log.join("\n"))}</pre></details>` : "";

function when(secs: number) {
  return secs ? new Date(secs * 1000).toLocaleString() : "unknown time";
}

function backups() {
  const list = state.backups;
  const name = (dir: string) => APPS.find((a) => a.dir === dir)?.name ?? dir;
  return `<h2>Backups &amp; restore</h2>
    <p class="hint">Restoring puts the apps recorded in a backup back exactly as they were, including removing apps that were not installed then. Other apps are not touched.</p>
    ${list === null ? "<p>Reading backups from the head unit...</p>" : list.length === 0 ? "<p>No backups found on the head unit.</p>" : list.map((b) => `<div class="check"><div><div><b>${esc(when(b.created))}</b></div><code>${esc(b.apps.map(name).join(", "))}</code></div>
      <div class="actions"><button data-restore="${esc(b.id)}" ${state.busy ? "disabled" : ""}>${state.pending === "restore:" + b.id ? "Confirm restore" : "Restore"}</button>
      <button class="secondary" data-delete="${esc(b.id)}" ${state.busy ? "disabled" : ""}>${state.pending === "delete:" + b.id ? "Confirm delete (cannot be undone)" : "Delete"}</button></div></div>`).join("")}
    ${list && list.length ? `<label class="row"><input type="checkbox" id="delete-local" ${state.deleteLocal ? "checked" : ""}/> Also delete the copy on this computer when deleting</label>
    <p class="hint">Deleting a backup does not change any installed app. Once it is deleted, that state can no longer be restored. Deleting the last backup also removes the ID6Installer folder from the head unit.</p>` : ""}
    ${state.notice ? `<p class="hint">${esc(state.notice)}</p>` : ""}
    ${logPanel()}
    ${state.error && state.log.length ? `<p class="hint">The full log was saved to the log file named in the error above.</p>` : ""}
    <div class="actions"><button class="secondary" id="back-connect">Back</button><button id="backup-now" ${state.busy ? "disabled" : ""}>Back up now</button></div>`;
}

function result() {
  const d = state.done;
  if (!d) return "<h2>Result</h2>";
  const name = (dir: string) => APPS.find((a) => a.dir === dir)?.name ?? dir;
  return `<h2>${esc(state.doneKind)} complete</h2>
    <div class="verdict ok">Verified</div>
    <p>Changed: ${esc(d.changed.map(name).join(", "))}</p>
    <p class="hint">Backup on the head unit:<br/><code>${esc(d.remote_backup)}</code></p>
    <p class="hint">Backup on this computer:<br/><code>${esc(d.local_backup)}</code></p>
    <p class="hint">Log file:<br/><code>${esc(d.log_file)}</code></p>
    ${logPanel()}
    <p class="hint">Restart iDrive while parked (hold the volume knob until the screen goes dark), then check the menus under My Vehicle. To revert, use Backups &amp; restore. Temporary SSH ends when the head unit reboots.</p>
    <div class="actions"><button class="secondary" id="restart">Start over</button></div>`;
}

function render() {
  const body = [prepare, connect, check, apps, backups, result][state.step]();
  root.innerHTML = `<main><h1>ID6 Installer by PNWGR</h1>
    <div class="steps">${STEPS.map((s, i) => `<span class="${i === state.step ? "on" : ""}">${i + 1}. ${s}</span>`).join("")}</div>
    <div class="card">${body}${state.error ? `<p class="err">${esc(state.error)}</p>` : ""}</div></main>`;
  bind();
}

const go = (step: number) => {
  state.step = step;
  state.pending = "";
  state.error = "";
  render();
};

async function guarded(fn: () => Promise<void>) {
  state.busy = true;
  state.error = "";
  render();
  try {
    await fn();
  } catch (e) {
    state.error = String(e);
    void invoke("log_ui", { message: `error on step ${STEPS[state.step]}: ${state.error}` });
  }
  state.busy = false;
  render();
}

async function runCheck() {
  state.result = null;
  go(2);
  await guarded(async () => {
    state.result = await invoke<Result>("run_check", {
      head: state.head,
      hostKey: state.hostKey,
      password: state.password || null,
      firmware: state.firmware || null,
    });
  });
}

const creds = () => ({ head: state.head, hostKey: state.hostKey, password: state.password || null });

async function loadBackups() {
  state.backups = null;
  go(4);
  await guarded(async () => {
    state.backups = await invoke<Backup[]>("list_backups", creds());
  });
}

function bind() {
  document.querySelectorAll<HTMLAnchorElement>("a[data-ext]").forEach((a) =>
    a.addEventListener("click", (e) => {
      e.preventDefault();
      void openUrl(a.href);
    }));
  const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T | null;
  document.querySelectorAll<HTMLInputElement>("[data-consent]").forEach((el) =>
    el.addEventListener("change", () => {
      state.consent[Number(el.dataset.consent)] = el.checked;
      render();
    }));
  $("head")?.addEventListener("input", (e) => {
    state.head = (e.target as HTMLInputElement).value;
    state.hostKey = "";
  });
  $("password")?.addEventListener("input", (e) => (state.password = (e.target as HTMLInputElement).value));
  $("firmware")?.addEventListener("input", (e) => (state.firmware = (e.target as HTMLInputElement).value));
  $("back")?.addEventListener("click", () => go(state.step - 1));
  $("next")?.addEventListener("click", async () => {
    if (state.step === 0) {
      state.enet = await invoke<Enet[]>("detect_enet");
      if (!state.head && state.enet[0]) state.head = state.enet[0].ip.replace(/\.\d+$/, ".");
    }
    go(state.step + 1);
  });
  $("probe")?.addEventListener("click", () =>
    guarded(async () => {
      state.hostKey = await invoke<string>("probe_host_key", { head: state.head });
    }));
  $("trust")?.addEventListener("click", runCheck);
  $("retry")?.addEventListener("click", runCheck);
  $("backups")?.addEventListener("click", loadBackups);
  $("open-logs")?.addEventListener("click", (e) => {
    e.preventDefault();
    invoke("open_logs_folder").catch((err) => {
      state.error = String(err);
      render();
    });
  });
  $("save-diag")?.addEventListener("click", (e) => {
    e.preventDefault();
    invoke<string>("save_diagnostics")
      .then((p) => {
        state.diag = p;
        render();
      })
      .catch((err) => {
        state.error = String(err);
        render();
      });
  });
  $("delete-local")?.addEventListener("change", (e) => (state.deleteLocal = (e.target as HTMLInputElement).checked));
  document.querySelectorAll<HTMLButtonElement>("[data-delete]").forEach((el) =>
    el.addEventListener("click", async () => {
      const id = el.dataset.delete!;
      if (state.pending !== "delete:" + id) {
        state.pending = "delete:" + id;
        return render();
      }
      state.pending = "";
      state.log = [];
      state.notice = "";
      await guarded(async () => {
        const log = await invoke<string>("delete_backup", { ...creds(), backupId: id, deleteLocal: state.deleteLocal });
        state.notice = `Backup deleted. Log: ${log}`;
        state.backups = await invoke<Backup[]>("list_backups", creds());
      });
    }));
  $("backup-now")?.addEventListener("click", async () => {
    state.log = [];
    await guarded(async () => {
      state.done = await invoke<Done>("backup_now", creds());
      state.doneKind = "Backup";
      state.step = 5;
    });
  });
  $("back-connect")?.addEventListener("click", () => go(1));
  $("restart")?.addEventListener("click", () => go(1));
  $("op")?.addEventListener("change", (e) => {
    state.op = (e.target as HTMLSelectElement).value as "install" | "uninstall";
    state.selected = new Set(state.op === "install" ? ["mhd", "boostdeck", "shiftdeck", "enginecodes"] : []);
    render();
  });
  $("gateway")?.addEventListener("input", (e) => (state.gateway = (e.target as HTMLInputElement).value));
  document.querySelectorAll<HTMLInputElement>("[data-app]").forEach((el) =>
    el.addEventListener("change", () => {
      const id = el.dataset.app!;
      if (el.type === "radio") {
        state.selected.delete("mhd");
        state.selected.delete("bm3");
        if (id !== "none") state.selected.add(id);
      } else if (el.checked) state.selected.add(id);
      else state.selected.delete(id);
      render();
    }));
  $("apply")?.addEventListener("click", async () => {
    const removing = state.op === "uninstall";
    if (state.pending !== "apply") {
      state.pending = "apply";
      return render();
    }
    state.pending = "";
    const chosen = APPS.filter((a) => state.selected.has(a.id));
    state.log = [];
    await guarded(async () => {
      state.done = await invoke<Done>("install_apps", {
        ...creds(),
        firmware: state.firmware || null,
        install: removing ? [] : chosen.map((a) => a.id),
        remove: removing ? chosen.map((a) => a.dir) : [],
        gateway: state.gateway || null,
      });
      state.doneKind = removing ? "Uninstall" : "Install";
      state.step = 5;
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-restore]").forEach((el) =>
    el.addEventListener("click", async () => {
      if (state.pending !== "restore:" + el.dataset.restore) {
        state.pending = "restore:" + el.dataset.restore;
        return render();
      }
      state.pending = "";
      state.log = [];
      await guarded(async () => {
        state.done = await invoke<Done>("restore_backup", { ...creds(), backupId: el.dataset.restore });
        state.doneKind = "Restore";
        state.step = 5;
      });
    }));
  $("save")?.addEventListener("click", () =>
    guarded(async () => {
      state.saved = await invoke<string>("save_report", { result: state.result });
    }));
}

window.addEventListener("error", (e) => void invoke("log_ui", { message: `uncaught: ${e.message}` }));
window.addEventListener("unhandledrejection", (e) => void invoke("log_ui", { message: `unhandled rejection: ${String(e.reason)}` }));
void listen<string>("progress", (e) => {
  state.progress = e.payload;
  state.log.push(e.payload);
  if (state.busy) render();
});
render();

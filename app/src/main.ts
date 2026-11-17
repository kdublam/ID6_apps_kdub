import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import "./style.css";

type Check = { name: string; ok: boolean; detail: string };
type Result = {
  report: Record<string, unknown>;
  assessment: { verdict: "supported" | "porting_needed" | "unknown"; checks: Check[]; evidence: string | null };
};
type Enet = { name: string; ip: string };

const STEPS = ["Prepare", "Connect", "Check", "Choose apps"];
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
};

const root = document.querySelector<HTMLDivElement>("#app")!;
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

function prepare() {
  const items = [
    "The car is parked and iDrive is awake.",
    "This computer is connected to the car over wired ENET.",
    "I am authorized to work on this car and understand this step only reads from the head unit.",
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
    <label>Password (leave empty to use your SSH agent)<input type="password" id="password" value="${esc(state.password)}"/></label>` : ""}
    <div class="actions">
      <button class="secondary" id="back">Back</button>
      ${state.hostKey
        ? `<button id="trust" ${state.busy ? "disabled" : ""}>Trust and run check</button>`
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
  const opt = (type: string, name: string, text: string, checked = false) =>
    `<label class="row"><input type="${type}" name="tune" disabled ${checked ? "checked" : ""}/> <span><b>${name}</b><br/><span class="hint">${text}</span></span></label>`;
  return `<h2>Choose apps</h2>
    <p class="hint">Installing is not available in this version. This preview only checks compatibility.</p>
    <div class="apps">
      ${opt("radio", "MHD+ Suite", "Four map slots, Exhaust Flap and Max Cooling.", true)}
      ${opt("radio", "Bootmod3 Suite", "Beta. Compatible CustomROM tunes.")}
      ${opt("checkbox", "BoostDeck", "Boost, AFR and other live gauges.", true)}
      ${opt("checkbox", "ShiftDeck", "Speed, RPM bar and shift lights.", true)}
      ${opt("checkbox", "Engine Fault Codes", "Read engine codes.", true)}
      ${opt("checkbox", "xDrive Control", "Beta. The engine must be off before switching AWD and RWD.")}
      ${opt("checkbox", "HUD Gauges", "Requires a factory windshield HUD.")}
    </div>
    <div class="actions"><button class="secondary" id="back">Back</button></div>`;
}

function render() {
  const body = [prepare, connect, check, apps][state.step]();
  root.innerHTML = `<main><h1>ID6 Installer by PNWGR</h1>
    <div class="steps">${STEPS.map((s, i) => `<span class="${i === state.step ? "on" : ""}">${i + 1}. ${s}</span>`).join("")}</div>
    <div class="card">${body}${state.error ? `<p class="err">${esc(state.error)}</p>` : ""}</div></main>`;
  bind();
}

const go = (step: number) => {
  state.step = step;
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
  $("save")?.addEventListener("click", () =>
    guarded(async () => {
      state.saved = await invoke<string>("save_report", { result: state.result });
    }));
}

render();

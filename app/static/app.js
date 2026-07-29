"use strict";

// ---------- helpers ----------
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => (s == null ? "" : String(s).replace(/[&<>"]/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])));

async function api(path, opts = {}) {
  const res = await fetch("api/" + path, { credentials: "same-origin", ...opts });
  if (!res.ok) {
    let msg = res.status + " " + res.statusText;
    try { const j = await res.json(); if (j.detail) msg = j.detail; } catch (_) {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

let toastTimer;
function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 3200);
}

function fmtBytes(b) {
  if (b == null || b === "" || isNaN(b)) return null;
  b = Number(b);
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b >= 100 || i === 0 ? 0 : 1) + " " + u[i];
}

function ago(iso) {
  if (!iso) return "—";
  const d = new Date(iso), s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  if (s < 604800) return Math.floor(s / 86400) + "d ago";
  return d.toLocaleDateString();
}

// CIM_DATETIME like "20230115120000.000000+000" -> "2023-01-15"
function cimDate(s) {
  if (!s || typeof s !== "string" || s.length < 8) return s || null;
  const m = s.match(/^(\d{4})(\d{2})(\d{2})/);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : s;
}

// ---------- tabs ----------
$$("#tabs button").forEach(b => b.addEventListener("click", () => {
  $$("#tabs button").forEach(x => x.classList.toggle("active", x === b));
  const tab = b.dataset.tab;
  $$(".panel").forEach(p => (p.hidden = p.dataset.panel !== tab));
  if (tab === "scans") loadHistory();
  if (tab === "credentials") loadCreds();
  if (tab === "settings") loadSettings();
}));

// ---------- inventory ----------
const TYPES = ["windows", "linux", "mac", "printer", "network", "unknown"];
let filter = { q: "", type: "", site: "", online: null };

function buildChips() {
  const wrap = $("#typeChips");
  wrap.innerHTML = "";
  const all = document.createElement("button");
  all.textContent = "all";
  all.className = "active";
  all.onclick = () => setType("");
  wrap.appendChild(all);
  TYPES.forEach(t => {
    const b = document.createElement("button");
    b.textContent = t;
    b.dataset.type = t;
    b.onclick = () => setType(t);
    wrap.appendChild(b);
  });
}
function setType(t) {
  filter.type = t;
  $$("#typeChips button").forEach(b =>
    b.classList.toggle("active", (b.dataset.type || "") === t));
  loadDevices();
}

let searchTimer;
$("#searchBox").addEventListener("input", e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { filter.q = e.target.value.trim(); loadDevices(); }, 220);
});
$("#siteFilter").addEventListener("change", e => { filter.site = e.target.value; loadDevices(); });
$("#onlineOnly").addEventListener("change", e => { filter.online = e.target.checked ? true : null; loadDevices(); });

async function loadDevices() {
  const p = new URLSearchParams();
  if (filter.q) p.set("q", filter.q);
  if (filter.type) p.set("type", filter.type);
  if (filter.site) p.set("site", filter.site);
  if (filter.online !== null) p.set("online", filter.online);
  let devices;
  try { devices = await api("devices?" + p.toString()); }
  catch (e) { toast("Failed to load devices: " + e.message, true); return; }

  const tbody = $("#deviceRows");
  const empty = $("#deviceEmpty");
  $("#deviceCount").textContent = devices.length + " device" + (devices.length === 1 ? "" : "s");
  populateSites(devices);
  if (!devices.length) {
    tbody.innerHTML = "";
    empty.hidden = false;
    $("#deviceTable").style.display = "none";
    return;
  }
  empty.hidden = true;
  $("#deviceTable").style.display = "";
  tbody.innerHTML = devices.map(rowHtml).join("");
  $$("#deviceRows tr").forEach(tr =>
    tr.addEventListener("click", () => openDevice(tr.dataset.id)));
}

let sitesSeen = false;
function populateSites(devices) {
  if (sitesSeen) return;
  const sites = [...new Set(devices.map(d => d.site).filter(Boolean))].sort();
  if (!sites.length) return;
  const sel = $("#siteFilter");
  const current = sel.value;
  // rebuild, keeping the "All sites" option at index 0
  [...sel.querySelectorAll("option:not([value=''])")].forEach(o => o.remove());
  sites.forEach(s => {
    const o = document.createElement("option");
    o.value = s; o.textContent = s; sel.appendChild(o);
  });
  sel.value = current;
  sitesSeen = true;
}

function rowHtml(d) {
  const ports = (d.open_ports || []).map(p => p.port).join(" ");
  const mesh = d.mesh_link
    ? `<span class="mesh-chip ${d.mesh_agent ? "" : "off"}"><span class="stat"></span>${d.mesh_agent ? "agent" : "linked"}</span>`
    : `<span class="muted small">—</span>`;
  return `<tr class="clickable" data-id="${d.id}">
    <td><span class="stat ${d.online ? "online" : "offline"}" title="${d.online ? "online" : "offline"}"></span></td>
    <td class="host-cell">${esc(d.hostname || "(unknown)")}${d.fqdn ? `<span class="sub">${esc(d.fqdn)}</span>` : ""}</td>
    <td class="mono">${esc(d.ip)}</td>
    <td><span class="badge ${esc(d.device_type)}">${esc(d.device_type)}</span></td>
    <td>${esc(d.os_name || "—")}</td>
    <td>${esc(d.vendor || "—")}</td>
    <td>${esc(d.site || "—")}</td>
    <td><span class="ports" title="${esc(ports)}">${esc(ports || "—")}</span></td>
    <td>${mesh}</td>
    <td class="muted small">${ago(d.last_seen)}</td>
  </tr>`;
}

// ---------- device drawer ----------
function rows(pairs, sans = false) {
  const items = pairs.filter(([, v]) => v != null && v !== "" &&
    !(Array.isArray(v) && v.length === 0));
  if (!items.length) return "";
  return `<div class="rows">` + items.map(([k, v]) =>
    `<div class="k">${esc(k)}</div><div class="v ${sans ? "sans" : ""}">${esc(v)}</div>`).join("") + `</div>`;
}
function sect(title, body) {
  return body ? `<div class="sect"><h3>${esc(title)}</h3>${body}</div>` : "";
}

async function openDevice(id) {
  let d;
  try { d = await api("devices/" + id); }
  catch (e) { toast("Failed to load device: " + e.message, true); return; }

  const wmi = d.wmi || {}, ssh = d.ssh || {}, snmp = d.snmp || {}, mesh = d.mesh || {};
  const wos = wmi.os || {}, wc = wmi.computer || {}, wp = wmi.product || {}, wb = wmi.bios || {};

  // Hardware summary from best available source
  const manufacturer = wp.vendor || wc.manufacturer || null;
  const model = wp.name || wc.model || ssh.product || null;
  const serial = wp.serial || wb.serial || (wos.serial) || ssh.serial || null;
  const memBytes = wc.total_memory_bytes || ssh.mem_bytes || null;

  const cpuBody = (() => {
    if (wmi._ok && (wmi.cpu || []).length)
      return (wmi.cpu).map(c =>
        `${esc(c.name || "CPU")} — ${c.cores || "?"}c/${c.threads || "?"}t${c.max_mhz ? " @ " + (c.max_mhz / 1000).toFixed(1) + "GHz" : ""}`
      ).join("<br>");
    if (ssh.cpu) return esc(ssh.cpu) + (ssh.cpu_count ? ` (${esc(ssh.cpu_count)} cores)` : "");
    return null;
  })();

  const disksBody = (() => {
    if ((wmi.disks || []).length)
      return `<div class="rows">` + wmi.disks.map(dk =>
        `<div class="k mono">${esc(dk.device || "")}</div><div class="v">${fmtBytes(dk.size_bytes) || "?"} total · ${fmtBytes(dk.free_bytes) || "?"} free${dk.label ? " · " + esc(dk.label) : ""}</div>`
      ).join("") + `</div>`;
    if (ssh.disk_root) return `<div class="rows"><div class="k mono">/</div><div class="v">${esc(ssh.disk_root)}</div></div>`;
    return null;
  })();

  const netBody = (() => {
    const a = wmi.adapters || [];
    if (!a.length) return null;
    return a.map(ad => `<div class="rows">
      <div class="k">${esc(ad.description || "adapter")}</div>
      <div class="v">${esc((ad.ips || []).join(", "))}${ad.mac ? "<br>MAC " + esc(ad.mac) : ""}${ad.gateway ? "<br>GW " + esc([].concat(ad.gateway).join(", ")) : ""}</div>
    </div>`).join("");
  })();

  const portsBody = (d.open_ports || []).length
    ? `<div class="port-list">` + d.open_ports.map(p =>
        `<span class="port-tag"><b>${p.port}</b>${p.service ? "/" + esc(p.service) : ""}${p.product ? " " + esc(p.product) : ""}</span>`
      ).join("") + `</div>`
    : null;

  const snmpBody = snmp._ok ? rows([
    ["Description", (snmp.system || {}).sysDescr],
    ["Name", (snmp.system || {}).sysName],
    ["Location", (snmp.system || {}).sysLocation],
    ["Contact", (snmp.system || {}).sysContact],
    ["Uptime", (snmp.system || {}).sysUpTime],
    ["Interfaces", snmp.interface_count],
    ["Page count", snmp.page_count],
  ]) : "";

  const avBody = (wmi.antivirus || []).length
    ? rows(wmi.antivirus.map(a => [a.name || "AV", "state " + a.state]), true) : "";

  const sw = d.software || [];
  const swBody = sw.length ? `<div class="sw-list"><table>` +
    sw.slice(0, 500).map(s => `<tr><td>${esc(s.name)}</td><td>${esc(s.version || "")}</td></tr>`).join("") +
    `</table></div>` : (wmi._ok ? `<p class="muted small">No software recorded.</p>` : "");

  const meshBody = mesh.nodeid ? `
    ${rows([
      ["Agent", mesh.agent_online ? "online" : "offline"],
      ["Group", mesh.mesh],
      ["Agent OS", mesh.os_desc],
      ["Agent version", mesh.agent_ver],
      ["Tags", (mesh.tags || []).join(", ")],
    ], true)}
    ${mesh.link ? `<a class="mesh-open" href="${esc(mesh.link)}" target="_blank" rel="noopener">Open in MeshCentral ↗</a>` : ""}
  ` : `<p class="muted small">No matching MeshCentral agent.</p>`;

  const osBody = rows([
    ["Name", d.os_name],
    ["Version", wos.version],
    ["Build", wos.build],
    ["Architecture", wos.architecture || ssh.arch],
    ["Kernel", ssh.kernel],
    ["Installed", cimDate(wos.install_date)],
    ["Last boot", cimDate(wos.last_boot)],
    ["Uptime", ssh.uptime],
    ["Logged-on user", wc.logged_on_user],
  ]);

  const html = `
    <div class="dh">
      <div class="dh-top">
        <div>
          <h2>${esc(d.hostname || d.ip)}</h2>
          <div class="ip">${esc(d.ip)}${d.mac ? " · " + esc(d.mac) : ""}</div>
        </div>
        <button class="close" id="drawerClose" aria-label="Close">×</button>
      </div>
      <div class="meta">
        <span class="stat ${d.online ? "online" : "offline"}"></span>
        <span class="badge ${esc(d.device_type)}">${esc(d.device_type)}</span>
        ${d.site ? `<span class="muted small">${esc(d.site)}</span>` : ""}
        ${d.mesh_agent ? `<span class="mesh-chip"><span class="stat"></span>mesh agent</span>` : ""}
      </div>
    </div>
    <div class="db">
      ${sect("Identity", rows([
        ["MAC address", d.mac],
        ["Vendor", d.vendor],
        ["FQDN", d.fqdn],
        ["Domain", wc.domain],
        ["First seen", new Date(d.first_seen).toLocaleString()],
        ["Last seen", new Date(d.last_seen).toLocaleString()],
      ], false))}
      ${sect("Operating system", osBody)}
      ${sect("Hardware", rows([
        ["Manufacturer", manufacturer],
        ["Model", model],
        ["Serial", serial],
        ["Memory", fmtBytes(memBytes)],
        ["BIOS", wb.version],
      ], true) + (cpuBody ? `<div class="rows" style="margin-top:6px"><div class="k">CPU</div><div class="v">${cpuBody}</div></div>` : ""))}
      ${sect("Storage", disksBody)}
      ${sect("Network adapters", netBody)}
      ${sect("Open ports & services", portsBody)}
      ${sect("SNMP", snmpBody)}
      ${sect("Antivirus", avBody)}
      ${sect(`Installed software${sw.length ? " (" + sw.length + ")" : ""}`, swBody)}
      ${sect("MeshCentral", meshBody)}
      <div class="sect">
        <h3>Notes</h3>
        <textarea class="notes-area" id="notesArea" placeholder="Operator notes…">${esc(d.notes || "")}</textarea>
        <div class="form-actions">
          <button class="btn primary tiny" id="saveNotes">Save notes</button>
          <button class="btn danger tiny" id="deleteDevice">Delete device</button>
        </div>
      </div>
    </div>`;

  const drawer = $("#drawer");
  drawer.innerHTML = html;
  drawer.hidden = false;
  $("#drawerScrim").hidden = false;
  $("#drawerClose").onclick = closeDrawer;
  $("#saveNotes").onclick = async () => {
    try {
      await api("devices/" + id + "/notes", {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: $("#notesArea").value }),
      });
      toast("Notes saved");
    } catch (e) { toast("Save failed: " + e.message, true); }
  };
  $("#deleteDevice").onclick = async () => {
    if (!confirm("Delete this device from the inventory?")) return;
    try { await api("devices/" + id, { method: "DELETE" }); closeDrawer(); loadDevices(); toast("Device deleted"); }
    catch (e) { toast("Delete failed: " + e.message, true); }
  };
}
function closeDrawer() { $("#drawer").hidden = true; $("#drawerScrim").hidden = true; }
$("#drawerScrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

// ---------- scan control ----------
let pollTimer;
$("#runScanBtn").addEventListener("click", async () => {
  try {
    const r = await api("scan/run", { method: "POST" });
    if (r.already_running) { toast("A scan is already running"); }
    else { toast("Scan started"); }
    startPolling();
  } catch (e) { toast("Could not start scan: " + e.message, true); }
});

function setPill(state, text) {
  const pill = $("#scanPill");
  pill.className = "scan-pill " + (state || "");
  $(".label", pill).textContent = text;
}

async function pollStatus() {
  let s;
  try { s = await api("scan/status"); } catch (_) { return; }
  const prog = s.progress || {};
  const live = $("#liveState");
  if (s.running) {
    const done = prog.done, total = prog.total;
    const pct = total ? Math.round((done / total) * 100) : (prog.phase === "discovery" ? 8 : 3);
    setPill("running", total ? `scanning ${done}/${total}` : "scanning");
    if (live) { live.textContent = "running"; live.className = "state-badge running"; }
    $("#progressBar").style.width = pct + "%";
    $("#scanMsg").textContent = prog.message || "Working…";
  } else {
    clearInterval(pollTimer); pollTimer = null;
    const state = prog.state === "error" ? "error" : (prog.state === "finished" ? "finished" : "");
    setPill(state, prog.state === "error" ? "scan failed" : (prog.state === "finished" ? "scan complete" : "idle"));
    if (live) {
      live.textContent = prog.state || "idle";
      live.className = "state-badge " + (prog.state === "error" ? "error" : prog.state === "finished" ? "finished" : "");
    }
    if (prog.state === "finished") { $("#progressBar").style.width = "100%"; $("#scanMsg").textContent = "Scan complete."; loadDevices(); }
    if (prog.state === "error") { $("#scanMsg").textContent = "Error: " + (prog.error || prog.message || "unknown"); }
    loadHistory();
  }
}
function startPolling() {
  if (pollTimer) return;
  pollStatus();
  pollTimer = setInterval(pollStatus, 1500);
}

const recorrBtn = $("#recorrelateBtn");
if (recorrBtn) recorrBtn.addEventListener("click", async () => {
  recorrBtn.disabled = true;
  const prev = recorrBtn.textContent;
  recorrBtn.textContent = "Matching…";
  try {
    const r = await api("scan/recorrelate", { method: "POST" });
    if (r.ok) { toast(`MeshCentral: ${r.correlated} of ${r.nodes} nodes matched`); loadDevices(); }
    else toast("MeshCentral: " + (r.error || "failed"), true);
  } catch (e) { toast("Failed: " + e.message, true); }
  finally { recorrBtn.disabled = false; recorrBtn.textContent = prev; }
});

async function loadHistory() {
  let rows;
  try { rows = await api("scan/history"); } catch (_) { return; }
  $("#historyRows").innerHTML = rows.map(r => {
    let dur = "—";
    if (r.finished_at) {
      const s = (new Date(r.finished_at) - new Date(r.started_at)) / 1000;
      dur = s < 60 ? Math.round(s) + "s" : Math.floor(s / 60) + "m " + Math.round(s % 60) + "s";
    }
    const cls = r.status === "done" ? "finished" : r.status === "error" ? "error" : "running";
    return `<tr>
      <td>${new Date(r.started_at).toLocaleString()}</td>
      <td>${esc(r.trigger)}</td>
      <td><span class="state-badge ${cls}">${esc(r.status)}</span></td>
      <td class="mono">${r.hosts_found}</td>
      <td class="mono">${r.hosts_probed}</td>
      <td class="mono">${dur}</td>
      <td class="mono small">${esc((r.subnets || []).join(", "))}</td>
    </tr>`;
  }).join("");
}

// ---------- credentials ----------
let editingCred = null;
$("#credKind").addEventListener("change", syncCredForm);
function syncCredForm() {
  const kind = $("#credKind").value;
  $$("[data-cred-group]").forEach(el => {
    const groups = el.dataset.credGroup.split(" ");
    el.style.display = groups.includes(kind) ? "" : "none";
  });
  $("#secretLabel").firstChild.textContent = kind === "ssh" ? "Password or private key " : "Password ";
}

async function loadCreds() {
  let creds;
  try { creds = await api("credentials"); } catch (e) { toast("Failed to load credentials: " + e.message, true); return; }
  $("#credRows").innerHTML = creds.map(c => `<tr>
    <td>${esc(c.name)}</td>
    <td><span class="badge ${c.kind === "windows" ? "windows" : c.kind === "ssh" ? "linux" : "network"}">${esc(c.kind)}</span></td>
    <td class="mono small">${esc(c.kind === "snmp" ? "community" : (c.domain ? c.domain + "\\" : "") + (c.username || ""))}</td>
    <td>${c.enabled ? "yes" : "no"}</td>
    <td style="text-align:right;white-space:nowrap">
      <button class="btn tiny ghost" data-edit="${c.id}">Edit</button>
      <button class="btn tiny danger" data-del="${c.id}">Delete</button>
    </td></tr>`).join("");
  $$("#credRows [data-edit]").forEach(b => b.onclick = () => editCred(creds.find(c => c.id == b.dataset.edit)));
  $$("#credRows [data-del]").forEach(b => b.onclick = () => delCred(b.dataset.del));
  syncCredForm();
}

function editCred(c) {
  editingCred = c.id;
  $("#credFormTitle").textContent = "Edit credential";
  $("#credKind").value = c.kind;
  $("#credName").value = c.name;
  $("#credDomain").value = c.domain || "";
  $("#credUser").value = c.username || "";
  $("#credSnmpVer").value = c.snmp_version || "v2c";
  $("#credSecret").value = "";
  $("#credCommunity").value = "";
  $("#credEnabled").checked = c.enabled;
  $("#credReset").hidden = false;
  $("#credSecret").placeholder = c.has_secret ? "(unchanged)" : "";
  $("#credCommunity").placeholder = c.has_secret ? "(unchanged)" : "public";
  syncCredForm();
  window.scrollTo({ top: 0, behavior: "smooth" });
}
function resetCredForm() {
  editingCred = null;
  $("#credFormTitle").textContent = "Add credential";
  ["credName", "credDomain", "credUser", "credSecret", "credCommunity"].forEach(i => ($("#" + i).value = ""));
  $("#credEnabled").checked = true;
  $("#credReset").hidden = true;
  $("#credSecret").placeholder = "••••••••";
  $("#credCommunity").placeholder = "public";
}
$("#credReset").onclick = resetCredForm;

$("#credSave").onclick = async () => {
  const kind = $("#credKind").value;
  const body = {
    name: $("#credName").value.trim(), kind,
    domain: $("#credDomain").value.trim() || null,
    username: $("#credUser").value.trim() || null,
    secret: $("#credSecret").value || null,
    snmp_version: $("#credSnmpVer").value,
    community: $("#credCommunity").value || null,
    enabled: $("#credEnabled").checked,
  };
  if (!body.name) { toast("Name is required", true); return; }
  try {
    if (editingCred) await api("credentials/" + editingCred, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    else await api("credentials", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    toast("Credential saved");
    resetCredForm();
    loadCreds();
  } catch (e) { toast("Save failed: " + e.message, true); }
};
async function delCred(id) {
  if (!confirm("Delete this credential?")) return;
  try { await api("credentials/" + id, { method: "DELETE" }); loadCreds(); toast("Credential deleted"); }
  catch (e) { toast("Delete failed: " + e.message, true); }
}

// ---------- settings ----------
async function loadSettings() {
  // subnets
  try {
    const subnets = await api("settings/subnets");
    const wrap = $("#subnetRows");
    wrap.innerHTML = "";
    (subnets.length ? subnets : [{ cidr: "", label: "" }]).forEach(addSubnetRow);
  } catch (e) { toast("Failed to load subnets: " + e.message, true); }
  // mesh
  try {
    const m = await api("settings/mesh");
    $("#meshUrl").value = m.url || "";
    $("#meshUser").value = m.username || "";
    $("#meshVerify").checked = m.verify_tls;
    $("#meshPass").placeholder = m.has_password ? "(unchanged)" : "";
    $("#meshToken").placeholder = m.has_token ? "(unchanged)" : "optional";
  } catch (_) {}
  // scan params
  try {
    const p = await api("settings/scan");
    $("#scanParams").innerHTML = `
      <dt>nmap timing</dt><dd>-T${p.nmap_timing}</dd>
      <dt>OS detection</dt><dd>${p.nmap_os_detect}</dd>
      <dt>Max concurrency</dt><dd>${p.max_concurrency}</dd>
      <dt>Probe timeout</dt><dd>${p.probe_timeout}s</dd>
      <dt>Software inventory</dt><dd>${p.wmi_software_inventory}</dd>
      <dt>Schedule</dt><dd>${p.scan_cron || "(disabled)"}</dd>`;
  } catch (_) {}
}

function addSubnetRow(s = { cidr: "", label: "" }) {
  const row = document.createElement("div");
  row.className = "subnet-row";
  row.innerHTML = `
    <input class="cidr-in" placeholder="10.0.1.0/24" value="${esc(s.cidr || "")}" />
    <input class="label-in" placeholder="Site label" value="${esc(s.label || "")}" />
    <button class="btn tiny danger" title="Remove">×</button>`;
  row.querySelector("button").onclick = () => row.remove();
  $("#subnetRows").appendChild(row);
}
$("#addSubnet").onclick = () => addSubnetRow();
$("#saveSubnets").onclick = async () => {
  const subnets = $$("#subnetRows .subnet-row").map(r => ({
    cidr: r.querySelector(".cidr-in").value.trim(),
    label: r.querySelector(".label-in").value.trim() || null,
  })).filter(s => s.cidr);
  try {
    await api("settings/subnets", {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(subnets) });
    toast("Subnets saved");
    sitesSeen = false;
  } catch (e) { toast("Save failed: " + e.message, true); }
};

$("#saveMesh").onclick = async () => {
  const body = {
    url: $("#meshUrl").value.trim(),
    username: $("#meshUser").value.trim(),
    password: $("#meshPass").value || "",
    token: $("#meshToken").value || "",
    verify_tls: $("#meshVerify").checked,
  };
  try {
    await api("settings/mesh", {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    toast("MeshCentral settings saved");
    $("#meshPass").value = ""; $("#meshToken").value = "";
    loadSettings();
  } catch (e) { toast("Save failed: " + e.message, true); }
};
$("#testMesh").onclick = async () => {
  const r = $("#meshResult");
  r.textContent = "Testing…"; r.className = "test-result";
  try {
    const res = await api("settings/mesh/test", { method: "POST" });
    if (res.ok) {
      r.className = "test-result ok";
      r.textContent = `Connected to ${res.server || "server"} · ${res.node_count} nodes, ${res.agents_online} agents online`;
    } else { r.className = "test-result err"; r.textContent = "Failed: " + (res.error || "unknown"); }
  } catch (e) { r.className = "test-result err"; r.textContent = "Failed: " + e.message; }
};

// ---------- init ----------
buildChips();
loadDevices();
startPolling();

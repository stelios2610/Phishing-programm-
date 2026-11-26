let last = null;
let busy = false;

function formatTime(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  try {
    const zone = "Europe/Bucharest";
    const when = new Intl.DateTimeFormat("en-GB", {
      timeZone: zone,
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    }).format(date);
    const name = new Intl.DateTimeFormat("en-GB", {
      timeZone: zone,
      timeZoneName: "short",
    }).formatToParts(date).find((part) => part.type === "timeZoneName");
    return name ? when + " " + name.value : when;
  } catch (_err) {
    return iso;
  }
}

function render(state) {
  last = state;
  const banner = document.getElementById("banner");
  banner.hidden = state.view !== "demo";
  banner.textContent = "Simulation. The numbers and alerts here are not the real network, and no packet was sent.";

  const gateway = state.gateway || {};
  document.getElementById("gateway-ip").textContent = gateway.ip || "No gateway visible";
  const iface = gateway.iface ? " · " + gateway.iface : "";
  document.getElementById("gateway-mac").textContent = (gateway.mac || "No MAC yet") + iface;
  const trust = document.getElementById("gateway-trust");
  trust.className = "";
  if (!state.taken_at && state.view !== "demo") {
    trust.textContent = "No reading yet.";
  } else if (gateway.mismatch) {
    trust.className = "bad";
    const confirmed = gateway.trusted ? gateway.trusted.mac : "";
    trust.textContent = "The MAC does not match the confirmed one." + (confirmed ? " " + confirmed : "");
  } else if (gateway.trusted) {
    trust.className = "ok";
    trust.textContent = "Confirmed: " + gateway.trusted.mac + (state.locked ? " · A static entry is active on this computer." : "");
  } else {
    trust.textContent = "Not confirmed. Compare the MAC with the router before you confirm.";
  }

  const icmp = state.icmp || {};
  document.getElementById("ping-session").textContent = "New pings since opening: " + (icmp.session_pings || 0);
  if (icmp.in_echos === null || icmp.in_echos === undefined) {
    document.getElementById("ping-kernel").textContent = "ICMP counters were not read.";
  } else if (state.view === "demo") {
    document.getElementById("ping-kernel").textContent = "Counter inside the simulation: " + icmp.in_echos;
  } else {
    document.getElementById("ping-kernel").textContent = "Pings since system boot: " + icmp.in_echos;
  }
  document.getElementById("redirect-session").textContent = "New ICMP redirects since opening: " + (icmp.session_redirects || 0);

  const capture = document.getElementById("capture-mode");
  if (state.capture === "icmp-echo") capture.textContent = "The address that sends a ping (ICMP echo) is visible.";
  else if (state.capture === "counters") capture.textContent = "The count of incoming pings is visible, not the sender. The sender needs administrator rights.";
  else capture.textContent = "This system's ICMP counters were not read.";
  const when = formatTime(state.taken_at);
  document.getElementById("updated").textContent = when ? "Last reading: " + when : "";

  const flags = state.flags || {};
  document.getElementById("confirm").disabled = busy || !flags.can_confirm;
  document.getElementById("accept").hidden = !flags.can_accept;
  document.getElementById("accept").disabled = busy || !flags.can_accept;
  document.getElementById("protect").disabled = busy || !flags.can_protect;
  document.getElementById("forget").disabled = busy || !flags.can_forget;
  document.getElementById("demo-reset").disabled = busy || state.view !== "demo";
  for (const id of ["demo-ping", "demo-mitm", "demo-redirect"]) {
    document.getElementById(id).disabled = busy;
  }

  const note = document.getElementById("protect-note");
  const command = document.getElementById("protect-command");
  const protection = state.view === "live" ? state.protection : null;
  if (protection) {
    note.textContent = protection.message || "";
    command.hidden = !protection.command;
    command.textContent = protection.command || "";
  } else {
    note.textContent = "";
    command.hidden = true;
    command.textContent = "";
  }

  renderAlerts(state.alerts || []);
  renderNeighbors(state.neighbors || []);
  document.getElementById("footer").textContent = "NetWatch " + (state.version || "") + " — addresses stay on this computer. Nothing is uploaded.";
}

function renderAlerts(alerts) {
  const root = document.getElementById("alerts");
  root.replaceChildren();
  if (!alerts.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No alerts since opening.";
    root.append(empty);
    return;
  }
  for (const alert of alerts) {
    const article = document.createElement("article");
    article.className = "alert " + (alert.severity || "info");
    const title = document.createElement("h3");
    title.textContent = alert.title || "";
    const detail = document.createElement("p");
    detail.textContent = alert.detail || "";
    const meta = document.createElement("p");
    meta.className = "meta";
    const kind = alert.simulated ? "simulation" : "live";
    const count = alert.count > 1 ? " · " + alert.count : "";
    meta.textContent = [formatTime(alert.at), kind].filter(Boolean).join(" · ") + count;
    article.append(title, detail, meta);
    root.append(article);
  }
}

function renderNeighbors(rows) {
  const body = document.getElementById("neighbors");
  body.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.textContent = "No ARP entries yet.";
    tr.append(td);
    body.append(tr);
    return;
  }
  const roles = { gateway: "router", clone: "copied MAC", device: "device" };
  for (const row of rows) {
    const tr = document.createElement("tr");
    if (row.role === "gateway" || row.role === "clone") tr.className = row.role;
    for (const value of [row.ip, row.mac, row.iface, row.state]) {
      const td = document.createElement("td");
      td.className = "mono";
      td.textContent = value || "";
      tr.append(td);
    }
    const role = document.createElement("td");
    role.textContent = roles[row.role] || "device";
    tr.append(role);
    body.append(tr);
  }
}

async function refresh() {
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(String(response.status));
    render(await response.json());
  } catch (_err) {
    document.getElementById("action-msg").textContent = "NetWatch status could not be read.";
  }
}

async function act(url, body) {
  if (busy) return;
  busy = true;
  if (last) render(last);
  try {
    const options = { method: "POST" };
    if (body) {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(body);
    }
    const response = await fetch(url, options);
    const data = await response.json();
    if (data.state) render(data.state);
    document.getElementById("action-msg").textContent = data.message || "";
  } catch (_err) {
    document.getElementById("action-msg").textContent = "NetWatch status could not be read.";
  } finally {
    busy = false;
    if (last) render(last);
  }
}

document.getElementById("confirm").addEventListener("click", () => act("/api/gateway/confirm", {}));
document.getElementById("accept").addEventListener("click", () => act("/api/gateway/confirm", { accept_change: true }));
document.getElementById("protect").addEventListener("click", () => act("/api/protect"));
document.getElementById("forget").addEventListener("click", () => act("/api/gateway/forget"));
document.getElementById("demo-ping").addEventListener("click", () => act("/api/demo/ping"));
document.getElementById("demo-mitm").addEventListener("click", () => act("/api/demo/mitm"));
document.getElementById("demo-redirect").addEventListener("click", () => act("/api/demo/redirect"));
document.getElementById("demo-reset").addEventListener("click", () => act("/api/demo/reset"));

refresh();
setInterval(refresh, 2000);

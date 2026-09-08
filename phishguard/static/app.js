const I18N = {
  el: {
    hero: "Έλεγχος phishing για Microsoft και τα πάντα",
    lede: "Επικολλήστε οποιοδήποτε URL. Η ανάλυση γίνεται στον υπολογιστή σας: typosquatting, homograph/IDN, κόλπο @, απομίμηση brand, ύποπτα TLD και kits σε δωρεάν hosting. Ο σύνδεσμος δεν ανοίγεται — έτσι δεν πέφτετε στην παγίδα.",
    label: "URL",
    analyze: "Ανάλυση",
    hint: "Enter για ανάλυση. Δοκιμάστε τα παραδείγματα παρακάτω.",
    examples: "Παραδείγματα",
    c1t: "Microsoft 365 / Outlook",
    c1: "Επίσημα: microsoft.com, microsoftonline.com, office.com, outlook.com, live.com, azure.com. Οτιδήποτε άλλο με «microsoft» στο subdomain είναι απομίμηση.",
    c2t: "Τράπεζες & gov.gr",
    c2: "Καλύπτει NBG, Eurobank, Πειραιώς, Alpha, gov.gr / AADE, PayPal, Visa, Revolut και διεθνείς τράπεζες.",
    c3t: "Χωρίς δίκτυο προς το phishing",
    c3: "Δεν γίνεται fetch της σελίδας, δεν στέλνεται το URL σε τρίτους. Μόνο heuristics στο host, το path και τους χαρακτήρες.",
    footer: "PhishGuard 1.0 — αμυντικό εργαλείο. Κανένα εργαλείο δεν είναι 100%. Αν αμφιβάλλετε, μην συνδεθείτε.",
    risk: "Κίνδυνος",
    official: "Επίσημο brand",
    looks: "Μοιάζει με",
    findings: "Ευρήματα",
    none: "Κανένα εύρημα.",
    error: "Η ανάλυση απέτυχε.",
  },
  en: {
    hero: "Phishing checks for Microsoft and everything else",
    lede: "Paste any URL. Analysis stays on this machine: typosquatting, homograph/IDN, @ tricks, brand impersonation, risky TLDs, and kits on free hosting. The link is never fetched — so you do not walk into the trap.",
    label: "URL",
    analyze: "Analyze",
    hint: "Press Enter to analyze. Try the examples below.",
    examples: "Examples",
    c1t: "Microsoft 365 / Outlook",
    c1: "Official: microsoft.com, microsoftonline.com, office.com, outlook.com, live.com, azure.com. Anything else with “microsoft” as a subdomain is impersonation.",
    c2t: "Banks & gov.gr",
    c2: "Covers NBG, Eurobank, Piraeus, Alpha, gov.gr / AADE, PayPal, Visa, Revolut, and major international banks.",
    c3t: "No request to the phish",
    c3: "The page is not fetched and the URL is not sent to a third party. Heuristics only: host, path, and characters.",
    footer: "PhishGuard 1.0 — defensive tool. Nothing is 100%. If you doubt it, do not sign in.",
    risk: "Risk",
    official: "Official brand",
    looks: "Looks like",
    findings: "Findings",
    none: "No findings.",
    error: "Analysis failed.",
  },
};

const EXAMPLES = [
  { label: "Microsoft official", url: "https://login.microsoftonline.com/" },
  { label: "Subdomain trap", url: "https://login.microsoft.com.secure-auth.xyz/signin" },
  { label: "Typosquat", url: "https://micros0ft-online.com/login" },
  { label: "@ trick", url: "https://login.microsoftonline.com@evil.example/login" },
  { label: "gov.gr phish", url: "https://gov-gr-taxisnet.web.app/login" },
  { label: "PayPal path kit", url: "http://185.22.10.4/paypal/webscr?cmd=_login" },
];

let lang = "el";

function t(key) {
  return I18N[lang][key];
}

function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll(".lang button").forEach((b) => {
    b.classList.toggle("on", b.dataset.lang === lang);
  });
}

function meterClass(verdict) {
  if (verdict === "official" || verdict === "likely_safe") return "ok";
  if (verdict === "suspicious") return "warn";
  return "bad";
}

function render(data) {
  const box = document.getElementById("result");
  box.classList.remove("hidden");
  const titleKey = lang === "el" ? "title_el" : "title";
  const detailKey = lang === "el" ? "detail_el" : "detail";
  const findings = (data.findings || [])
    .map(
      (f) => `<li>
        <div class="sev ${f.severity}">${f.severity}</div>
        <h4>${escapeHtml(f[titleKey] || f.title)}</h4>
        <p>${escapeHtml(f[detailKey] || f.detail)}</p>
      </li>`
    )
    .join("");
  const verdictLabel = lang === "el" ? data.verdict_el : data.verdict.replace("_", " ");
  box.innerHTML = `
    <div class="verdict">
      <div>
        <span class="badge ${data.verdict}">${escapeHtml(verdictLabel)}</span>
        <p class="meta" style="margin:10px 0 0">${escapeHtml(data.normalized || data.url)}</p>
      </div>
      <div style="min-width:160px;text-align:right">
        <div style="font-size:13px;color:var(--muted)">${t("risk")}</div>
        <div style="font-size:28px;font-weight:800">${data.risk_percent}</div>
      </div>
    </div>
    <div class="meter ${meterClass(data.verdict)}"><span style="width:${data.risk_percent}%"></span></div>
    <p class="meta">
      ${data.official_brand ? `${t("official")}: <strong>${escapeHtml(data.official_brand)}</strong> · ` : ""}
      ${data.impersonated_brand ? `${t("looks")}: <strong>${escapeHtml(data.impersonated_brand)}</strong>` : ""}
    </p>
    <h3 style="margin:18px 0 0;font-size:14px;color:var(--muted)">${t("findings")}</h3>
    <ul class="findings">${findings || `<li><p>${t("none")}</p></li>`}</ul>
  `;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function run(url) {
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error("bad status");
  render(await res.json());
}

function initChips() {
  const root = document.getElementById("chips");
  root.innerHTML = "";
  EXAMPLES.forEach((ex) => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = ex.label;
    b.addEventListener("click", () => {
      document.getElementById("url").value = ex.url;
      run(ex.url);
    });
    root.appendChild(b);
  });
}

document.querySelectorAll(".lang button").forEach((b) => {
  b.addEventListener("click", () => {
    lang = b.dataset.lang;
    applyLang();
  });
});

document.getElementById("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("url").value.trim();
  if (!url) return;
  try {
    await run(url);
  } catch {
    const box = document.getElementById("result");
    box.classList.remove("hidden");
    box.textContent = t("error");
  }
});

applyLang();
initChips();

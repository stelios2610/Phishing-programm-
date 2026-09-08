const I18N = {
  el: {
    hero: "Έλεγχος phishing για Microsoft και τα πάντα",
    lede: "Επικολλήστε URL. Ελέγχεται το domain και κατεβαίνει μόνο το HTML (χωρίς login, χωρίς JavaScript) για φόρμες κωδικού και ψεύτικα brands.",
    label: "URL",
    analyze: "Ανάλυση",
    hint: "Enter για ανάλυση. Δοκιμάστε τα παραδείγματα παρακάτω.",
    examples: "Παραδείγματα",
    c1t: "Microsoft 365 / Outlook",
    c1: "Επίσημα: microsoft.com, microsoftonline.com, office.com, outlook.com, live.com, azure.com. Οτιδήποτε άλλο με «microsoft» στο subdomain είναι απομίμηση.",
    c2t: "Τράπεζες & gov.gr",
    c2: "Καλύπτει NBG, Eurobank, Πειραιώς, Alpha, gov.gr / AADE, PayPal, Visa, Revolut και διεθνείς τράπεζες.",
    c3t: "Διαβάζει τη σελίδα, δεν συνδέεται",
    c3: "Γίνεται σύντομο GET του HTML. Δεν στέλνονται κωδικοί και δεν εκτελείται JS. Kits που εμφανίζουν τη φόρμα μόνο με JavaScript μπορεί να ξεφύγουν.",
    footer: "PhishGuard — αμυντικό εργαλείο. Αν αμφιβάλλετε, μην συνδεθείτε.",
    risk: "Κίνδυνος",
    official: "Επίσημο brand",
    looks: "Μοιάζει με",
    findings: "Ευρήματα",
    none: "Κανένα εύρημα.",
    error: "Η ανάλυση απέτυχε.",
  },
  en: {
    hero: "Phishing checks for Microsoft and everything else",
    lede: "Paste a URL. We inspect the domain and download HTML only (no login, no JavaScript) to catch password forms and fake brand pages.",
    label: "URL",
    analyze: "Analyze",
    hint: "Press Enter to analyze. Try the examples below.",
    examples: "Examples",
    c1t: "Microsoft 365 / Outlook",
    c1: "Official: microsoft.com, microsoftonline.com, office.com, outlook.com, live.com, azure.com. Anything else with “microsoft” as a subdomain is impersonation.",
    c2t: "Banks & gov.gr",
    c2: "Covers NBG, Eurobank, Piraeus, Alpha, gov.gr / AADE, PayPal, Visa, Revolut, and major international banks.",
    c3t: "Reads the page, does not sign in",
    c3: "A short GET of the HTML. No passwords are sent and no JS runs. Kits that paint the form only with JavaScript can still slip through.",
    footer: "PhishGuard — defensive tool. If you doubt it, do not sign in.",
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

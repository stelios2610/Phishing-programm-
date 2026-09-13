/* PhishGuard URL + HTML heuristics (mirrors phishguard/ Python engine). */
(function (global) {
  const C = global.PHISHGUARD_CATALOG || {};
  const BRANDS = C.brands || [];
  const USER_CONTENT = C.user_content || [];
  const SHORTENERS = new Set(C.shorteners || []);
  const SUSPICIOUS_TLDS = new Set(C.suspicious_tlds || []);
  const CRED_KEYS = C.credential_keywords || [];
  const LURE_PHRASES = C.lure_phrases || [];
  const CLOUD_SHARE = C.cloud_share || [];
  const HOST_CRED = C.host_cred || [];
  const INVISIBLE = ["\u00a0", "\u200b", "\u200c", "\u200d", "\ufeff", "\u2060", "\u202f", "\u00ad", "\u180e", "\u202e", "\u202d"];
  const TWO_PART = new Set([
    "co.uk", "com.au", "co.nz", "co.jp", "com.br", "com.gr", "com.tr", "co.in",
    "com.mx", "co.za", "com.cn", "gov.uk", "ac.uk", "org.uk", "net.au", "gov.gr", "com.cy",
  ]);
  const VERDICT_EL = {
    official: "Επίσημο",
    likely_safe: "Πιθανώς ασφαλές",
    suspicious: "Ύποπτο",
    phishing: "Phishing",
    dangerous: "Επικίνδυνο",
    invalid: "Άκυρο",
  };

  function hostMatches(host, suffix) {
    host = (host || "").toLowerCase().replace(/\.$/, "");
    suffix = (suffix || "").toLowerCase().replace(/\.$/, "");
    return host === suffix || host.endsWith("." + suffix);
  }
  function isUserContent(host) {
    return USER_CONTENT.some((s) => hostMatches(host, s));
  }
  function officialBrand(host) {
    if (!host || isUserContent(host)) return null;
    for (const b of BRANDS) {
      if ((b.domains || []).some((d) => hostMatches(host, d))) return b;
    }
    return null;
  }
  function isCloudShare(host) {
    return CLOUD_SHARE.some((d) => hostMatches(host, d));
  }
  function fold(s) {
    s = String(s || "").toLowerCase();
    try { s = s.normalize("NFKC"); } catch (_) {}
    return s;
  }
  function compact(s) {
    return fold(s).replace(/[^a-z0-9α-ωάέήίόύώ]/gi, "");
  }
  function fullyUnquote(s) {
    let prev = String(s || "").replace(/\+/g, " ");
    for (let i = 0; i < 4; i++) {
      let nxt = prev;
      try { nxt = decodeURIComponent(prev); } catch (_) {}
      nxt = nxt.replace(/&amp;/g, "&").replace(/&nbsp;/g, "\u00a0");
      if (nxt === prev) break;
      prev = nxt;
    }
    return prev;
  }
  function filenameFromPath(path) {
    if (!path) return "";
    const parts = path.replace(/\/+$/, "").split("/");
    return parts[parts.length - 1] || "";
  }
  function normalizeForMatch(s) {
    let t = String(s || "");
    try { t = t.normalize("NFKC"); } catch (_) {}
    for (const ch of INVISIBLE) t = t.split(ch).join(" ");
    t = t.replace(/ς/g, "σ").toLowerCase();
    return t.replace(/\s+/g, " ");
  }
  function lureHits(text) {
    const norm = normalizeForMatch(text);
    return LURE_PHRASES.filter((p) => norm.includes(normalizeForMatch(p)));
  }
  function hasInvisible(text) {
    const s = String(text || "");
    return INVISIBLE.some((ch) => s.includes(ch));
  }
  function sentenceFilename(filename) {
    if (!filename) return false;
    const stem = filename.includes(".") ? filename.slice(0, filename.lastIndexOf(".")) : filename;
    if (stem.length < 35) return false;
    const spaces = (stem.match(/ |\u00a0/g) || []).length;
    const punct = (stem.match(/[.!?;:]/g) || []).length;
    const low = stem.toLowerCase();
    return spaces >= 5 && (punct >= 1 || low.includes("κλικ") || low.includes("click"));
  }
  function dangerousShareExt(filename) {
    if (!filename.includes(".")) return "";
    const ext = filename.split(".").pop().toLowerCase();
    return ["html", "htm", "xhtml", "js", "vbs", "lnk"].includes(ext) ? ext : "";
  }
  function unwrap(url) {
    try {
      const u = new URL(ensureScheme(url));
      const host = (u.hostname || "").toLowerCase();
      if (host.endsWith("safelinks.protection.outlook.com") || host.endsWith("linkprotect.cudasvc.com")) {
        const inner = u.searchParams.get("url");
        if (inner) return { url: fullyUnquote(inner), via: host };
      }
      if (host.endsWith("urldefense.proofpoint.com")) {
        let inner = u.searchParams.get("u") || "";
        if (inner) {
          inner = inner.replace(/-3A/g, ":").replace(/-2F/g, "/").replace(/_/g, "/");
          return { url: inner, via: host };
        }
      }
    } catch (_) {}
    return { url, via: "" };
  }
  function ensureScheme(raw) {
    raw = String(raw || "").trim();
    const low = raw.toLowerCase();
    if (low.startsWith("javascript:") || low.startsWith("data:") || low.startsWith("vbscript:") || low.startsWith("file:")) return raw;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw;
    if (raw.startsWith("//")) return "https:" + raw;
    return "https://" + raw;
  }
  function etldPlusOne(host) {
    const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
    if (!labels.length) return { etld: "", tld: "" };
    const tld = labels[labels.length - 1];
    if (labels.length === 1) return { etld: host, tld };
    const lastTwo = labels.slice(-2).join(".");
    if (TWO_PART.has(lastTwo) && labels.length >= 3) return { etld: labels.slice(-3).join("."), tld: lastTwo };
    return { etld: lastTwo, tld };
  }
  function isIp(host) {
    const h = host.replace(/^\[|\]$/g, "");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
    if (/^[0-9a-f:]+$/i.test(h) && h.includes(":")) return true;
    if (/^0x[0-9a-f]+$/i.test(h)) return true;
    if (/^\d+$/.test(h) && h.length <= 10) return true;
    return false;
  }
  function levenshtein(a, b) {
    const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) {
        cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1])));
      }
      for (let j = 0; j <= b.length; j++) prev[j] = cur[j];
    }
    return prev[b.length];
  }
  function isTypoOf(candidate, brand) {
    if (candidate === brand) return true;
    if (Math.abs(candidate.length - brand.length) > 2) return false;
    const dist = levenshtein(candidate, brand);
    if (brand.length <= 4) return dist === 0;
    if (brand.length <= 6) return dist <= 1;
    return dist <= 2;
  }
  function deleet(s) {
    return s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b");
  }
  function shannon(s) {
    if (!s) return 0;
    const freq = {};
    for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
    const n = s.length;
    let e = 0;
    for (const c of Object.values(freq)) e -= (c / n) * Math.log2(c / n);
    return e;
  }
  function parseUrl(raw) {
    const original = String(raw || "").trim();
    if (!original) throw new Error("empty URL");
    let working = original.replace(/^hxxps:/i, "https:").replace(/^hxxp:/i, "http:").replace(/^["'<>]+|["'<>]+$/g, "");
    const uw = unwrap(working);
    const notes = [];
    if (uw.via) {
      notes.push("unwrapped:" + uw.via);
      working = uw.url;
    }
    const lowered = working.toLowerCase();
    if (lowered.startsWith("javascript:") || lowered.startsWith("data:") || lowered.startsWith("vbscript:")) {
      const scheme = lowered.split(":")[0];
      return { original, normalized: working, scheme, userinfo: null, host: "", port: null, path: working, query: "", fragment: "", host_unicode: "", is_ip: false, labels: [], etld_plus_one: "", tld: "", punycode_used: false, decode_notes: ["dangerous-scheme"] };
    }
    const withScheme = ensureScheme(working);
    const u = new URL(withScheme);
    let userinfo = null;
    if (u.username || u.password) {
      userinfo = u.username + (u.password ? ":" + u.password : "");
      notes.push("userinfo");
    }
    let host = (u.hostname || "").replace(/\.$/, "").toLowerCase();
    const puny = host.includes("xn--");
    const unicodeHost = host;
    const ip = isIp(host);
    const labels = ip ? [] : unicodeHost.split(".").filter(Boolean);
    const { etld, tld } = ip ? { etld: "", tld: "" } : etldPlusOne(unicodeHost);
    const path = fullyUnquote(u.pathname || "");
    const query = u.search.startsWith("?") ? u.search.slice(1) : u.search;
    let normalized = u.protocol + "//" + (unicodeHost || host);
    if (u.port) normalized += ":" + u.port;
    normalized += u.pathname || "";
    if (query) normalized += "?" + query;
    return {
      original, normalized, scheme: (u.protocol || "").replace(":", "").toLowerCase(),
      userinfo, host, port: u.port ? Number(u.port) : null, path, query, fragment: u.hash.slice(1),
      host_unicode: unicodeHost, is_ip: ip, labels, etld_plus_one: etld, tld, punycode_used: puny, decode_notes: notes,
    };
  }
  function finding(code, title, title_el, detail, detail_el, severity, score) {
    return { code, title, title_el, detail, detail_el, severity, score };
  }
  function typosquatLabel(label) {
    const folded = fold(label);
    const parts = folded.split(/[-_]/).filter(Boolean);
    const candidates = new Set([folded, folded.replace(/-/g, ""), deleet(folded.replace(/-/g, "")), ...parts, ...parts.map(deleet)]);
    const hits = [];
    for (const brand of BRANDS) {
      for (const alias of brand.aliases || []) {
        const aliasF = fold(alias);
        if (aliasF.length < 5) continue;
        let matched = false;
        for (const cand of candidates) {
          if (cand === aliasF || isTypoOf(cand, aliasF)) { matched = true; break; }
          if (cand.startsWith(aliasF) && cand.length - aliasF.length <= 8) {
            const suffix = cand.slice(aliasF.length);
            if (["login", "secure", "verify", "support", "online", "onlinecom", "com", "365", "account"].includes(suffix)) {
              matched = true; break;
            }
          }
        }
        if (matched) { hits.push({ brand, alias }); break; }
      }
    }
    return hits;
  }
  function findingsFor(parsed) {
    const findings = [];
    let impersonated = null;
    const host = parsed.host_unicode || parsed.host;
    const hostL = host.toLowerCase();
    const foldedHost = fold(hostL);
    const etld = (parsed.etld_plus_one || "").toLowerCase();
    const sld = etld ? etld.split(".")[0] : (parsed.labels[0] || "");

    if (["javascript", "data", "vbscript"].includes(parsed.scheme)) {
      findings.push(finding("dangerous_scheme", "Dangerous URL scheme", "Επικίνδυνο σχήμα URL",
        `Scheme '${parsed.scheme}:' can execute code in the browser.`,
        `Το σχήμα '${parsed.scheme}:' μπορεί να εκτελέσει κώδικα στον browser.`, "critical", 100));
      return { findings, impersonated, official: null, signals: { scheme: parsed.scheme } };
    }
    if (parsed.scheme === "file") {
      findings.push(finding("file_scheme", "Local file URL", "Τοπικό αρχείο",
        "file:// links are not web login pages.", "Οι σύνδεσμοι file:// δεν είναι σελίδες σύνδεσης στο διαδίκτυο.", "high", 70));
    }
    const official = hostL && !parsed.is_ip ? officialBrand(hostL) : null;

    if (parsed.userinfo) {
      findings.push(finding("userinfo_at", "Credentials / @ trick in host", "Κόλπο @ στο host",
        "The '@' hides the real destination. Browsers use the host after '@'.",
        "Το '@' κρύβει τον πραγματικό προορισμό. Ο browser χρησιμοποιεί το host μετά το '@'.", "critical", 90));
      const ui = fold(parsed.userinfo);
      for (const brand of BRANDS) {
        let hit = false;
        for (const alias of brand.aliases || []) {
          if (alias.length >= 5 && fold(alias) && ui.includes(fold(alias))) {
            impersonated = impersonated || brand.name;
            findings.push(finding("brand_in_userinfo", `${brand.name} name before @`, `Όνομα ${brand.name} πριν το @`,
              "The brand appears only in the fake userinfo prefix, not on the real host.",
              "Το brand εμφανίζεται μόνο στο ψεύτικο πρόθεμα πριν το @, όχι στο πραγματικό host.", "critical", 88));
            hit = true; break;
          }
        }
        if (hit) break;
      }
    }
    if (parsed.is_ip) {
      findings.push(finding("ip_host", "IP address instead of domain", "Διεύθυνση IP αντί για domain",
        "Login pages for major brands never use a raw IP as the host.",
        "Οι σελίδες σύνδεσης μεγάλων εταιρειών δεν χρησιμοποιούν raw IP ως host.", "high", 75));
    }
    if (parsed.punycode_used) {
      findings.push(finding("homograph", "Homograph / IDN lookalike", "Homograph / IDN απομίμηση",
        `Decoded host: ${parsed.host_unicode}. Characters may look like Latin letters.`,
        `Αποκωδικοποιημένο host: ${parsed.host_unicode}. Χαρακτήρες μπορεί να μοιάζουν με λατινικά.`, "critical", 85));
    }
    if (hasInvisible(parsed.original) || hasInvisible(host)) {
      findings.push(finding("invisible_chars", "Invisible / RTL override characters", "Αόρατοι χαρακτήρες / RTL override",
        "Zero-width or direction-override characters are a classic phishing obfuscation.",
        "Αόρατοι χαρακτήρες ή αλλαγή κατεύθυνσης κειμένου είναι κλασική τεχνική phishing.", "critical", 90));
    }
    if (SUSPICIOUS_TLDS.has(parsed.tld) && !official) {
      findings.push(finding("suspicious_tld", "Suspicious top-level domain", "Ύποπτο TLD",
        `TLD '.${parsed.tld}' is frequently abused in phishing kits.`,
        `Το TLD '.${parsed.tld}' χρησιμοποιείται συχνά σε phishing kits.`, "medium", 18));
    }
    if (SHORTENERS.has(hostL) || [...SHORTENERS].some((h) => hostMatches(hostL, h))) {
      const aka = hostMatches(hostL, "aka.ms");
      findings.push(finding("shortener", "URL shortener hides destination", "Shortener κρύβει τον προορισμό",
        "Short links conceal the real host. Expand them before trusting.",
        "Τα short links κρύβουν τον πραγματικό host. Ανοίξτε τα μόνο αφού επεκταθούν.", aka ? "low" : "medium", aka ? 12 : 28));
    }
    if (isUserContent(hostL)) {
      findings.push(finding("user_content_host", "Free / user-content hosting", "Δωρεάν / user-content hosting",
        "Anyone can publish a site on this host. Fake login pages are often hosted here.",
        "Οποιοσδήποτε μπορεί να δημοσιεύσει σελίδα εδώ. Οι ψεύτικες σελίδες login συχνά φιλοξενούνται εδώ.", "high", 48));
    }

    const compactHost = compact(foldedHost);
    const brandHits = [];
    for (const brand of BRANDS) {
      for (const alias of brand.aliases || []) {
        const aliasF = fold(alias);
        if (aliasF.length < 5) continue;
        const labels = parsed.labels.map((l) => fold(l));
        const compactLabels = labels.map((l) => l.replace(/-/g, ""));
        if (labels.includes(aliasF) || compactLabels.includes(aliasF)) { brandHits.push({ brand, alias, kind: "host" }); break; }
        if (aliasF.length >= 6 && (compactHost.includes(aliasF) || foldedHost.includes(aliasF))) {
          brandHits.push({ brand, alias, kind: "host" }); break;
        }
      }
    }
    if (sld) {
      for (const { brand, alias } of typosquatLabel(sld)) {
        if (official && official.name === brand.name) continue;
        brandHits.push({ brand, alias, kind: "typosquat" });
      }
    }
    const seen = new Set();
    const unique = [];
    for (const h of brandHits) {
      if (seen.has(h.brand.name)) continue;
      seen.add(h.brand.name);
      unique.push(h);
    }
    for (const { brand, alias, kind } of unique) {
      if (official && official.name === brand.name) continue;
      impersonated = brand.name;
      if (kind === "typosquat") {
        findings.push(finding("typosquat", `Typosquat of ${brand.name}`, `Typosquat της ${brand.name}`,
          `Domain label looks like '${alias}' (${brand.name}) but is not an official domain.`,
          `Το domain μοιάζει με '${alias}' (${brand.name}) αλλά δεν είναι επίσημο.`, "critical", 88));
      } else if (parsed.is_ip) {
        findings.push(finding("brand_on_ip", `${brand.name} mentioned on an IP host`, `${brand.name} σε IP host`,
          `Brand token '${alias}' on a raw IP is phishing.`, `Το όνομα '${alias}' σε raw IP είναι phishing.`, "critical", 92));
      } else if (isUserContent(hostL)) {
        findings.push(finding("brand_on_user_host", `${brand.name} impersonation on free hosting`, `Απομίμηση ${brand.name} σε δωρεάν hosting`,
          `Token '${alias}' on a user-content host is a common kit pattern.`,
          `Το '${alias}' σε user-content host είναι κοινό μοτίβο phishing kit.`, "critical", 86));
      } else if (!(brand.domains || []).some((d) => hostMatches(hostL, d))) {
        findings.push(finding("brand_impersonation", `Impersonates ${brand.name}`, `Απομίμηση ${brand.name}`,
          `Uses '${alias}' but the registrable domain is '${etld || host}', not an official ${brand.name} property.`,
          `Χρησιμοποιεί '${alias}' αλλά το domain είναι '${etld || host}', όχι επίσημη ιδιοκτησία της ${brand.name}.`, "critical", 90));
      }
    }

    const decodedPath = parsed.path;
    const filename = filenameFromPath(decodedPath);
    const pathQ = fold(decodedPath + "?" + parsed.query);
    const compactPath = compact(pathQ);
    let pathBrand = null;
    for (const brand of BRANDS) {
      for (const alias of brand.aliases || []) {
        const aliasF = fold(alias);
        if (aliasF.length >= 5 && compactPath.includes(aliasF)) {
          pathBrand = brand.name;
          if (!official || official.name !== brand.name) {
            impersonated = impersonated || brand.name;
            findings.push(finding("brand_in_path", `${brand.name} named in path/query`, `${brand.name} στο path/query`,
              "Phishing kits put the real brand in the path while the domain is unrelated.",
              "Τα kits βάζουν το πραγματικό brand στο path ενώ το domain είναι άσχετο.", "high", 55));
          }
          break;
        }
      }
      if (pathBrand) break;
    }
    const keywordHits = CRED_KEYS.filter((k) => pathQ.includes(k) || compactPath.includes(k.replace(/-/g, "")));
    if (keywordHits.length && !official) {
      findings.push(finding("credential_keywords", "Login / account keywords", "Λέξεις σύνδεσης / λογαριασμού",
        "Path or query contains: " + [...new Set(keywordHits)].slice(0, 8).join(", "),
        "Το path ή το query περιέχει: " + [...new Set(keywordHits)].slice(0, 8).join(", "), "medium", 22));
    }
    const hostCred = HOST_CRED.filter((t) => foldedHost.replace(/\./g, "-").includes(t));
    if (hostCred.length && !official) {
      const many = new Set(hostCred).size >= 2;
      findings.push(finding("host_login_tokens", "Login-style hostname", "Hostname τύπου login",
        "Host contains: " + [...new Set(hostCred)].slice(0, 8).join(", "),
        "Το host περιέχει: " + [...new Set(hostCred)].slice(0, 8).join(", "), many ? "high" : "medium", many ? 40 : 24));
    }
    const hits = lureHits(decodedPath + " " + filename);
    if (hits.length) {
      findings.push(finding("lure_filename", "Filename is a phishing instruction", "Το όνομα αρχείου είναι οδηγία phishing",
        "The file is not named like a document. It says: " + hits.slice(0, 4).join(", "),
        "Το αρχείο δεν έχει κανονικό όνομα. Λέει: " + hits.slice(0, 4).join(", "), "critical", 80));
    }
    if (sentenceFilename(filename)) {
      findings.push(finding("sentence_filename", "Whole sentence used as filename", "Ολόκληρη πρόταση ως όνομα αρχείου",
        `«${filename.slice(0, 120)}» looks like a message to the user, not a file.`,
        `«${filename.slice(0, 120)}» μοιάζει με μήνυμα προς τον χρήστη, όχι με έγγραφο.`, "high", 40));
    }
    if (hasInvisible(decodedPath) || hasInvisible(filename) || hasInvisible(parsed.original)) {
      findings.push(finding("invisible_in_path", "Hidden character in filename/path", "Κρυφός χαρακτήρας στο όνομα αρχείου",
        "NBSP or zero-width characters disguise a lure filename.",
        "NBSP ή αόρατοι χαρακτήρες κρύβουν δόλωμα στο όνομα αρχείου.", "high", 40));
    }
    const cloud = isCloudShare(hostL);
    if (cloud && (hits.length || sentenceFilename(filename))) {
      findings.push(finding("trusted_host_lure", "Real SharePoint/OneDrive, fake content", "Αληθινό SharePoint/OneDrive, ψεύτικο περιεχόμενο",
        "The domain belongs to Microsoft/Google/Dropbox. That does not make the file safe.",
        "Το domain είναι της Microsoft/Google/Dropbox. Αυτό δεν σημαίνει ότι το αρχείο είναι ασφαλές.", "critical", 70));
    }
    const ext = dangerousShareExt(filename);
    if (cloud && ext) {
      findings.push(finding("dangerous_share_ext", `.${ext} file on a cloud share`, `Αρχείο .${ext} σε cloud share`,
        "HTML/script files on OneDrive/SharePoint are a common credential-phishing kit.",
        "Τα HTML/script αρχεία σε OneDrive/SharePoint χρησιμοποιούνται για κλοπή κωδικών.", "high", 55));
    }
    if (parsed.decode_notes.some((n) => n.startsWith("unwrapped:"))) {
      findings.push(finding("unwrapped", "SafeLinks / gateway wrapper", "Ο σύνδεσμος ήταν τυλιγμένος (SafeLinks)",
        "Analyzed the inner URL, not the Outlook wrapper.", "Αναλύθηκε ο εσωτερικός σύνδεσμος, όχι το SafeLinks.", "info", 0));
    }
    if (parsed.scheme === "http" && (official || impersonated || keywordHits.length)) {
      findings.push(finding("plain_http", "Unencrypted HTTP", "HTTP χωρίς κρυπτογράφηση",
        "Login pages for major brands require HTTPS.", "Οι σελίδες σύνδεσης μεγάλων εταιρειών απαιτούν HTTPS.",
        official || impersonated ? "high" : "medium", official || impersonated ? 35 : 18));
    }
    if (parsed.port && ![80, 443, 8080, 8443].includes(parsed.port)) {
      findings.push(finding("odd_port", "Unusual port", "Ασυνήθιστο port",
        `Port ${parsed.port} is uncommon for official brand sites.`, `Το port ${parsed.port} είναι ασυνήθιστο για επίσημες σελίδες.`, "low", 12));
    }
    if (parsed.labels.length >= 5) {
      findings.push(finding("deep_subdomains", "Excessive subdomain depth", "Υπερβολικό βάθος subdomain",
        `${parsed.labels.length} labels. Deep trees are used to fake 'microsoft.com' as a prefix.`,
        `${parsed.labels.length} labels. Βαθιά δέντρα χρησιμοποιούνται για να φαίνεται 'microsoft.com' ως prefix.`, "medium", 20));
    }
    for (const brand of BRANDS) {
      let brk = false;
      for (const domain of brand.domains || []) {
        const parts = domain.split(".");
        if (parts.length < 2) continue;
        if (hostL.endsWith("." + domain)) continue;
        if (hostL.includes(domain) && !hostMatches(hostL, domain)) {
          if (hostL.startsWith(domain + ".") || ("." + hostL + ".").includes("." + domain + ".")) {
            if (!official || official.name !== brand.name) {
              impersonated = impersonated || brand.name;
              findings.push(finding("domain_as_subdomain", `Official ${brand.name} domain used as subdomain`,
                `Επίσημο domain ${brand.name} ως subdomain`,
                `'${domain}' appears inside '${host}' but the real registrable domain is '${etld}'.`,
                `Το '${domain}' εμφανίζεται μέσα στο '${host}' αλλά το πραγματικό domain είναι '${etld}'.`, "critical", 92));
              brk = true; break;
            }
          }
        }
      }
      if (brk) break;
    }
    const sldEntropy = shannon(sld);
    if (sld.length >= 16 && sldEntropy > 3.8 && !official) {
      findings.push(finding("high_entropy_domain", "Random-looking domain", "Domain που μοιάζει τυχαίο",
        `Second-level label entropy ${sldEntropy.toFixed(2)} often indicates generated phishing domains.`,
        `Εντροπία ${sldEntropy.toFixed(2)} συχνά δείχνει αυτόματα generated phishing domains.`, "low", 10));
    }
    if ((sld.match(/-/g) || []).length >= 3 && !official) {
      findings.push(finding("many_hyphens", "Many hyphens in domain", "Πολλά ενωτικά στο domain",
        "Patterns like 'microsoft-office365-login-secure.xyz' are kit defaults.",
        "Μοτίβα όπως 'microsoft-office365-login-secure.xyz' είναι defaults των kits.", "medium", 16));
    }
    if (parsed.original.length > 180) {
      findings.push(finding("very_long_url", "Very long URL", "Πολύ μεγάλο URL",
        "Long URLs bury the real host and tracking payloads.", "Τα μεγάλα URL κρύβουν το πραγματικό host.", "low", 8));
    }
    if (official && !findings.some((f) => f.severity === "critical" || f.severity === "high")) {
      findings.unshift(finding("official_domain", `Official ${official.name} domain`, `Επίσημο domain ${official.name}`,
        `Host matches known ${official.name} property '${etld || host}'. Still check the path and HTTPS.`,
        `Το host ταιριάζει με γνωστή ιδιοκτησία ${official.name} ('${etld || host}'). Ελέγξτε path και HTTPS.`, "info", 0));
    }
    return {
      findings, impersonated, official: official ? official.name : null,
      signals: { scheme: parsed.scheme, host, etld_plus_one: etld, tld: parsed.tld, is_ip: parsed.is_ip, punycode: parsed.punycode_used, userinfo: !!parsed.userinfo, official: official ? official.name : null, impersonated, sld_entropy: Math.round(sldEntropy * 1000) / 1000, label_count: parsed.labels.length },
    };
  }
  function verdict(score, findings, official) {
    const codes = new Set(findings.map((f) => f.code));
    const critical = findings.some((f) => f.severity === "critical");
    if (findings.some((f) => f.code === "dangerous_scheme")) return "dangerous";
    for (const c of ["lure_filename", "trusted_host_lure", "brand_impersonation", "typosquat", "domain_as_subdomain", "password_form", "brand_in_page", "form_exfil", "page_lure"]) {
      if (codes.has(c)) return "phishing";
    }
    if (critical || score >= 55) return "phishing";
    if (score >= 30) return "suspicious";
    if (official && score < 20) return "official";
    return "likely_safe";
  }
  function inspectHtml(html) {
    const sig = { title: "", password: false, brands: [], form_hosts: [], lures: [] };
    const h = String(html || "");
    const tm = h.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    if (tm) sig.title = tm[1].replace(/<[^>]+>/g, " ").trim();
    if (/type\s*=\s*["']?password["']?/i.test(h) || /name\s*=\s*["']?(passwd|password|pwd)["']?/i.test(h)) sig.password = true;
    const formRe = /<form[^>]*action\s*=\s*["']([^"']+)["'][^>]*>/gi;
    let m;
    while ((m = formRe.exec(h))) {
      try {
        const host = new URL(m[1], "https://placeholder.invalid").hostname.toLowerCase();
        if (host && host !== "placeholder.invalid") sig.form_hosts.push(host);
      } catch (_) {}
    }
    const blob = fold((sig.title + " " + h.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ")).slice(0, 20000));
    const compactBlob = compact(blob);
    for (const brand of BRANDS) {
      for (const alias of brand.aliases || []) {
        const a = fold(alias);
        if (a.length >= 5 && compactBlob.includes(a.replace(/[^a-z0-9α-ω]/gi, ""))) {
          sig.brands.push(brand.name);
          break;
        }
      }
    }
    sig.lures = lureHits(blob);
    return sig;
  }
  function pageFindings(parsed, officialName, html, err) {
    const out = [];
    if (!["http", "https"].includes(parsed.scheme) || !(parsed.host_unicode || parsed.host)) return out;
    if (officialName) return out;
    if (err && String(err).startsWith("ssl")) {
      out.push(finding("tls_error", "TLS / certificate problem", "Πρόβλημα πιστοποιητικού TLS",
        "The page failed HTTPS checks. Fake sites often use broken certificates.",
        "Η σελίδα απέτυχε στον έλεγχο HTTPS. Οι ψεύτικες σελίδες συχνά έχουν λάθος πιστοποιητικό.", "high", 45));
    }
    if (!html) return out;
    const sig = inspectHtml(html);
    const host = (parsed.host_unicode || parsed.host).toLowerCase();
    if (sig.password) {
      out.push(finding("password_form", "Login form on an unofficial site", "Φόρμα κωδικού σε μη επίσημο site",
        "The page asks for a password but the domain is not a known official brand site.",
        "Η σελίδα ζητάει κωδικό αλλά το domain δεν είναι επίσημο.", "critical", 90));
    }
    if (sig.brands.length) {
      const brand = sig.brands[0];
      out.push(finding("brand_in_page", `Page pretends to be ${brand}`, `Η σελίδα παριστάνει την ${brand}`,
        `HTML/title mentions ${brand} while the host is '${host}'.`,
        `Το HTML/τίτλος αναφέρει ${brand} ενώ το host είναι '${host}'.`, "critical", 92));
    }
    if (sig.lures.length) {
      out.push(finding("page_lure", "Phishing lure text in the page", "Κείμενο-δόλωμα στη σελίδα",
        "Found: " + sig.lures.slice(0, 4).join(", "), "Βρέθηκε: " + sig.lures.slice(0, 4).join(", "), "critical", 80));
    }
    for (const fh of sig.form_hosts) {
      if (fh && fh !== host && !host.endsWith("." + fh) && !fh.endsWith("." + host.split(".").slice(-2).join("."))) {
        out.push(finding("form_exfil", "Form submits to another domain", "Η φόρμα στέλνει σε άλλο domain",
          `Form action host is '${fh}', page host is '${host}'.`,
          `Το action της φόρμας πάει στο '${fh}', η σελίδα είναι '${host}'.`, "critical", 85));
        break;
      }
    }
    return out;
  }
  function finalize(raw, parsed, findings, impersonated, officialName, signals) {
    const uniq = [];
    const seen = new Set();
    for (const f of findings) {
      const key = f.code + f.title;
      if (seen.has(key)) continue;
      seen.add(key);
      uniq.push(f);
    }
    let score = Math.min(100, uniq.reduce((a, f) => a + f.score, 0));
    if (uniq.some((f) => ["lure_filename", "trusted_host_lure", "href_mismatch", "password_form", "brand_in_page", "page_lure", "form_exfil"].includes(f.code))) {
      score = Math.min(100, Math.max(score, 85));
    }
    const hi = uniq.filter((f) => f.severity === "high" || f.severity === "critical").length;
    if (hi >= 2) score = Math.min(100, Math.max(score, 70));
    if (hi >= 3) score = Math.min(100, Math.max(score, 85));
    const v = verdict(score, uniq, officialName);
    return {
      url: raw, normalized: parsed.normalized, host: parsed.host, host_unicode: parsed.host_unicode,
      verdict: v, verdict_el: VERDICT_EL[v] || v, score, risk_percent: score,
      impersonated_brand: impersonated, official_brand: officialName, findings: uniq, signals,
    };
  }
  function looksLikeHtmlOrEmail(text) {
    const t = text.trimStart().slice(0, 4000).toLowerCase();
    if (t.includes("<a ") || t.includes("<html") || t.includes("href=")) return true;
    if (t.startsWith("from:") || t.includes("\nsubject:") || t.startsWith("mime-version")) return true;
    if ((text.match(/https?:\/\//g) || []).length >= 2 && text.includes("\n")) return true;
    return false;
  }
  function analyzeBlob(text) {
    const extra = [];
    const re = /<a\s[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    const hrefs = [];
    while ((m = re.exec(text))) {
      const href = m[1].trim();
      const shown = m[2].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      hrefs.push(href);
      if (!href || href.startsWith("#") || href.toLowerCase().startsWith("mailto:")) continue;
      if (shown.includes("://") || shown.toLowerCase().startsWith("www.")) {
        extra.push(finding("href_mismatch", "Link text does not match destination", "Το κείμενο του συνδέσμου δεν ταιριάζει με τον προορισμό",
          `Shown as «${shown.slice(0, 80)}» but goes to «${href.slice(0, 120)}».`,
          `Φαίνεται «${shown.slice(0, 80)}» αλλά πάει στο «${href.slice(0, 120)}».`, "critical", 80));
      }
    }
    const urls = (text.match(/https?:\/\/[^\s<>"']+/gi) || []).concat(hrefs.filter((h) => /^https?:/i.test(h)));
    const uniqUrls = [];
    const seenU = new Set();
    for (let u of urls) {
      u = u.replace(/[).,;\]]+$/, "");
      if (!seenU.has(u)) { seenU.add(u); uniqUrls.push(u); }
    }
    if (!uniqUrls.length && extra.length) {
      const dummy = { original: text.slice(0, 200), normalized: "", host: "", host_unicode: "", scheme: "https", userinfo: null, port: null, path: "", query: "", fragment: "", is_ip: false, labels: [], etld_plus_one: "", tld: "", punycode_used: false, decode_notes: [] };
      return finalize(text.slice(0, 200), dummy, extra, null, null, { blob: true });
    }
    if (!uniqUrls.length) return analyzeParsed(text, parseUrl(text.split(/\s+/)[0] || text), null);
    let best = analyzeParsed(uniqUrls[0], parseUrl(uniqUrls[0]), null);
    const all = best.findings.concat(extra);
    for (const u of uniqUrls.slice(1)) {
      const other = analyzeParsed(u, parseUrl(u), null);
      if (other.score > best.score) best = other;
      all.push(...other.findings);
    }
    return finalize(best.url, { ...best, normalized: best.normalized, host: best.host, host_unicode: best.host_unicode, scheme: "https", userinfo: null, port: null, path: "", query: "", fragment: "", is_ip: false, labels: [], etld_plus_one: "", tld: "", punycode_used: false, decode_notes: [] }, all, best.impersonated_brand, best.official_brand, { blob: true, url_count: uniqUrls.length });
  }
  function analyzeParsed(raw, parsed, page) {
    const { findings, impersonated, official, signals } = findingsFor(parsed);
    let imp = impersonated;
    if (page) {
      const extra = pageFindings(parsed, official, page.html, page.error);
      findings.push(...extra);
      for (const f of extra) {
        if (f.code === "brand_in_page") {
          imp = imp || f.title.replace("Page pretends to be ", "").replace("Η σελίδα παριστάνει την ", "");
          break;
        }
      }
    }
    return finalize(raw, parsed, findings, imp, official, signals);
  }
  function analyze(url, page) {
    const raw = String(url || "").trim();
    if (!raw) {
      return { url: "", normalized: "", host: "", host_unicode: "", verdict: "invalid", verdict_el: VERDICT_EL.invalid, score: 0, risk_percent: 0, impersonated_brand: null, official_brand: null, findings: [finding("empty", "Empty input", "Κενή είσοδος", "Paste a URL to analyze.", "Επικολλήστε ένα URL για ανάλυση.", "info", 0)], signals: {} };
    }
    const first = raw.split(/\s+/)[0] || raw;
    if (looksLikeHtmlOrEmail(raw) && !/^(https?|hxxps?):\/\//i.test(first)) {
      return analyzeBlob(raw);
    }
    try {
      const parsed = parseUrl(raw);
      return analyzeParsed(raw, parsed, page || null);
    } catch (exc) {
      return { url: raw, normalized: "", host: "", host_unicode: "", verdict: "invalid", verdict_el: VERDICT_EL.invalid, score: 50, risk_percent: 50, impersonated_brand: null, official_brand: null, findings: [finding("parse_error", "Could not parse URL", "Αδυναμία ανάλυσης URL", String(exc), String(exc), "high", 50)], signals: { error: String(exc) } };
    }
  }

  global.PhishGuard = { analyze, parseUrl, inspectHtml };
})(typeof window !== "undefined" ? window : globalThis);

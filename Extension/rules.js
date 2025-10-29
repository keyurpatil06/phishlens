window.PG = window.PG || {};

// Simple Levenshtein for typosquatting checks
function editDistance(a, b) {
  a = (a || "").toLowerCase();
  b = (b || "").toLowerCase();
  const dp = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}

const BRAND_DOMAINS = [
  "google.com","microsoft.com","apple.com","amazon.com","paypal.com",
  "netflix.com","adobe.com","github.com","zoom.us","dropbox.com","icloud.com",
];

const SUSPICIOUS_TLDS = ["zip","mov","lol","top","gq","cf","tk","work","click","link"];
const URGENCY_WORDS = [
  "urgent","immediately","verify your account","password expired","final notice",
  "account suspended","update billing","confirm identity","wire transfer","gift card"
];
const CONTROL_CHAR_RE = /[\u202E\u202A-\u202E\u2066-\u2069]/; // bidi controls
const PUNYCODE_RE = /(^|\.)xn--/;

function domainFromEmail(addr) {
  const m = (addr || "").match(/@([^>]+)>?$|@(.+)$/);
  return m ? (m[1] || m[2]).toLowerCase().trim() : "";
}

function hostnameFromUrl(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function looksTyposquat(host) {
  host = (host || "").toLowerCase();
  return BRAND_DOMAINS.some(b => editDistance(host, b) === 1 || host.endsWith("." + b));
}

function linkTextHrefMismatch(aEl) {
  const text = (aEl.textContent || "").trim().toLowerCase();
  const host = hostnameFromUrl(aEl.href);
  return text && host && text.includes(".") && !text.includes(host);
}

function scoreEmail({ fromName, fromEmail, subject, bodyText, links }) {
  let score = 0; const reasons = [];

  const fromDomain = domainFromEmail(fromEmail);
  if (!fromDomain) { score += 10; reasons.push("Sender address missing or malformed."); }

  if (fromName && fromDomain && fromName.toLowerCase().includes("support")) {
    if (!BRAND_DOMAINS.some(b => fromDomain.endsWith(b))) {
      score += 8; reasons.push("Display name suggests support, domain not recognized.");
    }
  }

  if (PUNYCODE_RE.test(fromDomain)) { score += 15; reasons.push("Punycode domain detected."); }
  if (CONTROL_CHAR_RE.test(bodyText || "")) { score += 12; reasons.push("Hidden unicode control characters found."); }

  const text = `${subject || ""}\n${bodyText || ""}`.toLowerCase();
  const urgencyHits = URGENCY_WORDS.filter(w => text.includes(w)).length;
  if (urgencyHits) { score += 5 + urgencyHits * 2; reasons.push("Urgent/pressure wording detected."); }

  // Links analysis
  const arr = Array.isArray(links) ? links : [];
  let sawLinks = false;
  for (const L of arr) {
    const host = hostnameFromUrl(L.href);
    if (!host) continue;
    sawLinks = true;

    if (SUSPICIOUS_TLDS.some(t => host.endsWith("." + t))) {
      score += 6; reasons.push(`Suspicious TLD: ${host}`);
    }
    if (looksTyposquat(host)) {
      score += 10; reasons.push(`Domain looks like a brand typosquat: ${host}`);
    }
    if (L.text && L.text !== L.href && linkTextHrefMismatch({ textContent: L.text, href: L.href })) {
      score += 6; reasons.push("Link text does not match destination.");
    }
    if (L.isDataUrl) { score += 4; reasons.push("Data URI link present."); }
  }
  if (!sawLinks) reasons.push("No links detected.");

  const level = score >= 25 ? "high" : score >= 12 ? "medium" : "low";
  return { score, level, reasons: Array.from(new Set(reasons)).slice(0, 8) };
}

// expose
window.PG.scoreEmail = scoreEmail;

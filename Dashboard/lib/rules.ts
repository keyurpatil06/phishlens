// --- Constants & Wordlists ---

// 1. High-Risk TLDs: Often used for cheap/disposable phishing sites
const SUSPICIOUS_TLDS = new Set([
  ".xyz",
  ".top",
  ".club",
  ".online",
  ".life",
  ".work",
  ".live",
  ".shop",
  ".fun",
  ".pro",
  ".kim",
  ".click",
  ".gq",
  ".cf",
  ".ga",
  ".ml",
  ".tk",
  ".zip",
  ".mov",
  ".rar",
  ".exe",
  ".ru",
  ".cn",
  ".ir",
  ".kp",
]);

// 2. Sensitive Keywords: Patterns found in the URL path/query
const RISK_KEYWORDS = [
  "login",
  "signin",
  "log-in",
  "sign-in",
  "verify",
  "verification",
  "auth",
  "authenticate",
  "password",
  "credential",
  "account",
  "user",
  "update",
  "confirm",
  "suspend",
  "restriction",
  "lock",
  "expires",
  "immediate",
  "action",
  "required",
  "secure",
  "safe",
  "service",
  "wallet",
  "bank",
  "pay",
  "payment",
  "invoice",
  "statement",
  "billing",
  "crypto",
  "coin",
  "token",
  "refund",
  "bonus",
  "prize",
];

// 3. Brand Imitation: Common targets (flag if found in subdomain/path but not main domain)
const TARGET_BRANDS = [
  "paypal",
  "google",
  "microsoft",
  "apple",
  "facebook",
  "instagram",
  "whatsapp",
  "netflix",
  "amazon",
  "chase",
  "wells",
  "fargo",
  "citi",
  "binance",
  "coinbase",
];

export type RuleResult = {
  riskScore: number;
  flags: string[];
  isSuspicious: boolean;
};

// --- Helper Functions ---

function isIpAddress(hostname: string): boolean {
  // IPv4 check
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return true;
  // IPv6 check (simplified)
  if (hostname.includes(":") && hostname.includes("[")) return true;
  return false;
}

function getDomainFromHostname(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length > 2) {
    return parts.slice(-2).join(".");
  }
  return hostname;
}

// --- Main Logic ---

export function checkUrlRules(urlStr: string): RuleResult {
  const flags: string[] = [];
  let score = 0;

  try {
    const urlObj = new URL(urlStr);
    const hostname = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname.toLowerCase();
    const search = urlObj.search.toLowerCase();
    const fullPath = pathname + search;

    // RULE 1: IP Address Usage
    if (isIpAddress(hostname)) {
      score += 75; // Very high risk
      flags.push("Host is a raw IP address (obfuscates identity)");
    }

    // RULE 2: Suspicious TLD
    const tldMatch = hostname.match(/\.[a-z]+$/);
    if (tldMatch) {
      const tld = tldMatch[0];
      if (SUSPICIOUS_TLDS.has(tld)) {
        score += 25;
        flags.push(`Uses high-risk Top Level Domain: ${tld}`);
      }
    }

    // RULE 3: Punycode / Homograph Attacks
    if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
      score += 40;
      flags.push("Uses Punycode (possible homograph/spoofing attack)");
    }

    // RULE 4: Deep Subdomains (e.g. paypal.com.account-update.badsite.com)
    // Counting dots can indicate nesting complexity
    const dotCount = (hostname.match(/\./g) || []).length;
    if (dotCount > 3 && !isIpAddress(hostname)) {
      score += 15;
      flags.push("Excessive subdomains (potential spoofing structure)");
    }

    // RULE 5: Credential Stuffing / Obfuscation
    if (urlStr.includes("@")) {
      score += 50;
      flags.push("Contains '@' symbol (credential embedding)");
    }

    // RULE 6: Double HTTP (Open Redirects)
    if (urlStr.indexOf("http", 4) > -1) {
      // 4 skips the initial protocol
      score += 20;
      flags.push("Contains multiple 'http' schemas (possible open redirect)");
    }

    // RULE 7: Sensitive Keywords
    const foundKeywords = RISK_KEYWORDS.filter(
      (k) => hostname.includes(k) || fullPath.includes(k)
    );
    if (foundKeywords.length > 0) {
      const uniqueKw = [...new Set(foundKeywords)];
      score += uniqueKw.length * 10; // 10 points per keyword
      flags.push(
        `Suspicious keywords found: ${uniqueKw.slice(0, 3).join(", ")}`
      );
    }

    // RULE 8: Brand Impersonation
    const mainDomain = getDomainFromHostname(hostname);
    for (const brand of TARGET_BRANDS) {
      // If URL contains brand...
      if (urlStr.toLowerCase().includes(brand)) {
        // ...but the main domain is NOT the brand
        if (!mainDomain.includes(brand)) {
          score += 30;
          flags.push(`Potential impersonation of: ${brand}`);
        }
      }
    }

    // Clamp score 0-100
    score = Math.min(Math.max(score, 0), 100);
  } catch (error) {
    flags.push("Invalid URL format");
    score = 10;
  }

  return {
    riskScore: score,
    flags,
    isSuspicious: score >= 40,
  };
}

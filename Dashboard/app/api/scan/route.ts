// app/api/scan/route.ts
import { NextResponse } from "next/server";
import { getThreatInfo, ThreatInfo } from "@/lib/threatInfo";

type VTStats = {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
};

type RuleBasedCheck = {
  score: number;
  level: "low" | "medium" | "high";
  reasons: string[];
};

type UrlScanResult = {
  url: string;
  stats?: VTStats;
  total?: number;
  malicious?: boolean;
  riskCategory?: string;
  threatInfo?: ThreatInfo;
  score?: number;
  ruleBasedCheck?: RuleBasedCheck;
  error?: string;
};

type EmailScanResponse = {
  type: "email";
  totalUrls: number;
  results: UrlScanResult[];
  hasMalicious: boolean;
  ruleBasedCheck?: RuleBasedCheck;
};

type UrlScanResponse = {
  type: "url";
  result: UrlScanResult;
};

// Rule-based detection functions
function editDistance(a: string, b: string): number {
  a = (a || "").toLowerCase();
  b = (b || "").toLowerCase();
  const dp = Array.from({ length: a.length + 1 }, () =>
    Array(b.length + 1).fill(0)
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[a.length][b.length];
}

const BRAND_DOMAINS = [
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "paypal.com",
  "netflix.com",
  "adobe.com",
  "github.com",
  "zoom.us",
  "dropbox.com",
  "icloud.com",
];

const SUSPICIOUS_TLDS = [
  "zip",
  "mov",
  "lol",
  "top",
  "gq",
  "cf",
  "tk",
  "work",
  "click",
  "link",
];

const URGENCY_WORDS = [
  "urgent",
  "immediately",
  "verify your account",
  "password expired",
  "final notice",
  "account suspended",
  "update billing",
  "confirm identity",
  "wire transfer",
  "gift card",
];

const CONTROL_CHAR_RE = /[\u202E\u202A-\u202E\u2066-\u2069]/;
const PUNYCODE_RE = /(^|\.)xn--/;

function hostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function looksTyposquat(host: string): boolean {
  host = (host || "").toLowerCase();
  return BRAND_DOMAINS.some(
    (b) => editDistance(host, b) === 1 || host.endsWith("." + b)
  );
}

function scoreUrl(url: string): RuleBasedCheck {
  let score = 0;
  const reasons: string[] = [];

  const host = hostnameFromUrl(url);
  if (!host) {
    score += 10;
    reasons.push("Invalid or malformed URL.");
  }

  if (PUNYCODE_RE.test(host)) {
    score += 15;
    reasons.push("Punycode domain detected.");
  }

  if (SUSPICIOUS_TLDS.some((t) => host.endsWith("." + t))) {
    score += 8;
    reasons.push(`Suspicious TLD: ${host}`);
  }

  if (looksTyposquat(host)) {
    score += 12;
    reasons.push(`Domain looks like a brand typosquat: ${host}`);
  }

  if (url.startsWith("data:")) {
    score += 6;
    reasons.push("Data URI detected.");
  }

  // Check for excessive path/query length (potential obfuscation)
  try {
    const urlObj = new URL(url);
    if (urlObj.pathname.length + urlObj.search.length > 200) {
      score += 4;
      reasons.push("Unusually long URL path/query.");
    }
  } catch {}

  const level = score >= 25 ? "high" : score >= 12 ? "medium" : "low";
  return {
    score,
    level,
    reasons: Array.from(new Set(reasons)).slice(0, 8),
  };
}

function domainFromEmail(addr: string): string {
  const m = (addr || "").match(/@([^>]+)>?$|@(.+)$/);
  return m ? (m[1] || m[2]).toLowerCase().trim() : "";
}

function scoreEmail(params: {
  fromName?: string;
  fromEmail?: string;
  subject?: string;
  bodyText?: string;
  links?: Array<{ href: string; text?: string; isDataUrl?: boolean }>;
}): RuleBasedCheck {
  const { fromName, fromEmail, subject, bodyText, links } = params;
  let score = 0;
  const reasons: string[] = [];

  const fromDomain = domainFromEmail(fromEmail || "");
  if (!fromDomain) {
    score += 10;
    reasons.push("Sender address missing or malformed.");
  }

  if (fromName && fromDomain && fromName.toLowerCase().includes("support")) {
    if (!BRAND_DOMAINS.some((b) => fromDomain.endsWith(b))) {
      score += 8;
      reasons.push("Display name suggests support, domain not recognized.");
    }
  }

  if (PUNYCODE_RE.test(fromDomain)) {
    score += 15;
    reasons.push("Punycode domain detected.");
  }

  if (CONTROL_CHAR_RE.test(bodyText || "")) {
    score += 12;
    reasons.push("Hidden unicode control characters found.");
  }

  const text = `${subject || ""}\n${bodyText || ""}`.toLowerCase();
  const urgencyHits = URGENCY_WORDS.filter((w) => text.includes(w)).length;
  if (urgencyHits) {
    score += 5 + urgencyHits * 2;
    reasons.push("Urgent/pressure wording detected.");
  }

  // Links analysis
  const arr = Array.isArray(links) ? links : [];
  let sawLinks = false;
  for (const L of arr) {
    const host = hostnameFromUrl(L.href);
    if (!host) continue;
    sawLinks = true;

    if (SUSPICIOUS_TLDS.some((t) => host.endsWith("." + t))) {
      score += 6;
      reasons.push(`Suspicious TLD: ${host}`);
    }
    if (looksTyposquat(host)) {
      score += 10;
      reasons.push(`Domain looks like a brand typosquat: ${host}`);
    }
    if (L.isDataUrl) {
      score += 4;
      reasons.push("Data URI link present.");
    }
  }
  if (!sawLinks) reasons.push("No links detected.");

  const level = score >= 25 ? "high" : score >= 12 ? "medium" : "low";
  return {
    score,
    level,
    reasons: Array.from(new Set(reasons)).slice(0, 8),
  };
}

function determineRiskCategory(stats: VTStats): string {
  if (stats.malicious > 0) return "malicious";
  if (stats.suspicious > 0) return "suspicious";
  if (stats.harmless > 0) return "harmless";
  return "unrated";
}

function calculateSafetyScore(stats: VTStats): number {
  const total =
    stats.harmless +
    stats.malicious +
    stats.suspicious +
    stats.timeout +
    stats.undetected;

  if (total === 0) return 0;

  // Weight different verdicts
  const weightedScore =
    stats.harmless * 1.0 +
    stats.undetected * 0.5 +
    stats.timeout * 0.3 -
    stats.suspicious * 1.0 -
    stats.malicious * 2.0;

  // Normalize to 0-100 scale
  const maxPossibleScore = total * 1.0; // All harmless
  const minPossibleScore = total * -2.0; // All malicious
  const range = maxPossibleScore - minPossibleScore;

  const normalizedScore = ((weightedScore - minPossibleScore) / range) * 100;

  // Clamp between 0 and 100
  return Math.max(0, Math.min(100, Math.round(normalizedScore)));
}

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const { url, email, emailMeta } = body as {
      url?: string;
      email?: string;
      emailMeta?: {
        fromName?: string;
        fromEmail?: string;
        subject?: string;
        bodyText?: string;
      };
    };
    const apiKey =
      process.env.API_KEY ||
      process.env.VIRUSTOTAL_API_KEY ||
      process.env.API_KEY;

    if (!apiKey) {
      return NextResponse.json(
        { error: "Missing VirusTotal API key" },
        { status: 500 }
      );
    }

    // extract urls helper (works for multiple in email)
    const extractUrls = (text: string) => {
      if (!text) return [];
      return Array.from(text.matchAll(/https?:\/\/[^\s'")<>]+/gi)).map((m) =>
        m[0].replace(/[.,;:)\]>]+$/g, "")
      );
    };

    async function submitUrlToVT(targetUrl: string): Promise<UrlScanResult> {
      try {
        const params = new URLSearchParams();
        params.set("url", targetUrl);

        const headers: Record<string, string> = {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
        };
        if (apiKey) headers["x-apikey"] = apiKey;

        const submitRes = await fetch(
          "https://www.virustotal.com/api/v3/urls",
          {
            method: "POST",
            headers,
            body: params,
          }
        );

        if (!submitRes.ok) {
          const text = await submitRes.text().catch(() => "");
          return {
            url: targetUrl,
            error: `Failed to submit URL: ${text}`,
          } as UrlScanResult;
        }

        const data = await submitRes.json().catch(() => ({}));
        const analysisId = data?.data?.id;
        if (!analysisId) {
          return {
            url: targetUrl,
            error: "No analysis ID returned",
          } as UrlScanResult;
        }

        // Poll analysis endpoint until completed (or timeout)
        const maxAttempts = 20;
        const delayMs = 1000;
        let attempt = 0;
        let analysisData: any = null;

        while (attempt < maxAttempts) {
          attempt++;
          const headers2: Record<string, string> = {};
          if (apiKey) headers2["x-apikey"] = apiKey;

          const analysisRes = await fetch(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            { headers: headers2 }
          );

          if (!analysisRes.ok) {
            await new Promise((r) => setTimeout(r, delayMs));
            continue;
          }

          analysisData = await analysisRes.json().catch(() => null);
          const status = analysisData?.data?.attributes?.status;
          if (status === "completed") break;
          await new Promise((r) => setTimeout(r, delayMs));
        }

        if (!analysisData) {
          return {
            url: targetUrl,
            error: "Failed to fetch analysis results",
          } as UrlScanResult;
        }

        const stats =
          analysisData?.data?.attributes?.stats ||
          analysisData?.data?.attributes?.results?.stats ||
          {};

        const normalized: VTStats = {
          harmless: Number(stats.harmless || 0),
          malicious: Number(stats.malicious || 0),
          suspicious: Number(stats.suspicious || 0),
          timeout: Number(stats.timeout || 0),
          undetected: Number(stats.undetected || 0),
        };

        const total =
          normalized.harmless +
          normalized.malicious +
          normalized.suspicious +
          normalized.timeout +
          normalized.undetected;

        const riskCategory = determineRiskCategory(normalized);
        const score = calculateSafetyScore(normalized);
        const ruleBasedCheck = scoreUrl(targetUrl);
        const threatInfo = await getThreatInfo(riskCategory, targetUrl);
        console.log(ruleBasedCheck);

        return {
          url: targetUrl,
          stats: normalized,
          total,
          malicious: normalized.malicious + normalized.suspicious > 0,
          riskCategory,
          score,
          ruleBasedCheck,
          threatInfo,
        };
      } catch (err: any) {
        return {
          url: targetUrl,
          error: String(err?.message || err),
        } as UrlScanResult;
      }
    }

    if (url) {
      const result = await submitUrlToVT(url);
      return NextResponse.json({ type: "url", result } as UrlScanResponse);
    }

    if (email) {
      const urls = extractUrls(email);
      if (urls.length === 0) {
        const empty: EmailScanResponse = {
          type: "email",
          totalUrls: 0,
          results: [],
          hasMalicious: false,
        };
        return NextResponse.json(empty);
      }

      const results = await Promise.all(urls.map((u) => submitUrlToVT(u)));
      const hasMalicious = results.some((r) => r.malicious === true);

      // Calculate overall email rule-based check
      const links = results.map((r) => ({
        href: r.url,
        isDataUrl: r.url.startsWith("data:"),
      }));

      const emailRuleCheck = scoreEmail({
        fromName: emailMeta?.fromName,
        fromEmail: emailMeta?.fromEmail,
        subject: emailMeta?.subject,
        bodyText: emailMeta?.bodyText || email,
        links,
      });

      const resp: EmailScanResponse = {
        type: "email",
        totalUrls: urls.length,
        results,
        hasMalicious,
        ruleBasedCheck: emailRuleCheck,
      };
      return NextResponse.json(resp);
    }

    return NextResponse.json(
      { error: "No URL or email provided" },
      { status: 400 }
    );
  } catch (err: any) {
    console.error("Scan error:", err);
    return NextResponse.json(
      { error: String(err?.message || err) },
      { status: 500 }
    );
  }
}

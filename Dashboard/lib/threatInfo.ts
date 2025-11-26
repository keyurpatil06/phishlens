// lib/threatInfo.ts
export type ThreatInfo = {
  title: string;
  explanation: string;
  tips: string[];
  severity?: "low" | "medium" | "high" | "critical";
};

export const threatExplanations: Record<string, ThreatInfo> = {
  malicious: {
    title: "Malicious Website Detected",
    explanation:
      "The website is flagged by multiple security vendors for harmful activity such as phishing, malware distribution, or credential theft.",
    tips: [
      "Do NOT enter any personal or login information on this website.",
      "Avoid clicking buttons or downloading files from the site.",
      "Close the website and run a security scan if you interacted with it."
    ],
    severity: "critical",
  },
  suspicious: {
    title: "Suspicious Website Behavior",
    explanation:
      "The scanned URL shows suspicious indicators (redirects, strange hostnames, or suspicious content). It may be used for phishing or other social-engineering attacks.",
    tips: [
      "Do not enter credentials on the site.",
      "Verify the URL carefully for misspellings or extra characters.",
      "Cross-check the link with other online scanners before interacting."
    ],
    severity: "high",
  },
  harmless: {
    title: "No Threats Detected",
    explanation:
      "Security engines did not report malicious or suspicious indicators for this URL. This does not guarantee absolute safety.",
    tips: [
      "Proceed cautiously on login pages even if a scan is clean.",
      "Avoid downloading files from unknown subpages.",
      "Bookmark trusted sites and use bookmarks to visit them."
    ],
    severity: "low",
  },
  unrated: {
    title: "Unrated / Unknown",
    explanation:
      "This URL hasn't been analyzed by security vendors (or results are unavailable). Unrated does not mean safe.",
    tips: [
      "Be cautious when opening unrated sites.",
      "Only proceed if you trust the sender/source.",
      "Use sandboxing / virtual machine if you must interact with unknown content."
    ],
    severity: "medium",
  },
};

export function getThreatCategory(stats: {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected?: number;
}): string {
  // simple deterministic mapping based on VT stats
  if ((stats.malicious ?? 0) > 0) return "malicious";
  if ((stats.suspicious ?? 0) > 0) return "suspicious";
  if ((stats.harmless ?? 0) > 0) return "harmless";
  return "unrated";
}

export function getThreatInfo(category: string): ThreatInfo {
  return threatExplanations[category] ?? threatExplanations["unrated"];
}

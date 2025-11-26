// lib/types.ts

// Type for raw VirusTotal URL scan response
export interface UrlScanResult {
  type: "url";
  url: string;
  stats?: {
    harmless: number;
    malicious: number;
    suspicious: number;
    undetected: number;
    timeout: number;
  };
  total?: number;
  malicious?: boolean;
  suspicious?: boolean;

  // Optional extra fields
  riskCategory?: string;
  threatInfo?: {
    summary: string;
    explanation: string;
    tips: string[];
  };

  error?: string;
}

// Type for EACH URL inside an email scan result
export interface EmailUrlResult {
  url: string;
  malicious: boolean;
  suspicious?: boolean;
  error?: string;

  // Optional enhanced threat fields
  riskCategory?: string;
  threatInfo?: {
    summary: string;
    explanation: string;
    tips: string[];
  };
}

// Type for the whole email scan
export interface EmailScanResult {
  type: "email";
  totalUrls: number;
  results: EmailUrlResult[];
}

// Unified type for ScanForm + ScanResult
export type RiskAssessment =
  | {
      type: "url";
      result: UrlScanResult;
    }
  | EmailScanResult;

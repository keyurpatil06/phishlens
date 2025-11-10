// lib/types.ts
export type VTStats = {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
};

export type UrlScanResult = {
  url: string;
  stats?: VTStats;
  total?: number;
  malicious?: boolean;
  error?: string;
};

export type UrlScanResponse = {
  type: "url";
  result: UrlScanResult;
};

export type EmailScanResponse = {
  type: "email";
  totalUrls: number;
  results: UrlScanResult[];
  hasMalicious: boolean;
};

// union for convenience
export type RiskAssessment = UrlScanResponse | EmailScanResponse;

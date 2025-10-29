export type RiskLevel = "low" | "medium" | "high";

export type RiskCheck = {
  id: string;
  label: string;
  flagged: boolean;
  impact: number;
  details?: string;
};

export type RiskAssessment = {
  url: string;
  type: "url" | "email";
  stats: {
    harmless: number;
    malicious: number;
    suspicious: number;
    timeout: number;
    undetected: number;
  };
  total: number;
  malicious: boolean;
  checks?: RiskCheck[];
};

export type Risk = {
  result: RiskAssessment;
};

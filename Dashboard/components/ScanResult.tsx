// components/ScanResult.tsx
"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { UrlScanResult, RiskAssessment } from "@/lib/types";

function computeSafeScore(result: UrlScanResult) {
  const stats = result.stats || { harmless: 0, malicious: 0, suspicious: 0, timeout: 0, undetected: 0 };
  const totalDetections = stats.malicious + stats.suspicious + stats.timeout + stats.undetected;
  const totalChecks = result.total || (totalDetections + stats.harmless) || 1;
  const safeScore = Math.round((totalDetections / totalChecks) * 100);
  return { safeScore, stats, totalChecks };
}

export function ScanResultView({ url, result }: { url: string; result: RiskAssessment | null }) {
  if (!result) {
    return (
      <Alert>
        <AlertTitle>No scan yet</AlertTitle>
        <AlertDescription>Enter a URL or paste an email above to see the risk analysis.</AlertDescription>
      </Alert>
    );
  }

  // If URL scan response
  if (result.type === "url") {
    const r = result.result;
    if (r.error) {
      return (
        <Alert>
          <AlertTitle>Scan error</AlertTitle>
          <AlertDescription>{r.error}</AlertDescription>
        </Alert>
      );
    }

    const { safeScore, stats } = computeSafeScore(r);
    let safeLevel: "LOW" | "MEDIUM" | "HIGH" = "LOW";
    if (safeScore >= 70) safeLevel = "HIGH";
    else if (safeScore >= 30) safeLevel = "MEDIUM";

    const levelClass =
      safeLevel === "HIGH"
        ? "bg-destructive text-destructive-foreground"
        : safeLevel === "MEDIUM"
          ? "bg-secondary text-secondary-foreground"
          : "bg-primary text-primary-foreground";

    // Basic checks array for UI (non-actionable)
    const checks = [
      { id: "malicious", label: "Malicious detections", flagged: (stats.malicious || 0) > 0, details: `${stats.malicious || 0} engines flagged as malicious` },
      { id: "suspicious", label: "Suspicious detections", flagged: (stats.suspicious || 0) > 0, details: `${stats.suspicious || 0} engines flagged as suspicious` },
      { id: "undetected", label: "Undetected count", flagged: false, details: `${stats.undetected || 0} engines returned undetected` },
    ];

    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-pretty">Result for <span className="font-mono">{r.url}</span></CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-sm text-muted-foreground">Risk score (0-100)</span>
              <div className="flex items-center gap-2">
                <span className="text-3xl font-semibold">{safeScore}</span>
                <Badge className={levelClass} aria-label={`Risk level ${safeLevel}`}>{safeLevel}</Badge>
              </div>
            </div>
            <div className="w-1/2">
              <Progress value={Math.min(100, Math.max(0, safeScore))} aria-label="Risk score progress" />
            </div>
          </div>

          <div className="grid gap-2">
            <h3 className="text-sm font-medium">Findings</h3>
            <ul className="grid gap-2">
              {checks.map((c) => (
                <li key={c.id} className="rounded-md border p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-medium">{c.label}</span>
                    <Badge variant={c.flagged ? "destructive" : "default"}>{c.flagged ? "Flagged" : "OK"}</Badge>
                  </div>
                  {c.details && <p className="text-muted-foreground mt-1 text-sm leading-relaxed">{c.details}</p>}
                </li>
              ))}
            </ul>
          </div>
        </CardContent>
      </Card>
    );
  }

  // If email scan response show summary of all detected URLs
  if (result.type === "email") {
    const emailResp = result;
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-pretty">Email scan — {emailResp.totalUrls} URLs</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          {emailResp.results.map((r) => (
            <div key={r.url} className="rounded-md border p-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium truncate">{r.url}</div>
                  <div className="text-sm text-muted-foreground">
                    {r.error ? `Error: ${r.error}` : (r.malicious ? "Malicious or suspicious" : "No known malicious detections")}
                  </div>
                </div>
                <div className="ml-4">
                  <Badge variant={r.malicious ? "destructive" : "default"}>{r.malicious ? "Flagged" : "OK"}</Badge>
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  return null;
}

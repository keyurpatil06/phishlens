"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { Risk } from "@/lib/types";

export function ScanResultView({ url, result }: { url: string; result: Risk | null }) {
  if (!result) {
    return (
      <Alert>
        <AlertTitle>No scan yet</AlertTitle>
        <AlertDescription>Enter a URL above to see the risk analysis.</AlertDescription>
      </Alert>
    );
  }

  const stats = result.result.stats;
  const totalDetections = stats.malicious + stats.suspicious + stats.timeout + stats.undetected;
  const totalChecks = result.result.total || 1; // avoid division by 0
  const safeScore = Math.round((totalDetections / totalChecks) * 100);

  let safeLevel: "LOW" | "MEDIUM" | "HIGH" = "LOW";
  if (safeScore >= 70) safeLevel = "HIGH";
  else if (safeScore >= 30) safeLevel = "MEDIUM";

  const levelClass =
    safeLevel === "HIGH"
      ? "bg-destructive text-destructive-foreground"
      : safeLevel === "MEDIUM"
        ? "bg-secondary text-secondary-foreground"
        : "bg-primary text-primary-foreground";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-pretty">
          Result for <span className="font-mono">{url}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex items-center justify-between">
          <div className="flex flex-col">
            <span className="text-sm text-muted-foreground">Risk score (0-100)</span>
            <div className="flex items-center gap-2">
              <span className="text-3xl font-semibold">{safeScore}</span>
              <Badge className={levelClass} aria-label={`Risk level ${safeLevel}`}>
                {safeLevel}
              </Badge>
            </div>
          </div>
          <div className="w-1/2">
            <Progress value={Math.min(100, Math.max(0, safeScore))} aria-label="Risk score progress" />
          </div>
        </div>

        <div className="grid gap-2">
          <h3 className="text-sm font-medium">Findings</h3>
          <ul className="grid gap-2">
            {(result.checks || []).map((c) => (
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

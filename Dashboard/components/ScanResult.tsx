"use client"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import type { UrlScanResult, RiskAssessment } from "@/lib/types"

function computeSafeScore(result: UrlScanResult) {
  const stats = result.stats || {
    harmless: 0,
    malicious: 0,
    suspicious: 0,
    timeout: 0,
    undetected: 0,
  }

  const totalDetections = stats.malicious + stats.suspicious + stats.timeout + stats.undetected
  const totalChecks = result.total || 1
  const safeScore = Math.round((totalDetections / totalChecks) * 100)
  const aiScore = result.threatInfo?.score;
  const ruleBased = result.ruleBasedCheck.score;

  return { safeScore, stats, totalChecks, aiScore, ruleBased }
}

export function ScanResultView({ url, result }: { url: string; result: RiskAssessment | null }) {
  if (!result) {
    return (
      <Alert className="border-border/50 bg-secondary/30 backdrop-blur-sm">
        <AlertTitle className="text-primary">Ready to scan</AlertTitle>
        <AlertDescription>Enter a URL or paste an email to begin security analysis.</AlertDescription>
      </Alert>
    )
  }

  if (result.type === "url") {
    const r = result.result

    if (r.error) {
      return (
        <Alert className="border-destructive/50 bg-destructive/10">
          <AlertTitle>Scan Error</AlertTitle>
          <AlertDescription>{r.error}</AlertDescription>
        </Alert>
      )
    }

    const { safeScore, stats, aiScore, ruleBased } = computeSafeScore(r)

    let safeLevel: "LOW" | "MEDIUM" | "HIGH" = "LOW"
    let levelColor = "bg-green-500/20 text-green-300 border-green-500/30"
    let scoreBarColor = "bg-green-500/50"

    if (safeScore >= 70 || (aiScore !== undefined && aiScore >= 70)) {
      safeLevel = "HIGH"
      levelColor = "bg-destructive/20 text-destructive border-destructive/30"
      scoreBarColor = "bg-destructive/50"
    } else if (safeScore >= 30 || (aiScore !== undefined && aiScore >= 70)) {
      safeLevel = "MEDIUM"
      levelColor = "bg-yellow-500/20 text-yellow-300 border-yellow-500/30"
      scoreBarColor = "bg-yellow-500/50"
    }

    const checks = [
      {
        id: "malicious",
        label: "Malicious Detections",
        flagged: (stats.malicious || 0) > 0,
        count: stats.malicious || 0,
      },
      {
        id: "suspicious",
        label: "Suspicious Detections",
        flagged: (stats.suspicious || 0) > 0,
        count: stats.suspicious || 0,
      },
      {
        id: "undetected",
        label: "Undetected",
        flagged: false,
        count: stats.undetected || 0,
      },
    ]

    return (
      <Card className="border-border/50 bg-card/50 backdrop-blur-sm overflow-hidden">
        <CardHeader className="border-b border-border/30 pb-4">
          <CardTitle className="text-sm font-normal text-muted-foreground">
            Scan Result for:{" "}
            <span className="text-foreground font-semibold block mt-2 break-all text-base">{r.url}</span>
          </CardTitle>
        </CardHeader>

        <CardContent className="pt-6 space-y-6">
          {/* Risk Score */}
          <div className="space-y-3">
            <div className="flex items-end justify-between">
              <div>
                <p className="text-xs text-muted-foreground font-medium">RISK SCORE</p>
                <p className="text-xl font-bold text-foreground my-1">API Score: {safeScore}</p>
                <p className="text-xl font-bold text-foreground my-1">Rule based Score: {ruleBased}</p>
              </div>
              <Badge className={`${levelColor} border`}>{safeLevel}</Badge>
            </div>
            <Progress value={Math.min(100, Math.max(0, safeScore))} className="h-2" />
          </div>

          {/* Findings */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold text-muted-foreground uppercase">Security Findings</h3>
            <div className="grid gap-2">
              {checks.map((c) => (
                <div
                  key={c.id}
                  className="rounded-lg border border-border/50 bg-secondary/20 p-3 flex items-center justify-between hover:bg-secondary/40 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className={c.flagged ? "text-lg" : "text-lg"}>{c.flagged ? "⚠️" : "✓"}</span>
                    <span className="text-sm font-medium">{c.label}</span>
                  </div>
                  <Badge
                    variant={c.flagged ? "destructive" : "secondary"}
                    className={c.flagged ? "" : "bg-green-500/20 text-green-300 border-green-500/30"}
                  >
                    {c.count}
                  </Badge>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Assessment */}
          {r.riskCategory && r.threatInfo && (
            <div className="space-y-3 rounded-lg border border-border/50 bg-accent/10 p-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold">🎯 Threat Assessment</h3>
                <Badge variant="secondary" className="uppercase text-xs">
                  {r.threatInfo?.severity}
                </Badge>
              </div>
              <p className="text-2xl font-bold text-foreground my-1">AI Score: {aiScore}</p>
              <p className="text-sm text-muted-foreground">{r.threatInfo.explanation}</p>
              <ul className="text-xs space-y-1 text-muted-foreground">
                {r.threatInfo.tips.slice(0, 3).map((t, i) => (
                  <li key={i} className="flex gap-2">
                    <span>•</span>
                    <span>{t}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>
    )
  }

  if (result.type === "email") {
    const emailResp = result
    const r = emailResp.results[0];

    return (
      <Card className="border-border/50 bg-card/50 backdrop-blur-sm p-3">
        <CardHeader className="border-b border-border/30">
          <CardTitle className="text-base">Email Analysis - {emailResp.totalUrls} URLs</CardTitle>
        </CardHeader>
        <CardContent className="pt-6 space-y-3">
          {emailResp.results.map((r) => (
            <div key={r.url} className="rounded-lg border border-border/50 bg-secondary/20 p-3">
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-sm truncate">{r.url}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {r.error
                      ? `❌ Error: ${r.error}`
                      : r.malicious
                        ? "⚠️ Malicious or suspicious"
                        : "✓ No known threats"}
                  </div>
                </div>
                <Badge
                  variant={r.malicious ? "destructive" : "secondary"}
                  className={r.malicious ? "" : "bg-green-500/20 text-green-300 border-green-500/30"}
                >
                  {r.malicious ? "Flagged" : "OK"}
                </Badge>
              </div>
            </div>
          ))}
        </CardContent>

        {/* Threat Assessment */}
        {r.riskCategory && r.threatInfo && (
          <div className="space-y-3 rounded-lg border border-border/50 bg-accent/10 p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">🎯 Threat Assessment</h3>
              <Badge variant="secondary" className="uppercase text-xs">
                {r.threatInfo?.severity}
              </Badge>
            </div>
            <p className="text-xl font-bold text-foreground my-1">Threat Score: {r.threatInfo.score}</p>
            <p className="text-sm text-muted-foreground">{r.threatInfo.explanation}</p>
            <ul className="text-xs space-y-1 text-muted-foreground">
              {r.threatInfo.tips.slice(0, 3).map((t, i) => (
                <li key={i} className="flex gap-2">
                  <span>•</span>
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
    )
  }

  return null
}

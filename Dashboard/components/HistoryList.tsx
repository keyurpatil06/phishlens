"use client"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { RiskAssessment } from "@/lib/types"

type HistoryItem = {
  url: string
  result: RiskAssessment
  timestamp: number
}

export function HistoryList({
  items,
  onClear,
  onSelect,
}: {
  items: HistoryItem[]
  onClear: () => void
  onSelect: (item: HistoryItem) => void
}) {
  // Helper to compute score and level
  const computeScoreAndLevel = (result: any) => {
    // result may be UrlScanResult or { result: UrlScanResult } (older shape)
    const r = result?.stats ? result : (result?.result ? result.result : result);
    const stats = r.stats || { harmless: 0, malicious: 0, suspicious: 0, timeout: 0, undetected: 0 };
    const totalDetections = stats.malicious + stats.suspicious + stats.timeout + stats.undetected;
    const totalChecks = r.total || (totalDetections + stats.harmless) || 1;
    const safeScore = Math.round((totalDetections / totalChecks) * 100);

    let safeLevel: "LOW" | "MEDIUM" | "HIGH" = "LOW";
    if (safeScore >= 70) safeLevel = "HIGH";
    else if (safeScore >= 30) safeLevel = "MEDIUM";

    return { safeScore, safeLevel };
  };

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-base">History</CardTitle>
        <Button variant="outline" size="sm" onClick={onClear} aria-label="Clear history">
          Clear
        </Button>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-muted-foreground text-sm">No scans yet.</p>
        ) : (
          <ul className="grid gap-2">
            {items.map((item) => {
              const { safeScore, safeLevel } = computeScoreAndLevel(item.result)
              return (
                <li key={`${item.url}-${item.timestamp}`}>
                  <button
                    className="w-full rounded-md border p-2 text-left hover:bg-accent hover:text-accent-foreground"
                    onClick={() => onSelect(item)}
                    aria-label={`Load result for ${item.url}`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="truncate font-medium text-wrap">{item.url}</span>
                      <span className="text-muted-foreground text-xs">{new Date(item.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="text-muted-foreground text-xs">
                      Score {safeScore} • {safeLevel}
                    </div>
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

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
  const computeScoreAndLevel = (result: any) => {

    // console.log(result.result);

    const r = result?.stats ? result : result?.result ? result.result : result
    const stats = r.stats || { harmless: 0, malicious: 0, suspicious: 0, timeout: 0, undetected: 0 }
    const totalDetections = stats.malicious + stats.suspicious + stats.timeout + stats.undetected
    const totalChecks = r.total || totalDetections + stats.harmless || 1
    // const safeScore = Math.round((totalDetections / totalChecks) * 100)
    const safeScore = result.result?.threatInfo.score || 0

    let safeLevel: "LOW" | "MEDIUM" | "HIGH" = "LOW"
    if (safeScore >= 70) safeLevel = "HIGH"
    else if (safeScore >= 30) safeLevel = "MEDIUM"

    return { safeScore, safeLevel }
  }

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur-sm overflow-hidden">
      <CardHeader className="flex-row items-center justify-between pb-3 border-b border-border/30">
        <CardTitle className="text-base">Scan History</CardTitle>
        <Button
          variant="ghost"
          size="sm"
          onClick={onClear}
          className="text-xs text-white font-semibold bg-destructive/80 hover:bg-destructive cursor-pointer"
          aria-label="Clear history"
        >
          Clear
        </Button>
      </CardHeader>
      <CardContent className="pt-4">
        {items.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-6">No scans yet.</p>
        ) : (
          <ul className="space-y-2">
            {items.map((item) => {
              const { safeScore, safeLevel } = computeScoreAndLevel(item.result)
              const levelColor =
                safeLevel === "HIGH"
                  ? "text-destructive"
                  : safeLevel === "MEDIUM"
                    ? "text-yellow-400"
                    : "text-green-400"

              return (
                <li key={`${item.url}-${item.timestamp}`}>
                  <button
                    className="w-full text-left rounded-lg border border-border/50 bg-secondary/30 p-3 hover:bg-secondary/60 transition-colors group"
                    onClick={() => onSelect(item)}
                    aria-label={`Load result for ${item.url}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-xs font-mono truncate flex-1 text-foreground/80 group-hover:text-foreground">
                        {item.url}
                      </span>
                      <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(item.timestamp).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </span>
                    </div>
                    <div className="flex items-center justify-between mt-2">
                      <span className={`text-xs font-bold ${levelColor}`}>Risk: {safeScore}</span>
                      <span className="text-xs text-muted-foreground">
                        {safeLevel === "LOW" ? "✓ Safe" : safeLevel === "MEDIUM" ? "⚠️ Caution" : "🔴 High Risk"}
                      </span>
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

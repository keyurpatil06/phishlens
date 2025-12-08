"use client"

import { Line, Bar } from "react-chartjs-2"
import {
  Chart as ChartJS,
  LineElement,
  BarElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Tooltip,
  Legend,
} from "chart.js"
import type { RiskAssessment } from "@/lib/types"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

ChartJS.register(LineElement, BarElement, CategoryScale, LinearScale, PointElement, Tooltip, Legend)

type HistoryItem = {
  url: string
  result: RiskAssessment
  timestamp: number
}

type RiskLevel = "LOW" | "MEDIUM" | "HIGH"

function computeScoreAndLevel(result: any): { safeScore: number; safeLevel: RiskLevel } {
  const r = result?.stats ? result : result?.result ? result.result : result

  const stats = r.stats || {
    harmless: 0,
    malicious: 0,
    suspicious: 0,
    timeout: 0,
    undetected: 0,
  }

  const totalDetections = stats.malicious + stats.suspicious + stats.timeout + stats.undetected
  const totalChecks = r.total || totalDetections + stats.harmless || 1
  const safeScore = Math.round((totalDetections / totalChecks) * 100)

  let safeLevel: RiskLevel = "LOW"
  if (safeScore >= 70) safeLevel = "HIGH"
  else if (safeScore >= 30) safeLevel = "MEDIUM"

  return { safeScore, safeLevel }
}

export default function HistoryCharts({ history }: { history: HistoryItem[] }) {
  if (!history || history.length === 0)
    return (
      <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
        <CardContent className="pt-6">
          <p className="text-xs text-muted-foreground text-center py-6">No chart data yet.</p>
        </CardContent>
      </Card>
    )

  const scoreLabels = history.map((h) =>
    new Date(h.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  )

  const scoreValues = history.map((h) => computeScoreAndLevel(h.result).safeScore)

  const scoreData = {
    labels: scoreLabels,
    datasets: [
      {
        label: "Risk Score",
        data: scoreValues,
        borderColor: "rgb(99, 198, 208)",
        backgroundColor: "rgba(99, 198, 208, 0.1)",
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        pointBackgroundColor: "rgb(99, 198, 208)",
      },
    ],
  }

  const counts: Record<RiskLevel, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
  }

  history.forEach((h) => {
    const { safeLevel } = computeScoreAndLevel(h.result)
    counts[safeLevel]++
  })

  const summaryData = {
    labels: ["Low", "Medium", "High"],
    datasets: [
      {
        label: "Scan Count",
        data: [counts.LOW, counts.MEDIUM, counts.HIGH],
        backgroundColor: ["rgba(34, 197, 94, 0.8)", "rgba(234, 179, 8, 0.8)", "rgba(239, 68, 68, 0.8)"],
        borderColor: ["rgb(34, 197, 94)", "rgb(234, 179, 8)", "rgb(239, 68, 68)"],
        borderWidth: 1,
      },
    ],
  }

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        labels: { color: "rgb(148, 163, 184)", font: { size: 12 } },
      },
    },
    scales: {
      y: {
        ticks: { color: "rgb(148, 163, 184)", font: { size: 11 } },
        grid: { color: "rgba(148, 163, 184, 0.1)" },
      },
      x: {
        ticks: { color: "rgb(148, 163, 184)", font: { size: 11 } },
        grid: { color: "rgba(148, 163, 184, 0.1)" },
      },
    },
  }

  return (
    <div className="space-y-4">
      <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Risk Score Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <Line data={scoreData} options={chartOptions} height={200} />
        </CardContent>
      </Card>

      <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Risk Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <Bar data={summaryData} options={chartOptions} height={200} />
        </CardContent>
      </Card>
    </div>
  )
}

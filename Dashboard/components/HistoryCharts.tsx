"use client";

import { Line, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  LineElement,
  BarElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Tooltip,
  Legend,
} from "chart.js";
import type { RiskAssessment } from "@/lib/types";

ChartJS.register(
  LineElement,
  BarElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Tooltip,
  Legend
);

type HistoryItem = {
  url: string;
  result: RiskAssessment;
  timestamp: number;
};

type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

function computeScoreAndLevel(result: any): { safeScore: number; safeLevel: RiskLevel } {
  const r = result?.stats ? result : (result?.result ? result.result : result);

  const stats = r.stats || {
    harmless: 0,
    malicious: 0,
    suspicious: 0,
    timeout: 0,
    undetected: 0,
  };

  const totalDetections =
    stats.malicious + stats.suspicious + stats.timeout + stats.undetected;
  const totalChecks = r.total || (totalDetections + stats.harmless) || 1;
  const safeScore = Math.round((totalDetections / totalChecks) * 100);

  let safeLevel: RiskLevel = "LOW";
  if (safeScore >= 70) safeLevel = "HIGH";
  else if (safeScore >= 30) safeLevel = "MEDIUM";

  return { safeScore, safeLevel };
}

export default function HistoryCharts({ history }: { history: HistoryItem[] }) {
  if (!history || history.length === 0)
    return (
      <p className="text-muted-foreground text-sm mt-4">
        No chart data available.
      </p>
    );

  // ------------------------------
  // Score Line Chart
  // ------------------------------

  const scoreLabels = history.map((h) =>
    new Date(h.timestamp).toLocaleTimeString()
  );

  const scoreValues = history.map((h) =>
    computeScoreAndLevel(h.result).safeScore
  );

  const scoreData = {
    labels: scoreLabels,
    datasets: [
      {
        label: "Risk Score",
        data: scoreValues,
        borderWidth: 2,
      },
    ],
  };

  // ------------------------------
  // Bar Chart → LOW / MEDIUM / HIGH
  // ------------------------------

  const counts: Record<RiskLevel, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
  };

  history.forEach((h) => {
    const { safeLevel } = computeScoreAndLevel(h.result);
    counts[safeLevel]++;
  });

  const summaryData = {
    labels: ["Low", "Medium", "High"],
    datasets: [
      {
        label: "Scan Count",
        data: [counts.LOW, counts.MEDIUM, counts.HIGH],
        borderWidth: 2,
      },
    ],
  };

  return (
    <div className="grid gap-6 mt-6">
      <div className="rounded-lg border p-4">
        <h3 className="font-semibold mb-2">Risk Score History</h3>
        <Line data={scoreData} />
      </div>

      <div className="rounded-lg border p-4">
        <h3 className="font-semibold mb-2">Risk Level Summary</h3>
        <Bar data={summaryData} />
      </div>
    </div>
  );
}

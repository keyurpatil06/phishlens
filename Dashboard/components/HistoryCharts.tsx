"use client";

import { Line, Bar } from "react-chartjs-2";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { RiskAssessment, UrlScanResult } from "@/lib/types";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Tooltip,
  Legend
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, BarElement, PointElement, LineElement, Tooltip, Legend);

type HistoryItem = {
  url: string;
  result: RiskAssessment;
  timestamp: number;
};

// Helper: extract URL scan stats safely
function extractUrlStats(result: RiskAssessment): UrlScanResult | null {
  if (result.type === "url") {
    return result.result; // this has stats
  }
  return null; // email results don't have stats
}

export function HistoryCharts({ history }: { history: HistoryItem[] }) {
  if (history.length === 0) return null;

  // Labels for line chart
  const labels = history.map(h => new Date(h.timestamp).toLocaleDateString());

  // Line chart data: only URL results contribute
  const scores = history.map(h => {
    const r = extractUrlStats(h.result);
    if (!r) return 0; // For email scans, default = 0 score

    const stats = r.stats || { harmless: 0, malicious: 0, suspicious: 0, timeout: 0, undetected: 0 };
    const totalDetections =
      stats.malicious + stats.suspicious + stats.timeout + stats.undetected;
    const totalChecks = r.total || (totalDetections + stats.harmless) || 1;
    return Math.round((totalDetections / totalChecks) * 100);
  });

  // Aggregate bar chart data
  const total = { malicious: 0, suspicious: 0, undetected: 0, harmless: 0 };

  history.forEach(h => {
    const r = extractUrlStats(h.result);
    if (!r) return;

    const s: {
      malicious: number;
      suspicious: number;
      undetected: number;
      harmless: number;
    } = r.stats || {
      malicious: 0,
      suspicious: 0,
      undetected: 0,
      harmless: 0,
    };

    total.malicious += s.malicious;
    total.suspicious += s.suspicious;
    total.undetected += s.undetected;
    total.harmless += s.harmless;
  });

  return (
    <div className="grid gap-6 mt-6">

      {/* Line Chart */}
      <Card>
        <CardHeader>
          <CardTitle>Risk Score Over Time</CardTitle>
        </CardHeader>
        <CardContent>
          <Line
            data={{
              labels,
              datasets: [
                {
                  label: "Risk Score",
                  data: scores,
                  borderWidth: 2,
                },
              ],
            }}
          />
        </CardContent>
      </Card>

      {/* Bar Chart */}
      <Card>
        <CardHeader>
          <CardTitle>Detection Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <Bar
            data={{
              labels: ["Malicious", "Suspicious", "Undetected", "Harmless"],
              datasets: [
                {
                  label: "Count",
                  data: [
                    total.malicious,
                    total.suspicious,
                    total.undetected,
                    total.harmless,
                  ],
                  borderWidth: 1,
                },
              ],
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}

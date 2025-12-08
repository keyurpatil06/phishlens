"use client"

import { useCallback, useEffect, useState } from "react"
import type { RiskAssessment } from "@/lib/types"
import { ScanForm } from "./ScanForm"
import { ScanResultView } from "./ScanResult"
import HistoryCharts from "./HistoryCharts"
import { HistoryList } from "./HistoryList"

type HistoryItem = {
  url: string
  result: any
  timestamp: number
}

const HISTORY_KEY = "phishlens:history"

function loadHistory(): HistoryItem[] {
  if (typeof window === "undefined") return []
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY)
    return raw ? (JSON.parse(raw) as HistoryItem[]) : []
  } catch {
    return []
  }
}

function saveHistory(items: HistoryItem[]) {
  if (typeof window === "undefined") return
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 20)))
  } catch {
    // ignore quota errors
  }
}

export function PhishDashboard() {
  const [currentUrl, setCurrentUrl] = useState<string>("")
  const [result, setResult] = useState<RiskAssessment | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])

  useEffect(() => {
    setHistory(loadHistory())
  }, [])

  const handleScanned = useCallback((url: string, res: RiskAssessment) => {
    setCurrentUrl(url)
    setResult(res)
    const next: HistoryItem = { url, result: res, timestamp: Date.now() }
    setHistory((prev) => {
      const updated = [next, ...prev].slice(0, 20)
      saveHistory(updated)
      return updated
    })
  }, [])

  const handleClearHistory = useCallback(() => {
    saveHistory([])
    setHistory([])
  }, [])

  return (
    <div className="grid gap-8 lg:grid-cols-5">
      {/* Main scanning area */}
      <div className="lg:col-span-3 space-y-8">
        <ScanForm onScanned={handleScanned} />
        <div>
          <ScanResultView url={currentUrl} result={result} />
        </div>
      </div>

      {/* Sidebar */}
      <aside className="lg:col-span-2 space-y-8">
        <HistoryList
          items={history}
          onClear={handleClearHistory}
          onSelect={(item: HistoryItem) => {
            setCurrentUrl(item.url)
            setResult(item.result)
          }}
        />
        <HistoryCharts history={history} />
      </aside>
    </div>
  )
}

"use client"

import { useCallback, useEffect, useState } from "react"
import type { RiskAssessment } from "@/lib/types"
import { ScanForm } from "./ScanForm"
import { ScanResultView } from "./ScanResult"


type HistoryItem = {
  url: string
  result: RiskAssessment
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
    <div className="grid gap-6 md:grid-cols-5">
      <div className="md:col-span-3">
        <ScanForm onScanned={handleScanned} />
        <div className="mt-6">
          <ScanResultView url={currentUrl} result={result} />
        </div>
      </div>
      <aside className="md:col-span-2">
      </aside>
    </div>
  )
}

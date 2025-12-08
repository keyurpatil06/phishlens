"use client"

import type React from "react"
import { useState } from "react"
import useSWRMutation from "swr/mutation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { cn } from "@/lib/utils"
import type { RiskAssessment } from "@/lib/types"

async function postScan(_key: string, { arg }: { arg: { url?: string; email?: string } }): Promise<RiskAssessment> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(arg),
  })

  if (!res.ok) {
    const text = await res.text().catch(() => "")
    try {
      const json = JSON.parse(text || "{}")
      throw new Error(json.error || text || "Scan failed")
    } catch {
      throw new Error(text || "Scan failed")
    }
  }

  return (await res.json()) as RiskAssessment
}

export function ScanForm({
  onScanned,
}: {
  onScanned: (input: string, result: RiskAssessment) => void
}) {
  const [mode, setMode] = useState<"url" | "email">("url")
  const [input, setInput] = useState("")
  const { trigger, isMutating } = useSWRMutation("/api/scan", postScan)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = input.trim()
    if (!trimmed) return

    try {
      const payload = mode === "url" ? { url: trimmed } : { email: trimmed }
      const result = await trigger(payload)
      onScanned(trimmed, result)
    } catch (err) {
      console.error("Scan failed:", err)
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-6">
      {/* Mode Toggle */}
      <div className="flex gap-3 p-1 bg-secondary rounded-lg w-fit border border-border">
        <Button
          type="button"
          variant={mode === "url" ? "default" : "ghost"}
          onClick={() => setMode("url")}
          className="rounded-lg"
          size="sm"
        >
          URL Scan
        </Button>
        <Button
          type="button"
          variant={mode === "email" ? "default" : "ghost"}
          onClick={() => setMode("email")}
          className="rounded-lg"
          size="sm"
        >
          Email Scan
        </Button>
      </div>

      {/* Card */}
      <div className="rounded-xl border border-border/50 bg-card/50 backdrop-blur-sm p-6 shadow-xl hover:border-border/80 transition-colors">
        {/* Input Label */}
        <Label htmlFor={mode} className="text-sm font-semibold mb-3 block">
          {mode === "url" ? "Enter URL to check" : "Paste email content"}
        </Label>

        {mode === "url" ? (
          <div className="flex items-center gap-3">
            <div className="flex-1 relative">
              <Input
                id="url"
                type="url"
                placeholder="https://example.com/login"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className={cn("bg-input border-border/50 rounded-lg", "border-primary ring-primary")}
                aria-describedby="url-help"
                required
              />
            </div>
            <Button
              type="submit"
              disabled={isMutating}
              className="rounded-lg bg-gradient-to-r from-primary to-accent hover:from-primary/90 hover:to-accent/90"
            >
              {isMutating ? (
                <>
                  <span className="animate-spin mr-2">⏳</span>
                  Scanning
                </>
              ) : (
                <>
                  <span className="mr-2">🔍</span>
                  Scan
                </>
              )}
            </Button>
          </div>
        ) : (
          <>
            <Textarea
              id="email"
              placeholder="Paste suspicious email content here..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={6}
              className="resize-none bg-input border-border/50 rounded-lg focus:ring-primary"
              required
            />
            <Button
              type="submit"
              disabled={isMutating}
              className="mt-4 rounded-lg bg-gradient-to-r from-primary to-accent hover:from-primary/90 hover:to-accent/90"
            >
              {isMutating ? (
                <>
                  <span className="animate-spin mr-2">⏳</span>
                  Scanning
                </>
              ) : (
                <>
                  <span className="mr-2">📧</span>
                  Scan Email
                </>
              )}
            </Button>
          </>
        )}

        {/* Help Text */}
        <p id="url-help" className="text-xs text-muted-foreground mt-3 leading-relaxed">
          {mode === "url"
            ? "✓ VirusTotal database check • ✓ Malicious domain detection"
            : "✓ Link analysis • ✓ Phishing pattern detection"}
        </p>
      </div>
    </form>
  )
}

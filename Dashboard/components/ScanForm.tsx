"use client"

import React, { useState } from "react"
import useSWRMutation from "swr/mutation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { cn } from "@/lib/utils"
// where you defined postScan (e.g. in ScanForm file)
import type { RiskAssessment } from "@/lib/types";

async function postScan(
  _key: string,
  { arg }: { arg: { url?: string; email?: string } }
): Promise<RiskAssessment> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(arg),
  });

  if (!res.ok) {
    // try to get json error first
    let text = await res.text().catch(() => "");
    try {
      const json = JSON.parse(text || "{}");
      throw new Error(json.error || text || "Scan failed");
    } catch {
      throw new Error(text || "Scan failed");
    }
  }

  return (await res.json()) as RiskAssessment;
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
    <form
      onSubmit={onSubmit}
      className="grid gap-5 p-6 bg-card rounded-xl border border-border shadow-sm"
    >
      {/* --- Mode Switch --- */}
      <div className="flex justify-center gap-3">
        <Button
          type="button"
          variant={mode === "url" ? "default" : "outline"}
          onClick={() => setMode("url")}
          className="w-1/2"
        >
          URL Scan
        </Button>
        <Button
          type="button"
          variant={mode === "email" ? "default" : "outline"}
          onClick={() => setMode("email")}
          className="w-1/2"
        >
          Email Scan
        </Button>
      </div>

      {/* --- Input Section --- */}
      <div className="grid gap-2">
        <Label htmlFor={mode}>
          {mode === "url" ? "Enter URL to check" : "Paste email content"}
        </Label>

        {mode === "url" ? (
          <div className="flex items-center gap-2">
            <Input
              id="url"
              type="url"
              placeholder="https://example.com/login"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className={cn("flex-1")}
              aria-describedby="url-help"
              required
            />
            <Button type="submit" disabled={isMutating}>
              {isMutating ? "Scanning..." : "Scan"}
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
              className="resize-none"
              required
            />
            <Button type="submit" disabled={isMutating} className="self-end w-fit">
              {isMutating ? "Scanning..." : "Scan Email"}
            </Button>
          </>
        )}

        <p
          id="url-help"
          className="text-sm text-muted-foreground leading-relaxed"
        >
          {mode === "url"
            ? "We check VirusTotal's database for known malicious URLs, HTTPS usage, and risky domains."
            : "We scan all links in the email with VirusTotal and detect phishing patterns or impersonations."}
        </p>
      </div>
    </form>
  )
}

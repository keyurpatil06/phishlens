import { PhishDashboard } from "@/components/PhishDashboard"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function HomePage() {
  return (
    <main className="mx-auto max-w-5xl px-4 py-8">
      <header className="mb-6">
        <h1 className="text-balance text-3xl font-semibold tracking-tight">PhishLens</h1>
        <p className="text-muted-foreground mt-2 leading-relaxed">
          Scan URLs for phishing risk using heuristic checks. This MVP runs fully client-side and an API route—no
          external integrations yet.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="text-pretty">URL Risk Scanner</CardTitle>
        </CardHeader>
        <CardContent>
          <PhishDashboard />
        </CardContent>
      </Card>
    </main>
  )
}

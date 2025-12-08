import { PhishDashboard } from "@/components/PhishDashboard"

export const metadata = {
  title: "PhishLens - URL Security Scanner",
  description: "Advanced phishing detection and URL risk assessment",
}

export default function HomePage() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-background via-background to-secondary/20">
      {/* Header */}
      <header className="border-b border-border/50 backdrop-blur-sm sticky top-0 z-40 bg-background/80">
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                PhishLens
              </h1>
              <p className="text-sm text-muted-foreground mt-1">Advanced Email and URL Security Scanner</p>
            </div>
            <div className="hidden sm:block">
              <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-primary to-accent/50 flex items-center justify-center">
                <span className="text-lg font-bold text-primary-foreground">🛡️</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <PhishDashboard />
      </div>
    </main>
  )
}

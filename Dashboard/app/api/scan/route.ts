// app/api/scan/route.ts
import { NextResponse } from "next/server";

type VTStats = {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
};

type UrlScanResult = {
  url: string;
  stats: VTStats;
  total: number;
  malicious: boolean;
  error?: string;
};

type EmailScanResponse = {
  type: "email";
  totalUrls: number;
  results: UrlScanResult[];
  hasMalicious: boolean;
};

type UrlScanResponse = {
  type: "url";
  result: UrlScanResult;
};

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const { url, email } = body as { url?: string; email?: string };
    const apiKey = process.env.API_KEY;

    if (!apiKey) {
      return NextResponse.json(
        { error: "Missing VirusTotal API key" },
        { status: 500 }
      );
    }

    // extract urls helper (works for multiple in email)
    const extractUrls = (text: string) => {
      if (!text) return [];
      // simple but practical URL capture (http/https)
      return Array.from(text.matchAll(/https?:\/\/[^\s'")<>]+/gi)).map((m) =>
        // trim trailing punctuation
        m[0].replace(/[.,;:)\]>]+$/g, "")
      );
    };

    async function submitUrlToVT(targetUrl: string) {
      try {
        const params = new URLSearchParams();
        params.set("url", targetUrl);

        const headers: Record<string, string> = {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
        };
        if (apiKey) headers["x-apikey"] = apiKey;

        const submitRes = await fetch(
          "https://www.virustotal.com/api/v3/urls",
          {
            method: "POST",
            headers,
            body: params,
          }
        );

        if (!submitRes.ok) {
          const text = await submitRes.text().catch(() => "");
          return {
            url: targetUrl,
            error: `Failed to submit URL: ${text}`,
          } as UrlScanResult;
        }

        const data = await submitRes.json().catch(() => ({}));
        const analysisId = data?.data?.id;
        if (!analysisId) {
          return {
            url: targetUrl,
            error: "No analysis ID returned",
          } as UrlScanResult;
        }

        // Poll analysis endpoint until completed (or timeout)
        const maxAttempts = 12; // ~12s (with 1s delay)
        const delayMs = 1000;
        let attempt = 0;
        let analysisData: any = null;

        while (attempt < maxAttempts) {
          attempt++;
          const headers: Record<string, string> = {};
          if (apiKey) headers["x-apikey"] = apiKey;

          const analysisRes = await fetch(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            { headers }
          );

          if (!analysisRes.ok) {
            // try again unless we've exhausted attempts
            await new Promise((r) => setTimeout(r, delayMs));
            continue;
          }

          analysisData = await analysisRes.json().catch(() => null);
          const status = analysisData?.data?.attributes?.status;
          if (status === "completed") break;
          // else wait then poll again
          await new Promise((r) => setTimeout(r, delayMs));
        }

        // if still no analysisData, return with error
        if (!analysisData) {
          return {
            url: targetUrl,
            error: "Failed to fetch analysis results",
          } as UrlScanResult;
        }

        const stats = analysisData?.data?.attributes?.stats || {};
        // Normalize stats to numbers with defaults
        const normalized: VTStats = {
          harmless: Number(stats.harmless || 0),
          malicious: Number(stats.malicious || 0),
          suspicious: Number(stats.suspicious || 0),
          timeout: Number(stats.timeout || 0),
          undetected: Number(stats.undetected || 0),
        };

        const total =
          normalized.harmless +
          normalized.malicious +
          normalized.suspicious +
          normalized.timeout +
          normalized.undetected;

        return {
          url: targetUrl,
          stats: normalized,
          total,
          malicious: normalized.malicious + normalized.suspicious > 0,
        } as UrlScanResult;
      } catch (err: any) {
        return {
          url: targetUrl,
          error: String(err?.message || err),
        } as UrlScanResult;
      }
    }

    if (url) {
      const result = await submitUrlToVT(url);
      return NextResponse.json({ type: "url", result } as UrlScanResponse);
    }

    if (email) {
      const urls = extractUrls(email);
      if (urls.length === 0) {
        const empty: EmailScanResponse = {
          type: "email",
          totalUrls: 0,
          results: [],
          hasMalicious: false,
        };
        return NextResponse.json(empty);
      }

      const results = await Promise.all(urls.map((u) => submitUrlToVT(u)));
      const hasMalicious = results.some((r) => r.malicious === true);
      const resp: EmailScanResponse = {
        type: "email",
        totalUrls: urls.length,
        results,
        hasMalicious,
      };
      return NextResponse.json(resp);
    }

    return NextResponse.json(
      { error: "No URL or email provided" },
      { status: 400 }
    );
  } catch (err: any) {
    console.error("Scan error:", err);
    return NextResponse.json(
      { error: String(err?.message || err) },
      { status: 500 }
    );
  }
}

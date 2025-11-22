import { NextResponse } from "next/server";
import { checkUrlRules, RuleResult } from "@/lib/rules";

type VTStats = {
  harmless: number;
  malicious: number;
  suspicious: number;
  timeout: number;
  undetected: number;
};

type UrlScanResult = {
  url: string;
  stats?: VTStats;
  rules: RuleResult;
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

    const extractUrls = (text: string) => {
      if (!text) return [];
      return Array.from(text.matchAll(/https?:\/\/[^\s'")<>]+/gi)).map((m) =>
        m[0].replace(/[.,;:)\]>]+$/g, "")
      );
    };

    async function scanSingleUrl(targetUrl: string): Promise<UrlScanResult> {
      // 1. Run local rules (Instant)
      const ruleResult = checkUrlRules(targetUrl);

      // 2. Run VirusTotal (Async)
      try {
        const params = new URLSearchParams();
        params.set("url", targetUrl);

        const headers: Record<string, string> = {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
          "x-apikey": apiKey!,
        };

        const submitRes = await fetch(
          "https://www.virustotal.com/api/v3/urls",
          {
            method: "POST",
            headers,
            body: params,
          }
        );

        if (!submitRes.ok) throw new Error("VT Submit Failed");

        const data = await submitRes.json();
        const analysisId = data?.data?.id;
        if (!analysisId) throw new Error("No analysis ID");

        let attempt = 0;
        let analysisData: any = null;

        while (attempt < 10) {
          attempt++;
          await new Promise((r) => setTimeout(r, 1000)); // 1s wait

          const analysisRes = await fetch(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            { headers: { "x-apikey": apiKey! } }
          );

          if (analysisRes.ok) {
            analysisData = await analysisRes.json();
            if (analysisData?.data?.attributes?.status === "completed") break;
          }
        }

        if (!analysisData) throw new Error("Analysis timeout");

        const statsRaw = analysisData?.data?.attributes?.stats || {};
        const normalized: VTStats = {
          harmless: Number(statsRaw.harmless || 0),
          malicious: Number(statsRaw.malicious || 0),
          suspicious: Number(statsRaw.suspicious || 0),
          timeout: Number(statsRaw.timeout || 0),
          undetected: Number(statsRaw.undetected || 0),
        };

        const total = Object.values(normalized).reduce((a, b) => a + b, 0);
        const vtMalicious = normalized.malicious + normalized.suspicious > 0;

        return {
          url: targetUrl,
          stats: normalized,
          rules: ruleResult,
          total,
          // Flag as malicious if VT confirms it OR Rules give it a very high score (>70)
          malicious: vtMalicious || ruleResult.riskScore > 70,
        };
      } catch (err: any) {
        // Fallback: Return rule result if VT fails
        return {
          url: targetUrl,
          rules: ruleResult,
          total: 0,
          malicious: ruleResult.riskScore > 70,
          error: "VT Scan Failed, showing local analysis only",
        };
      }
    }

    // --- Handlers ---

    if (url) {
      const result = await scanSingleUrl(url);
      return NextResponse.json({ type: "url", result } as UrlScanResponse);
    }

    if (email) {
      const urls = extractUrls(email);
      if (!urls.length)
        return NextResponse.json({
          type: "email",
          totalUrls: 0,
          results: [],
          hasMalicious: false,
        });

      const results = await Promise.all(urls.map((u) => scanSingleUrl(u)));
      return NextResponse.json({
        type: "email",
        totalUrls: urls.length,
        results,
        hasMalicious: results.some((r) => r.malicious),
      } as EmailScanResponse);
    }

    return NextResponse.json(
      { error: "No URL or email provided" },
      { status: 400 }
    );
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

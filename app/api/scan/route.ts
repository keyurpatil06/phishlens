import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const { url, email } = await req.json();
    const apiKey = process.env.API_KEY!;

    if (!apiKey) {
      return NextResponse.json(
        { error: "Missing VirusTotal API key" },
        { status: 500 }
      );
    }

    async function scanUrl(targetUrl: string) {
      const params = new URLSearchParams();
      params.set("url", targetUrl);

      const res = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          accept: "application/json",
          "x-apikey": apiKey,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: params,
      });

      if (!res.ok)
        return { url: targetUrl, error: "Failed to submit URL to VirusTotal" };

      const data = await res.json();
      const analysisId = data?.data?.id;
      if (!analysisId)
        return { url: targetUrl, error: "No analysis ID returned" };

      const analysisRes = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: { "x-apikey": apiKey },
        }
      );
      if (!analysisRes.ok)
        return { url: targetUrl, error: "Failed to fetch analysis results" };

      const analysisData = await analysisRes.json();
      const stats = analysisData?.data?.attributes?.stats || {};

      const total =
        stats.harmless +
        stats.malicious +
        stats.suspicious +
        stats.timeout +
        stats.undetected;
      console.log(stats);

      return {
        url: targetUrl,
        stats: {
          harmless: stats.harmless || 0,
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          timeout: stats.timeout || 0,
          undetected: stats.undetected || 0,
        },
        total,
        malicious: stats.malicious + stats.suspicious > 0,
      };
    }

    if (url) {
      const result = await scanUrl(url);
      return NextResponse.json({ type: "url", result });
    }

    if (email) {
      const urls = Array.from(email.matchAll(/https?:\/\/[^\s]+/g)).map(
        (m: any) => m[0]
      );
      if (!urls.length)
        return NextResponse.json({
          type: "email",
          message: "No URLs found",
          results: [],
        });

      const results = await Promise.all(urls.map(scanUrl));
      return NextResponse.json({
        type: "email",
        totalUrls: urls.length,
        results,
        hasMalicious: results.some((r) => r.malicious),
      });
    }

    return NextResponse.json(
      { error: "No URL or email provided" },
      { status: 400 }
    );
  } catch (err: any) {
    console.error("Scan error:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

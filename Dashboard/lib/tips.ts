import fs from "fs/promises";
import path from "path";

export type Tip = {
  id: string;
  category: "url" | "file" | "domain" | "email" | string;
  threatType: string;
  title: string;
  summary: string;
  tips: string[];
  details?: string;
  severity?: "low" | "medium" | "high" | "critical" | string;
  locale?: string;
  lastUpdated?: string;
};

const DATA_DIR = path.join(process.cwd(), "data");

async function loadTipsForLocale(locale = "en"): Promise<Tip[]> {
  try {
    const file = path.join(DATA_DIR, `tips.${locale}.json`);
    const buf = await fs.readFile(file, "utf8");
    return JSON.parse(buf) as Tip[];
  } catch {
    // fallback to en
    const file = path.join(DATA_DIR, `tips.en.json`);
    const buf = await fs.readFile(file, "utf8");
    return JSON.parse(buf) as Tip[];
  }
}

export async function findTips({
  category,
  threatTypes,
  locale = "en",
  limit = 5,
}: {
  category?: string;
  threatTypes?: string[]; // map from scan engine
  locale?: string;
  limit?: number;
}) {
  const tips = await loadTipsForLocale(locale);
  // Filter by category and threatTypes
  const filtered = tips.filter((t) => {
    if (category && t.category !== category) return false;
    if (threatTypes && threatTypes.length > 0) {
      return threatTypes.includes(t.threatType);
    }
    return true;
  });
  return filtered.slice(0, limit);
}

export async function getTipById(
  id: string,
  locale = "en"
): Promise<Tip | null> {
  const tips = await loadTipsForLocale(locale);
  return tips.find((t) => t.id === id) ?? null;
}

export async function generateAITips({
  category,
  threatTypes,
  url,
  locale = "en",
}: {
  category?: string;
  url?: string;
  threatTypes?: string[];
  locale?: string;
}) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    throw new Error("Missing OPENROUTER_API_KEY");
  }

  const prompt = `
    You are a cybersecurity assistant for a browser phishing-detection extension named PhishLens.
    Generate 5 short, practical, human-friendly security tips.

    Rules:
    Analyze the url ${url} and base tips on its characteristics, look for anything suspicious, minute details. Don't mention the URL in your response.
    Tailor tips to the threat category and types provided.
    Make tips relevant to everyday users with varying tech skills.
    Focus on category: ${category || "general"}
    Threat types: ${threatTypes?.join(", ")}
    Keep them beginner-friendly and action-based
    Avoid long paragraphs — keep tips crisp
    Output must be a single JSON object of { title, summary, tips[], severity }

    Example:
    {
    "title": "...",
    "summary": "...",
    "tips": ["...", "..."],
    "severity": "low/medium/high/critical"
    }`.trim();

  const response = await fetch(
    "https://openrouter.ai/api/v1/chat/completions",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "x-ai/grok-4.1-fast:free",
        messages: [
          { role: "system", content: "You are a cybersecurity assistant." },
          { role: "user", content: prompt },
        ],
        temperature: 0.4,
      }),
    }
  );

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`AI Tip Generation Failed: ${err}`);
  }

  const data = await response.json();
  const raw = data?.choices?.[0]?.message?.content;

  return raw;
}

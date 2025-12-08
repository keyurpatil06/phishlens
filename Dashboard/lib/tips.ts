import fs from "fs/promises";
import path from "path";
import { GoogleGenAI } from "@google/genai";

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

/* -----------------------------
   Load Tips for Specific Locale
------------------------------ */
async function loadTipsForLocale(locale = "en"): Promise<Tip[]> {
  try {
    const file = path.join(DATA_DIR, `tips.${locale}.json`);
    const buf = await fs.readFile(file, "utf8");
    return JSON.parse(buf) as Tip[];
  } catch {
    const fallback = path.join(DATA_DIR, "tips.en.json");
    const buf = await fs.readFile(fallback, "utf8");
    return JSON.parse(buf) as Tip[];
  }
}

/* -----------------------------
   Find Tips (Filtered)
------------------------------ */
export async function findTips({
  category,
  threatTypes,
  locale = "en",
  limit = 5,
}: {
  category?: string;
  threatTypes?: string[];
  locale?: string;
  limit?: number;
}) {
  const tips = await loadTipsForLocale(locale);

  const filtered = tips.filter((t) => {
    if (category && t.category !== category) return false;
    if (threatTypes && threatTypes.length > 0) {
      return threatTypes.includes(t.threatType);
    }
    return true;
  });

  return filtered.slice(0, limit);
}

/* -----------------------------
   Return Single Tip by ID
------------------------------ */
export async function getTipById(
  id: string,
  locale = "en"
): Promise<Tip | null> {
  const tips = await loadTipsForLocale(locale);
  return tips.find((t) => t.id === id) ?? null;
}

/* -----------------------------
   Generate AI Tips - Gemini
------------------------------ */
export async function generateAITips({
  category,
  url,
  threatTypes,
  locale = "en",
}: {
  category?: string;
  url?: string;
  threatTypes?: string[];
  locale?: string;
}) {
  const apiKey = process.env.AI_KEY;
  if (!apiKey) throw new Error("Missing AI_KEY in environment (.env.local)");

  const ai = new GoogleGenAI({ apiKey });

  const prompt = `
You are a cybersecurity assistant for a browser phishing-detection extension called PhishLens.

Output ONLY a valid JSON object (no backticks, no extra text):

{
  "title": "",
  "summary": "",
  "tips": ["", "", ""],
  "severity": "low|medium|high|critical"
  "score": 0-100 (0 for safe, 100 for very dangerous)
}

Rules:
- Analyze the URL: ${url} and accordingly give relevant prevention tips.
- Never mention the URL in the output.
- Category: ${category || "general"}
- Threat types: ${threatTypes?.join(", ") || "none"}
- Make tips short, practical, beginner-friendly.
- MUST output valid JSON only.
`.trim();

  const response = await ai.models.generateContent({
    model: "gemini-2.5-flash",
    contents: prompt,
  });

  console.log(response.text);
  
  // Gemini returns text inside response.response.text()
  const raw = response.text;

  return raw; // raw = JSON string
}

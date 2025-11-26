// app/api/tips/route.ts
import { NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

const DATA_DIR = path.join(process.cwd(), "data");

export async function GET(req: Request) {
  try {
    const url = new URL(req.url);
    const id = url.searchParams.get("id");
    const locale = url.searchParams.get("locale") || "en";
    const file = path.join(DATA_DIR, `tips.${locale}.json`);

    const raw = await fs.readFile(file, "utf8").catch(async () => {
      // fallback to english if missing
      return await fs.readFile(path.join(DATA_DIR, "tips.en.json"), "utf8");
    });
    const tips = JSON.parse(raw || "[]");

    if (id) {
      const found = tips.find((t: any) => t.id === id) ?? null;
      return NextResponse.json({ tip: found });
    }

    return NextResponse.json({ tips });
  } catch (err: any) {
    return NextResponse.json({ error: String(err?.message || err) }, { status: 500 });
  }
}

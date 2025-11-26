import { generateAITips } from "./tips";

export type ThreatInfo = {
  title: string;
  explanation: string;
  tips: string[];
  severity?: "low" | "medium" | "high" | "critical";
};

export const threatExplanations: Record<string, string> = {
  malicious:
    "The website is flagged for harmful activity such as phishing, malware, or credential theft.",
  suspicious:
    "The scanned URL shows suspicious indicators like redirects, strange hostnames, or suspicious content.",
  harmless:
    "No malicious or suspicious indicators were detected for this URL. Not a guarantee of safety.",
  unrated:
    "This URL hasn't been analyzed by security vendors. Proceed with caution.",
};

export async function getThreatInfo(
  category: string,
  url?: string
): Promise<ThreatInfo> {
  const def: ThreatInfo = {
    title: category,
    explanation: threatExplanations[category] || threatExplanations["unrated"],
    tips: ["Follow standard cybersecurity practices."],
    severity: "medium",
  };

  try {
    // Include the URL in the AI prompt
    const aiRaw = await generateAITips({
      category,
      url,
      threatTypes: [category],
      locale: "en",
    });

    // Extract JSON object safely
    const jsonMatch = aiRaw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return def;

    const aiData: Partial<{
      title: string;
      summary: string;
      tips: string[];
      severity: string;
    }> = JSON.parse(jsonMatch[0]);

    return {
      title: aiData.title || category,
      explanation:
        threatExplanations[category] || threatExplanations["unrated"],
      tips: aiData.tips?.map((tip) => `${tip}`) || [
        "Follow standard cybersecurity practices.",
      ],
      severity: (aiData.severity as ThreatInfo["severity"]) || "medium",
    };
  } catch (err) {
    console.error("AI tip generation failed, using default tips:", err);
    return def;
  }
}

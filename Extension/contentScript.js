window.PG = window.PG || {};

let lastResult = null;

// Allow popup to request the current result
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "PG_GET_RESULT") {
    sendResponse(lastResult);
  }
});

// --- Extraction helpers ---

function extractFromGmail() {
  const subject = (document.querySelector("h2.hP, h1.hP")?.textContent || "").trim();

  const fromEl = document.querySelector(".gD");
  const fromName = (fromEl?.getAttribute("name") || fromEl?.textContent || "").trim();
  const fromEmail = (fromEl?.getAttribute("email") || "").trim();

  const bodyContainer =
    document.querySelector(".a3s") ||
    document.querySelector(".adn.ads") ||
    document.querySelector(".nH.hx");
  if (!bodyContainer) return null;

  const bodyText = bodyContainer.innerText || "";

  const links = Array.from(bodyContainer.querySelectorAll("a[href]")).map(a => ({
    text: (a.textContent || "").trim(),
    href: a.href,
    isDataUrl: a.href.startsWith("data:")
  }));

  return { fromName, fromEmail, subject, bodyText, links };
}

function extractFromOutlook() {
  const pane = document.querySelector('[data-app-section="ReadingPane"]');
  if (!pane) return null;

  const subject = (pane.querySelector('[role="heading"]')?.textContent || "").trim();
  const fromChip = pane.querySelector('[data-log-name="Sender"]');
  const fromName = (fromChip?.textContent || "").trim();
  const fromEmail = (fromChip?.getAttribute("aria-label") || "").match(/<(.+?)>/)?.[1] || "";

  const bodyNode = pane.querySelector('[role="document"]');
  const bodyText = bodyNode?.innerText || "";
  const links = Array.from(bodyNode?.querySelectorAll("a[href]") || []).map(a => ({
    text: (a.textContent || "").trim(),
    href: a.href,
    isDataUrl: a.href.startsWith("data:")
  }));

  return { fromName, fromEmail, subject, bodyText, links };
}

function getEmailContext() {
  if (location.hostname.includes("mail.google.com")) return extractFromGmail();
  if (location.hostname.includes("outlook.")) return extractFromOutlook();
  return null;
}

// --- UI banner ---

function ensureBanner() {
  let el = document.getElementById("pg-banner");
  if (el) return el;
  el = document.createElement("div");
  el.id = "pg-banner";
  el.style.position = "fixed";
  el.style.right = "16px";
  el.style.bottom = "16px";
  el.style.zIndex = 2147483647;
  el.style.maxWidth = "360px";
  el.style.boxShadow = "0 12px 24px rgba(0,0,0,.18)";
  el.style.borderRadius = "14px";
  el.style.fontFamily = "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial";
  el.style.background = "white";
  el.style.border = "1px solid #e5e7eb";
  el.style.overflow = "hidden";
  el.style.display = "none";
  el.innerHTML = `
    <div style="padding:12px 14px; border-bottom:1px solid #f1f5f9; display:flex; align-items:center; gap:8px;">
      <div style="width:10px;height:10px;border-radius:9999px;background:#a3a3a3;" id="pg-dot"></div>
      <strong style="font-size:14px;">PhishLens</strong>
      <div style="margin-left:auto;font-size:12px;color:#64748b" id="pg-level">—</div>
    </div>
    <div style="padding:12px 14px;font-size:13px;color:#111827" id="pg-body"></div>
  `;
  document.body.appendChild(el);
  return el;
}

// --- Analysis ---

async function analyze() {
  const ctx = getEmailContext();
  if (!ctx) { lastResult = null; return; }

  const { fromName, fromEmail, subject, bodyText, links } = ctx;

  const local = window.PG.scoreEmail({
    fromName, fromEmail, subject, bodyText,
    links: (links || []).map(l => ({ href: l.href, text: l.text, isDataUrl: l.isDataUrl }))
  });

  // Optional API checks (keys may be empty)
  let urlVerdicts = [];
  try {
    urlVerdicts = await window.PG.externalUrlVerdicts((links || []).map(l => l.href).filter(Boolean));
  } catch { /* ignore */ }

  const anyExternalBad = urlVerdicts.some(v => v.flagged);
  const level = anyExternalBad ? "high" : local.level;
  const score = local.score + (anyExternalBad ? 10 : 0);

  // UI
  const banner = ensureBanner();
  banner.style.display = "block";
  const dot = banner.querySelector("#pg-dot");
  const label = banner.querySelector("#pg-level");
  const body = banner.querySelector("#pg-body");

  const color = level === "high" ? "#ef4444" : level === "medium" ? "#f59e0b" : "#22c55e";
  dot.style.background = color;
  label.textContent = level.toUpperCase();
  body.innerHTML = `
    <div style="margin-bottom:8px;"><strong>${subject || "No subject"}</strong></div>
    <div style="color:#374151;margin-bottom:8px;">From: ${fromName || ""} &lt;${fromEmail || ""}&gt;</div>
    <div style="margin-bottom:6px;">Reasons:</div>
    <ul style="padding-left:18px;margin:0 0 8px 0;">
      ${local.reasons.slice(0,4).map(r=>`<li>${r}</li>`).join("")}
      ${anyExternalBad ? `<li>External reputation service flagged one or more links.</li>` : ""}
    </ul>
    <div style="font-size:12px;color:#6b7280;">Score: ${score}</div>
  `;

  // Expose result to popup
  lastResult = {
    level,
    score,
    reasons: [
      ...local.reasons.slice(0, 6),
      ...(anyExternalBad ? ["External reputation service flagged one or more links."] : [])
    ].filter(Boolean).slice(0, 6)
  };
  window.__PG_LAST_RESULT = lastResult; // optional legacy

  // Send to dashboard (fire-and-forget)
  try {
    window.PG.sendToDashboard({
      ts: Date.now(),
      page: location.href,
      fromName, fromEmail, subject,
      level, score,
      reasons: local.reasons,
      links: (links || []).map((l, i) => ({ ...l, verdict: urlVerdicts[i] || null }))
    });
  } catch { /* ignore */ }
}

// Re-run when SPA mail apps change the reading pane
let debounceTimer = null;
const rescan = () => { clearTimeout(debounceTimer); debounceTimer = setTimeout(analyze, 700); };
const observer = new MutationObserver(rescan);
observer.observe(document.body, { subtree: true, childList: true });

// Initial run
setTimeout(analyze, 1200);

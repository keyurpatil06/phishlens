window.PG = window.PG || {};

async function getCfg() {
  return new Promise(res => chrome.storage.sync.get(
    ["DASHBOARD_URL", "DASHBOARD_TOKEN"], v => res(v || {})
  ));
}

async function sendToDashboard(payload) {
  const cfg = await getCfg();
  if (!cfg.DASHBOARD_URL) return;
  const url = cfg.DASHBOARD_URL.replace(/\/+$/, "") + "/api/email-scan";
  const send = async (data) => {
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${cfg.DASHBOARD_TOKEN || ""}`
      },
      body: JSON.stringify(data)
    });
    if (!r.ok) throw new Error("dashboard_error");
  };

  try { await send(payload); }
  catch { await window.PG.enqueue(payload); }
}

chrome.alarms.create("pg_drain", { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener(al => {
  if (al.name === "pg_drain") window.PG.drain(sendToDashboard);
});

window.PG.sendToDashboard = sendToDashboard;

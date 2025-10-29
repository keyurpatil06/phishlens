window.PG = window.PG || {};

async function getKeys() {
  return new Promise(res => chrome.storage.sync.get(
    ["GSB_API_KEY", "VT_API_KEY"],
    (v) => res(v || {})
  ));
}

async function checkGSB(urls, apiKey) {
  if (!apiKey || !urls.length) return [];
  const body = {
    client: { clientId: "phishguard", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: urls.map(u => ({ url: u }))
    }
  };
  const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  if (!resp.ok) return [];
  const data = await resp.json();
  const bad = new Set((data.matches || []).map(m => m.threat.url));
  return urls.filter(u => bad.has(u));
}

async function checkVirusTotal(urls, apiKey) {
  if (!apiKey || !urls.length) return [];
  const bad = [];
  for (const u of urls.slice(0, 10)) {
    try {
      const resp = await fetch(`https://www.virustotal.com/api/v3/urls`, {
        method: "POST",
        headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ url: u })
      });
      if (!resp.ok) continue;
      const data = await resp.json();
      const id = data.data?.id;
      if (!id) continue;
      const r = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
        headers: { "x-apikey": apiKey }
      });
      const d2 = await r.json();
      const malVotes = d2.data?.attributes?.stats?.malicious || 0;
      if (malVotes > 0) bad.push(u);
    } catch { /* ignore */ }
  }
  return bad;
}

window.PG.externalUrlVerdicts = async function (urls) {
  const keys = await getKeys();
  const [gsbBad, vtBad] = await Promise.all([
    checkGSB(urls, keys.GSB_API_KEY),
    checkVirusTotal(urls, keys.VT_API_KEY)
  ]);
  const bad = new Set([...gsbBad, ...vtBad]);
  return urls.map(u => ({ url: u, gsb: gsbBad.includes(u), vt: vtBad.includes(u), flagged: bad.has(u) }));
};

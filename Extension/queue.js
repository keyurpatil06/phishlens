window.PG = window.PG || {};

async function enqueue(item) {
  const key = "PG_QUEUE";
  return new Promise(res => {
    chrome.storage.local.get([key], (v) => {
      const arr = v[key] || [];
      arr.push({ ...item, ts: Date.now() });
      chrome.storage.local.set({ [key]: arr }, () => res());
    });
  });
}

async function drain(sendFn) {
  const key = "PG_QUEUE";
  const items = await new Promise(res => chrome.storage.local.get([key], v => res(v[key] || [])));
  const remaining = [];
  for (const it of items) {
    try { await sendFn(it); }
    catch { remaining.push(it); }
  }
  await new Promise(res => chrome.storage.local.set({ [key]: remaining }, () => res()));
}

window.PG.enqueue = enqueue;
window.PG.drain = drain;

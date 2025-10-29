chrome.runtime.onInstalled.addListener(()=> {
  chrome.alarms.create("pg_drain", { periodInMinutes: 5 });
});
